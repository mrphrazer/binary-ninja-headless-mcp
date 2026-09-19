"""Native command-line client for the Binary Ninja Headless MCP server.

``binja_cli`` lets agents and shells that do not speak the MCP protocol drive *all* of the
server's tools with plain commands::

    binja_cli call binary.functions --session-id <id> --limit 50

It is a thin layer over a ``dispatch(method, params) -> result`` abstraction with two backends:

* **In-process** (default): builds the backend and dispatches through
  :meth:`SimpleMcpServer.handle_request` -- the identical MCP code path, so results match the
  server exactly. State is ephemeral per invocation.
* **Remote** (``--connect host:port`` or a managed background server): a line-delimited
  JSON-RPC/TCP client to a long-lived server, so session state persists across invocations.

Tool names, parameters, types and required-ness are all derived from
:data:`binary_ninja_headless_mcp.catalog.TOOL_DEFINITIONS`, so the CLI never drifts from the server.
"""

from __future__ import annotations

import argparse
import difflib
import json
import math
import os
import socket
import sys
from contextlib import redirect_stdout, suppress
from pathlib import Path
from typing import Any

from .backend import BinjaBackend
from .catalog import TOOL_DEFAULTS, TOOL_DEFINITIONS
from .cli import load_binja_module
from .server import SimpleMcpServer

# The package metadata also works in source checkouts without requiring Binary Ninja.
try:
    from importlib.metadata import version

    __version__ = version("binary-ninja-headless-mcp")
except Exception:  # Source checkout not installed.
    __version__ = "0.2.0"

SPECS: dict[str, dict[str, Any]] = {
    item["name"]: {**item, **item["inputSchema"]} for item in TOOL_DEFINITIONS
}

EXIT_OK = 0
EXIT_TOOL_ERROR = 1
EXIT_USAGE = 2

_DEFAULT_PROTOCOL = "2024-11-05"
_OPEN_TOOLS = {"session.open", "session.open_bytes", "session.open_existing"}
_PROTOCOL_ERROR_CODES = (-32700, -32600, -32601, -32602)

# Cache for a single stdin read shared across all ``-`` value sources in one invocation.
_STDIN_CACHE: dict[str, str] = {}


class CliUsageError(Exception):
    """A client-side usage error (bad flag, bad value, unknown tool, connection setup)."""


class RpcError(Exception):
    """A JSON-RPC ``error`` object returned by the server."""

    def __init__(self, code: Any, message: str, data: Any = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


# --------------------------------------------------------------------------------------
# Value parsing / coercion
# --------------------------------------------------------------------------------------


def _parse_int(raw: str) -> int:
    """Parse an integer accepting ``0x``/``0o``/``0b`` prefixes, else base-10 (no octal trap)."""

    text = (raw or "").strip()
    sign = 1
    if text and text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        text = text[1:]
    if not text:
        raise CliUsageError(f"expected an integer, got {raw!r}")
    low = text.lower()
    if low.startswith("0x"):
        base = 16
    elif low.startswith("0o"):
        base = 8
    elif low.startswith("0b"):
        base = 2
    else:
        base = 10
    try:
        return sign * int(text, base)
    except ValueError as exc:
        raise CliUsageError(f"expected an integer, got {raw!r}") from exc


def _parse_float(raw: str) -> float:
    try:
        value = float(raw)
    except (ValueError, TypeError) as exc:
        raise CliUsageError(f"expected a number, got {raw!r}") from exc
    if not math.isfinite(value):
        raise CliUsageError("number must be finite")
    return value


def _positive_timeout(raw: str) -> float:
    try:
        value = _parse_float(raw)
    except CliUsageError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc
    if value <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than zero")
    return value


def _parse_bool(raw: str | None) -> bool:
    if raw is None:
        return True
    text = raw.strip().lower()
    if text in {"true", "1", "yes", "on"}:
        return True
    if text in {"false", "0", "no", "off"}:
        return False
    raise CliUsageError(f"invalid boolean {raw!r} (use true/false/yes/no/on/off/1/0)")


def _parse_json(raw: str, *, expect: str | None = None) -> Any:
    try:
        value = json.loads(raw, parse_constant=_reject_json_constant, parse_float=_json_float)
    except (ValueError, TypeError) as exc:
        raise CliUsageError(f"invalid JSON value: {raw!r}") from exc
    if expect == "object" and not isinstance(value, dict):
        raise CliUsageError(f"expected a JSON object, got {type(value).__name__}")
    if expect == "array" and not isinstance(value, list):
        raise CliUsageError(f"expected a JSON array, got {type(value).__name__}")
    return value


def _reject_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _json_float(raw: str) -> float:
    value = float(raw)
    if not math.isfinite(value):
        raise ValueError(f"non-finite JSON number: {raw}")
    return value


def _try_json_else_str(raw: str) -> Any:
    try:
        return json.loads(raw, parse_constant=_reject_json_constant, parse_float=_json_float)
    except (ValueError, TypeError):
        return raw


def coerce_value(raw: str, schema: dict[str, Any] | None) -> Any:  # noqa: PLR0911
    """Coerce one string value to the JSON type described by a tool property schema.

    Address parameters (``oneOf[integer, string]``) and untyped (``{}``) parameters are passed
    through **as strings** so Binary Ninja applies its native integer-string interpretation
    (decimal bare digits, hexadecimal with an explicit 0x prefix).
    """

    schema = schema or {}
    if "oneOf" in schema:
        return raw
    kind = schema.get("type")
    if kind == "boolean":
        return _parse_bool(raw)
    if kind == "integer":
        return _parse_int(raw)
    if kind == "number":
        return _parse_float(raw)
    if kind == "string":
        return raw
    if kind == "object":
        return _parse_json(raw, expect="object")
    if kind == "array":
        return _parse_json(raw, expect="array")
    return raw


def coerce_scalar(raw: str, item_type: str | None) -> Any:
    """Coerce a single array element by its declared ``items.type``."""

    if item_type == "integer":
        return _parse_int(raw)
    if item_type == "number":
        return _parse_float(raw)
    if item_type == "boolean":
        return _parse_bool(raw)
    if item_type == "string":
        return raw
    return _try_json_else_str(raw)


def _coerce_typed(typ: str, raw: str | None, has_value: bool) -> Any:
    """Coerce using an explicit ``--key:TYPE`` override."""

    if typ == "null":
        return None
    if typ == "bool":
        return _parse_bool(raw)
    if not has_value:
        raise CliUsageError(f"type ':{typ}' requires a value")
    if typ == "str":
        return raw
    if typ == "int":
        return _parse_int(raw)
    if typ == "float":
        return _parse_float(raw)
    if typ == "json":
        return _parse_json(raw)
    raise CliUsageError(f"unknown value type ':{typ}' (use str/int/float/bool/json/null)")


def _read_stdin_once() -> str:
    if "data" not in _STDIN_CACHE:
        _STDIN_CACHE["data"] = sys.stdin.read()
    return _STDIN_CACHE["data"]


def _apply_value_source(raw: str) -> str:
    """Resolve ``@file`` and ``-`` value sources (keeps large/secret values off argv)."""

    if raw == "-":
        return _read_stdin_once()
    if raw.startswith("@"):
        path = raw[1:]
        try:
            return Path(path).read_text(encoding="utf-8")
        except OSError as exc:
            raise CliUsageError(f"cannot read value file {path!r}: {exc}") from exc
    return raw


# --------------------------------------------------------------------------------------
# Argument grammar for ``call``
# --------------------------------------------------------------------------------------


def _reject_unknown_flag(name: str, props: dict[str, Any]) -> None:
    matches = difflib.get_close_matches(name, list(props), n=3)
    hint = f" did you mean: {', '.join('--' + m for m in matches)}?" if matches else ""
    raise CliUsageError(f"unknown argument --{name}.{hint}")


def _assign_arg(  # noqa: PLR0917
    result: dict[str, Any],
    name: str,
    typ: str | None,
    raw: str | None,
    has_value: bool,
    schema: dict[str, Any],
) -> None:
    if typ is not None:
        result[name] = _coerce_typed(typ, raw, has_value)
        return
    if schema.get("type") == ["array", "string"]:
        if not has_value:
            raise CliUsageError(f"--{name} requires a value")
        if name not in result:
            result[name] = raw
        elif isinstance(result[name], list):
            result[name].append(raw)
        else:
            result[name] = [result[name], raw]
        return
    if schema.get("type") == "array":
        if not has_value:
            raise CliUsageError(f"--{name} requires a value")
        item_type = (schema.get("items") or {}).get("type")
        element = coerce_scalar(raw, item_type)
        existing = result.get(name)
        if isinstance(existing, list):
            existing.append(element)
        else:
            result[name] = [element]
        return
    if not has_value:
        if schema.get("type") == "boolean":
            result[name] = True
            return
        raise CliUsageError(f"--{name} requires a value")
    result[name] = coerce_value(raw, schema)


def parse_tool_rest(rest: list[str], spec: dict[str, Any]) -> dict[str, Any]:
    """Turn the trailing ``--flag value`` tokens of a ``call`` into a JSON arguments object.

    Supports ``--key value``, ``--key=value``, bare boolean ``--flag``, repeated flags (arrays),
    ``--key:TYPE`` overrides, ``@file``/``-`` value sources, and the ``--json``/``--json-stdin``
    escape hatches (whose object is the base; per-flag values override it).
    """

    props = spec.get("properties", {})
    base: dict[str, Any] = {}
    result: dict[str, Any] = {}
    index = 0
    count = len(rest)
    while index < count:
        token = rest[index]
        if token == "--":
            index += 1
            continue
        if not token.startswith("--"):
            raise CliUsageError(f"unexpected positional argument: {token!r} (use --name value)")
        left, eq, inline = token[2:].partition("=")
        name_part, colon, typ_part = left.partition(":")
        name = name_part.replace("-", "_")
        typ = typ_part if colon else None
        if name == "json_stdin":  # reads stdin, never consumes a following token
            if eq or typ:
                raise CliUsageError("--json-stdin takes no value or type override")
            base.update(_parse_json(_read_stdin_once(), expect="object"))
            index += 1
            continue
        if eq:
            raw: str | None = inline
            has_value = True
            index += 1
        elif index + 1 < count and not rest[index + 1].startswith("--"):
            raw = rest[index + 1]
            has_value = True
            index += 2
        else:
            raw = None
            has_value = False
            index += 1
        if has_value:
            raw = _apply_value_source(raw)
        if name == "json":
            if not has_value:
                raise CliUsageError("--json requires a JSON object value")
            base.update(_parse_json(raw, expect="object"))
            continue
        if name not in props:
            _reject_unknown_flag(name, props)
        _assign_arg(result, name, typ, raw, has_value, props[name])
    merged = dict(base)
    merged.update(result)
    return merged


def _inject_session(
    arguments: dict[str, Any], spec: dict[str, Any], session_id: str | None
) -> None:
    if session_id and "session_id" in spec.get("properties", {}) and "session_id" not in arguments:
        arguments["session_id"] = session_id


def _validate_required(spec: dict[str, Any], arguments: dict[str, Any]) -> None:
    missing = [key for key in spec.get("required", []) if key not in arguments]
    if missing:
        flags = ", ".join(f"--{key}" for key in missing)
        raise CliUsageError(f"missing required argument(s): {flags}")


def _unknown_tool(tool: str) -> None:
    matches = difflib.get_close_matches(tool, list(SPECS), n=3)
    hint = f" did you mean: {', '.join(matches)}?" if matches else ""
    raise CliUsageError(f"unknown tool: {tool!r}.{hint}")


# --------------------------------------------------------------------------------------
# Transports
# --------------------------------------------------------------------------------------


class InProcessTransport:
    """Dispatch against an in-process :class:`SimpleMcpServer` -- the exact MCP code path."""

    def __init__(self, server: SimpleMcpServer, *, owns_backend: bool = False) -> None:
        self._server = server
        self._owns_backend = owns_backend
        self._id = 0

    def dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        with redirect_stdout(sys.stderr):
            response = self._server.handle_request(
                {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
            )
        if response is None:
            return {}
        if "error" in response:
            err = response["error"]
            raise RpcError(err.get("code"), err.get("message", ""), err.get("data"))
        return response["result"]

    def close(self) -> None:
        if not self._owns_backend:
            return
        backend = getattr(self._server, "_backend", None)
        if backend is not None and hasattr(backend, "shutdown"):
            with redirect_stdout(sys.stderr):
                backend.shutdown()


class RemoteTransport:
    """Buffered line-delimited JSON-RPC client with strict response correlation."""

    def __init__(
        self,
        host: str,
        port: int,
        *,
        connect_timeout: float = 10.0,
        read_timeout: float | None = None,
    ) -> None:
        self._sock = socket.create_connection((host, port), timeout=connect_timeout)
        self._sock.settimeout(read_timeout)
        self._reader = self._sock.makefile("r", encoding="utf-8", newline="\n")
        self._writer = self._sock.makefile("w", encoding="utf-8", newline="\n")
        self._id = 0

    def dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._id += 1
        request = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        notification = method == "notifications/initialized"
        if notification:
            del request["id"]
        self._writer.write(json.dumps(request, allow_nan=False) + "\n")
        self._writer.flush()
        if notification:
            return {}
        line = self._reader.readline()
        if not line:
            raise ConnectionError("server closed the connection")
        try:
            response = json.loads(
                line, parse_constant=_reject_json_constant, parse_float=_json_float
            )
        except (ValueError, UnicodeError) as exc:
            raise ConnectionError("server returned invalid JSON") from exc
        if (
            not isinstance(response, dict)
            or response.get("jsonrpc") != "2.0"
            or type(response.get("id")) is not int
            or response["id"] != self._id
            or (("error" in response) == ("result" in response))
        ):
            raise ConnectionError("server returned an invalid or mismatched JSON-RPC response")
        if "error" in response:
            error = response["error"]
            if (
                not isinstance(error, dict)
                or type(error.get("code")) is not int
                or not isinstance(error.get("message"), str)
            ):
                raise ConnectionError("server returned an invalid JSON-RPC error")
            raise RpcError(error["code"], error["message"], error.get("data"))
        if not isinstance(response["result"], dict):
            raise ConnectionError("server returned a non-object result")
        return response["result"]

    def close(self) -> None:
        for closeable in (self._reader, self._writer, self._sock):
            with suppress(OSError):
                closeable.close()


def _parse_hostport(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep:
        raise CliUsageError(f"invalid connect target {target!r}; expected HOST:PORT")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise CliUsageError("IPv6 connect addresses must use [ADDRESS]:PORT")
    try:
        port_num = int(port)
    except ValueError as exc:
        raise CliUsageError(f"invalid port in {target!r}") from exc
    if not 1 <= port_num <= 65535:
        raise CliUsageError("port must be between 1 and 65535")
    return host or "127.0.0.1", port_num


def _connect_remote(
    host: str,
    port: int,
    *,
    version_check: bool,
    read_timeout: float | None = None,
) -> RemoteTransport:
    transport = RemoteTransport(host, port, read_timeout=10.0)
    try:
        if version_check:
            info = transport.dispatch("initialize", {"protocolVersion": _DEFAULT_PROTOCOL})
            server_info = info.get("serverInfo")
            if (
                not isinstance(server_info, dict)
                or server_info.get("name") != "binary_ninja_headless_mcp"
            ):
                raise CliUsageError("remote endpoint is not a Binary Ninja Headless MCP server")
            capabilities = info.get("capabilities")
            if info.get("protocolVersion") != _DEFAULT_PROTOCOL or (
                not isinstance(capabilities, dict)
                or not isinstance(capabilities.get("tools"), dict)
            ):
                raise CliUsageError("remote server returned incompatible initialization metadata")
            remote_version = server_info.get("version")
            if remote_version and remote_version != __version__:
                print(
                    f"warning: server version {remote_version} differs from client {__version__}",
                    file=sys.stderr,
                )
        transport._sock.settimeout(read_timeout)
        return transport
    except BaseException:
        transport.close()
        raise


def _build_inprocess(args: argparse.Namespace) -> InProcessTransport:
    try:
        with redirect_stdout(sys.stderr):
            backend = BinjaBackend(load_binja_module(args.fake_backend))
    except RuntimeError as exc:
        raise CliUsageError(str(exc)) from exc
    return InProcessTransport(SimpleMcpServer(backend), owns_backend=True)


def _make_transport(
    args: argparse.Namespace, *, server: SimpleMcpServer | None = None
) -> InProcessTransport | RemoteTransport:
    if server is not None:
        return InProcessTransport(server, owns_backend=False)
    if args.connect and (args.in_process or args.fake_backend):
        raise CliUsageError("--connect conflicts with --in-process and --fake-backend")
    if args.in_process or args.fake_backend:
        return _build_inprocess(args)
    target = args.connect or os.environ.get("BINJA_CLI_CONNECT")
    if not target:
        from .managed_cli import live_state

        live = live_state()
        if live:
            host = live["host"]
            target = f"[{host}]:{live['port']}" if ":" in host else f"{host}:{live['port']}"
    if target:
        host, port = _parse_hostport(target)
        return _connect_remote(host, port, version_check=True, read_timeout=args.timeout)
    return _build_inprocess(args)


# --------------------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------------------


def _print_json(obj: Any) -> None:
    print(json.dumps(obj, indent=2, sort_keys=True))


def _print_value(value: Any) -> None:
    if isinstance(value, (dict, list)):
        print(json.dumps(value, sort_keys=True))
    elif isinstance(value, bool):
        print("true" if value else "false")
    elif value is None:
        print("null")
    else:
        print(value)


def _extract_path(obj: Any, dotpath: str) -> Any:
    current = obj
    for part in dotpath.split("."):
        if isinstance(current, dict):
            if part not in current:
                raise CliUsageError(f"field path not found: {dotpath!r}")
            current = current[part]
        elif isinstance(current, list):
            try:
                idx = int(part)
            except ValueError as exc:
                raise CliUsageError(f"field path not found: {dotpath!r}") from exc
            if not 0 <= idx < len(current):
                raise CliUsageError(f"field index out of range: {dotpath!r}")
            current = current[idx]
        else:
            raise CliUsageError(f"field path not found: {dotpath!r}")
    return current


def _emit_call_result(result: dict[str, Any], args: argparse.Namespace) -> int:
    is_error = bool(result.get("isError"))
    structured = result.get("structuredContent", {})
    if args.raw:
        _print_json(result)
    elif args.quiet:
        content = result.get("content") or [{}]
        print(content[0].get("text", "") if content else "")
    elif args.field:
        _print_value(_extract_path(structured, args.field))
    else:
        _print_json(structured)
    return EXIT_TOOL_ERROR if is_error else EXIT_OK


def _rpc_exit_code(exc: RpcError) -> int:
    return EXIT_USAGE if exc.code in _PROTOCOL_ERROR_CODES else EXIT_TOOL_ERROR


def _handle_rpc_error(exc: RpcError) -> int:
    detail = f" :: {exc.data}" if exc.data not in (None, "") else ""
    hint = (
        " (tool/method not present on this server -- version skew?)" if exc.code == -32601 else ""
    )
    print(f"error[{exc.code}]: {exc.message}{detail}{hint}", file=sys.stderr)
    return _rpc_exit_code(exc)


# --------------------------------------------------------------------------------------
# Command handlers
# --------------------------------------------------------------------------------------


def _maybe_session_hint(args: argparse.Namespace, transport: Any, result: dict[str, Any]) -> None:
    if not isinstance(transport, InProcessTransport) or result.get("isError"):
        return
    structured = result.get("structuredContent") or {}
    if args.tool in _OPEN_TOOLS and structured.get("session_id"):
        print(
            "note: in-process sessions are ephemeral; use a managed/remote server "
            "(binja_cli server start / --connect) or 'batch' for multi-step work",
            file=sys.stderr,
        )


def _cmd_call(args: argparse.Namespace, transport: Any) -> int:
    arguments = args.call_arguments
    result = transport.dispatch("tools/call", {"name": args.tool, "arguments": arguments})
    _maybe_session_hint(args, transport, result)
    return _emit_call_result(result, args)


def _call_arguments(args: argparse.Namespace) -> dict[str, Any]:
    spec = SPECS.get(args.tool)
    if spec is None:
        _unknown_tool(args.tool)
    arguments = parse_tool_rest(args.rest, spec)
    _inject_session(arguments, spec, args.session_id)
    _validate_required(spec, arguments)
    return arguments


def _cmd_raw(args: argparse.Namespace, transport: Any) -> int:
    if args.method == "shutdown" and not args.yes:
        raise CliUsageError(
            "refusing to send 'shutdown' without --yes (it tears down a shared server)"
        )
    if args.params_stdin:
        params = _parse_json(_read_stdin_once(), expect="object")
    elif args.params:
        params = _parse_json(args.params, expect="object")
    else:
        params = {}
    result = transport.dispatch(args.method, params)
    _print_json(result)
    if isinstance(result, dict) and result.get("isError"):
        return EXIT_TOOL_ERROR
    return EXIT_OK


def _filter_specs(args: argparse.Namespace) -> tuple[list[dict[str, Any]], int]:
    if args.offset < 0 or (args.limit is not None and args.limit <= 0):
        raise CliUsageError("offset must be >= 0 and limit must be > 0")
    tools = list(TOOL_DEFINITIONS)
    if args.prefix:
        tools = [tool for tool in tools if tool["name"].startswith(args.prefix)]
    if args.query:
        needle = args.query.lower()
        tools = [
            tool
            for tool in tools
            if needle in tool["name"].lower() or needle in tool["description"].lower()
        ]
    total = len(tools)
    if args.offset:
        tools = tools[args.offset :]
    if args.limit is not None:
        tools = tools[: args.limit]
    return tools, total


def _cmd_list(args: argparse.Namespace) -> int:
    tools, total = _filter_specs(args)
    if args.names_only:
        for tool in tools:
            print(tool["name"])
        return EXIT_OK
    _print_json(
        {
            "total": total,
            "offset": args.offset or 0,
            "count": len(tools),
            "tools": [{"name": t["name"], "description": t["description"]} for t in tools],
        }
    )
    return EXIT_OK


def _tool_defaults(spec: dict[str, Any]) -> dict[str, Any]:
    return dict(TOOL_DEFAULTS.get(spec["name"], {}))


def _cmd_describe(args: argparse.Namespace) -> int:
    spec = SPECS.get(args.tool)
    if spec is None:
        _unknown_tool(args.tool)
    _print_json(
        {
            "name": spec["name"],
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
            "required": list(spec.get("required", [])),
            "properties": spec.get("properties", {}),
            "defaults": _tool_defaults(spec),
        }
    )
    return EXIT_OK


def _batch_request(line: str, line_no: int) -> tuple[str, dict[str, Any]]:
    request = _parse_json(line, expect="object")
    tool = request.get("tool", request.get("name"))
    if not isinstance(tool, str) or not tool:
        raise CliUsageError(f"batch line {line_no}: 'tool' must be a nonempty string")
    if tool not in SPECS:
        _unknown_tool(tool)
    arguments = request.get("arguments", request.get("args", {}))
    if not isinstance(arguments, dict):
        raise CliUsageError(f"batch line {line_no}: 'arguments' must be an object")
    return tool, dict(arguments)


def _run_batch_lines(stream: Any, args: argparse.Namespace, transport: Any) -> int:  # noqa: PLR0912, PLR0915
    worst = EXIT_OK
    last_session = args.session_id
    opened: list[str] = []
    try:
        for line_no, line in enumerate(stream, 1):
            stripped = line.strip()
            if not stripped:
                continue
            tool = None
            try:
                tool, arguments = _batch_request(stripped, line_no)
                if not args.no_autosession:
                    _inject_session(arguments, SPECS[tool], last_session)
                _validate_required(SPECS[tool], arguments)
                result = transport.dispatch("tools/call", {"name": tool, "arguments": arguments})
            except (CliUsageError, RpcError) as exc:
                code = _rpc_exit_code(exc) if isinstance(exc, RpcError) else EXIT_USAGE
                worst = max(worst, code)
                error = {"message": str(exc)}
                if isinstance(exc, RpcError):
                    error.update(code=exc.code, data=exc.data)
                print(json.dumps({"line": line_no, "tool": tool, "error": error}, sort_keys=True))
                if not args.continue_on_error:
                    break
                continue
            structured = result.get("structuredContent") or {}
            is_error = bool(result.get("isError"))
            if not is_error:
                session_id = structured.get("session_id")
                if tool in _OPEN_TOOLS and isinstance(session_id, str) and session_id:
                    if session_id not in opened:
                        opened.append(session_id)
                    if not args.no_autosession:
                        last_session = session_id
                if tool == "session.close":
                    closed = arguments.get("session_id")
                    if closed in opened:
                        opened.remove(closed)
                    if last_session == closed:
                        last_session = None
            else:
                worst = max(worst, EXIT_TOOL_ERROR)
            print(
                json.dumps(
                    {
                        "line": line_no,
                        "tool": tool,
                        "isError": is_error,
                        "structuredContent": structured,
                    },
                    sort_keys=True,
                )
            )
            if is_error and not args.continue_on_error:
                break
    finally:
        if args.close_after:
            for session_id in reversed(opened):
                try:
                    result = transport.dispatch(
                        "tools/call",
                        {"name": "session.close", "arguments": {"session_id": session_id}},
                    )
                    if result.get("isError"):
                        raise RuntimeError(str(result.get("structuredContent")))
                except Exception as exc:
                    worst = max(worst, EXIT_TOOL_ERROR)
                    print(f"cleanup failed for session {session_id}: {exc}", file=sys.stderr)
    return worst


def _cmd_batch(args: argparse.Namespace, transport: Any) -> int:
    if args.file == "-":
        return _run_batch_lines(sys.stdin, args, transport)
    with open(args.file, encoding="utf-8") as stream:
        return _run_batch_lines(stream, args, transport)


# --------------------------------------------------------------------------------------
# Managed background server lives in a separate worker module.
# --------------------------------------------------------------------------------------


def _cmd_server(args: argparse.Namespace) -> int:
    from .managed_cli import command

    return command(args)


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="binja_cli",
        description="Native command-line client for the Binary Ninja Headless MCP server.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--connect",
        metavar="HOST:PORT",
        help="Connect to a running TCP MCP server (persistent sessions).",
    )
    parser.add_argument(
        "--in-process",
        action="store_true",
        help="Force an in-process backend even if a managed server is live.",
    )
    parser.add_argument("--fake-backend", action="store_true", help="Use the test backend.")
    parser.add_argument(
        "--timeout",
        type=_positive_timeout,
        help="Remote response timeout in seconds; default: unlimited.",
    )
    parser.add_argument(
        "--session-id",
        default=os.environ.get("BINJA_CLI_SESSION"),
        help="Default session_id for tools that take one (env: BINJA_CLI_SESSION).",
    )
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--raw", action="store_true", help="Print the full tool-result envelope.")
    output.add_argument("--quiet", action="store_true", help="Print only the summary text line.")
    output.add_argument(
        "--field", metavar="DOTPATH", help="Print one value from structuredContent."
    )

    sub = parser.add_subparsers(dest="verb", required=True)

    call_parser = sub.add_parser("call", help="Invoke one tool.")
    call_parser.add_argument("tool")
    call_parser.add_argument("rest", nargs=argparse.REMAINDER)

    for verb in ("list", "tools"):
        list_parser = sub.add_parser(verb, help="List available tools.")
        list_parser.add_argument("--prefix")
        list_parser.add_argument("--query")
        list_parser.add_argument("--offset", type=int, default=0)
        list_parser.add_argument("--limit", type=int)
        list_parser.add_argument("--names-only", action="store_true")

    describe_parser = sub.add_parser("describe", help="Show a tool's description and parameters.")
    describe_parser.add_argument("tool")

    raw_parser = sub.add_parser(
        "raw", help="Send an arbitrary JSON-RPC method (bypasses coercion)."
    )
    raw_parser.add_argument("method")
    raw_group = raw_parser.add_mutually_exclusive_group()
    raw_group.add_argument("--params", help="Params as a JSON object.")
    raw_group.add_argument(
        "--params-stdin", action="store_true", help="Read params JSON from stdin."
    )
    raw_parser.add_argument(
        "--yes", action="store_true", help="Confirm dangerous methods (shutdown)."
    )

    batch_parser = sub.add_parser(
        "batch", help="Run a JSONL sequence of tool calls on one transport."
    )
    batch_parser.add_argument("file", nargs="?", default="-")
    batch_parser.add_argument("--continue-on-error", action="store_true")
    batch_parser.add_argument("--no-autosession", action="store_true")
    batch_parser.add_argument("--close-after", action="store_true")

    server_parser = sub.add_parser("server", help="Manage a background TCP MCP server.")
    server_parser.add_argument("action", choices=["start", "stop", "status", "restart"])
    server_parser.add_argument("--host", default="127.0.0.1")
    server_parser.add_argument("--port", type=int, default=8766)
    server_parser.add_argument("--fake-backend", action="store_true", default=argparse.SUPPRESS)

    return parser


_TRANSPORT_VERBS = {"call": _cmd_call, "raw": _cmd_raw, "batch": _cmd_batch}


def _run(args: argparse.Namespace, server: SimpleMcpServer | None) -> int:
    if args.verb in ("list", "tools"):
        return _cmd_list(args)
    if args.verb == "describe":
        return _cmd_describe(args)
    if args.verb == "server":
        return _cmd_server(args)
    if args.verb == "call":
        args.call_arguments = _call_arguments(args)
    if args.verb == "raw" and args.method == "shutdown" and not args.yes:
        raise CliUsageError("refusing to send 'shutdown' without --yes")
    handler = _TRANSPORT_VERBS[args.verb]
    transport = _make_transport(args, server=server)
    try:
        return handler(args, transport)
    finally:
        transport.close()


def main(argv: list[str] | None = None, *, server: SimpleMcpServer | None = None) -> int:  # noqa: PLR0911
    """Entry point. ``server`` injects a pre-built :class:`SimpleMcpServer` (used by tests)."""

    _STDIN_CACHE.clear()
    args = build_cli_parser().parse_args(argv)
    try:
        return _run(args, server)
    except CliUsageError as exc:
        print(f"usage error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except RpcError as exc:
        return _handle_rpc_error(exc)
    except json.JSONDecodeError as exc:
        print(f"usage error: invalid JSON: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except ConnectionError as exc:
        print(f"connection error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (OSError, UnicodeError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
