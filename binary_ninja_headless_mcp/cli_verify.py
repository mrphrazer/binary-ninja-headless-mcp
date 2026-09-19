"""Native semantic CLI verification with an auditable, fail-closed coverage ledger.

Run ``python -m binary_ninja_headless_mcp.cli_verify --output /path/to/evidence``.
Every invocation and assertion is incrementally saved. A successful process exit
requires every catalog tool to have an explicit successful semantic assertion in
every selected transport/argument-style combination; merely calling a tool is
never counted as verified coverage.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import traceback
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest.mock import patch

from .catalog import TOOL_DEFINITIONS

CATALOG = {item["name"]: item for item in TOOL_DEFINITIONS}


# Defined independently of runtime observations: forgotten variants remain missing.
REQUIRED_VARIANTS = {
    "workflow.machine.control": {
        "breakpoint_delete",
        "breakpoint_set",
        "disable",
        "dump",
        "enable",
        "halt",
        "override_clear",
        "override_set-false",
        "override_set-true",
        "reset",
        "resume",
        "run",
    },
    "plugin.execute": {
        "native-" + kind
        for kind in (
            "default",
            "address",
            "range",
            "function",
            "llil_function",
            "llil_instruction",
            "mlil_function",
            "mlil_instruction",
            "hlil_function",
            "hlil_instruction",
            "global",
            "project",
        )
    },
    "debug.parse_and_apply": {"native-registered", "native-dwarf", "native-separate-debug"},
    "plugin_repo.plugin_action": {
        "native-install",
        "native-enable",
        "native-disable",
        "native-uninstall",
        "restart-after-disable",
        "restart-after-uninstall",
    },
    "il.function": {
        level + suffix
        for level in ("llil", "mlil", "hlil")
        for suffix in ("", "_ssa", "_page", "_ssa_page")
    },
    "transform.inspect": {
        prefix + mode + suffix
        for prefix in ("", "path_")
        for mode in ("disabled", "interactive", "full")
        for suffix in ("_inspect", "_process")
    },
    "memory.reader_read": {
        f"{endian}-{width}" for endian in ("little", "big") for width in (1, 2, 4, 8)
    },
    "memory.writer_write": {
        f"{endian}-{width}{suffix}"
        for endian in ("little", "big")
        for width in (1, 2, 4, 8)
        for suffix in ("", "-bytes")
    },
    "analysis.set_hold": {"hold", "release"},
    "binja.eval": {"expression", "statements"},
    "binja.call": {"property", "function"},
    "session.set_mode": {"True", "False"},
    "baseaddr.detect": {"instruction-bounded", "sampling-known-base"},
    "uidf.set_user_var_value": {"after-True", "after-False"},
    "uidf.clear_user_var_value": {"after-True", "after-False"},
}

REQUIRED_VARIANTS.update(
    {
        name: {level + suffix for level in ("llil", "mlil", "hlil") for suffix in ("", "_ssa")}
        for name in (
            "binary.get_function_il_at",
            "il.instruction_by_addr",
            "il.address_to_index",
            "il.index_to_address",
            "value.possible",
        )
    }
)
REQUIRED_VARIANTS.update({name: {"before", "after"} for name in ("value.reg", "value.stack")})
REQUIRED_VARIANTS.update(
    {
        name: {"mlil", "hlil"}
        for name in (
            "function.var_refs",
            "function.var_refs_from",
            "function.ssa_var_def_use",
            "function.ssa_memory_def_use",
        )
    }
)
REQUIRED_VARIANTS.update(
    {name: {"view_arch", "explicit"} for name in ("arch.assemble", "arch.disasm_bytes")}
)
REQUIRED_VARIANTS.update(
    {
        "il.rewrite.noop_replace": {"llil", "mlil", "hlil"},
        "il.rewrite.translate_identity": {"llil", "mlil"},
        "task.cancel": {"running-cancelled", "native-analysis-drained"},
        "task.result": {"analysis", "native-cancelled"},
    }
)
REQUIRED_VARIANTS.update(
    {
        "binary." + name: {"fixture_contents", "pagination"}
        for name in ("functions", "strings", "sections", "segments", "symbols", "data_vars")
    }
)


class VerificationFailure(RuntimeError):
    """A command or semantic oracle failed, with evidence preserved on disk."""


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_fixture(output: Path, compiler: str = "cc") -> Path:
    """Compile only into the analysis workspace and record reproducible identity."""
    output.mkdir(parents=True, exist_ok=True)
    source = Path(__file__).resolve().parent / "fixtures/binja_cli_native.c"
    binary = output / "binja_cli_native"
    command = [
        compiler,
        str(source),
        "-O0",
        "-g",
        "-fno-inline",
        "-fno-pie",
        "-no-pie",
        "-o",
        str(binary),
    ]
    result = subprocess.run(command, text=True, capture_output=True, check=False)
    (output / "build.json").write_text(
        json.dumps(
            {
                "command": command,
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            indent=2,
        )
    )
    if result.returncode:
        raise VerificationFailure(f"fixture compilation failed: {result.stderr}")
    identity = {
        "source": str(source),
        "source_sha256": sha256(source),
        "binary": str(binary),
        "sha256": sha256(binary),
        "command": command,
        "platform": platform.platform(),
    }
    (output / "identity.json").write_text(json.dumps(identity, indent=2))
    (output / "README.md").write_text(
        "# Native CLI fixture\n\nObjective: verify Binary Ninja CLI semantics on controlled "
        "functions, branches, globals, strings, and dependent types.\n\n"
        f"Input: `{binary}`\n\nSHA-256: `{identity['sha256']}`\n\n"
        "Build command and source hash: [identity.json](identity.json). "
        "Compiler output: [build.json](build.json). Original fixture is preserved; "
        "verification modifies private copies in each run directory.\n"
    )
    return binary


def flags_for(arguments: dict[str, Any]) -> list[str]:
    """Exercise ordinary scalar flags and typed complex/null arguments losslessly."""
    flags: list[str] = []
    for key, value in arguments.items():
        name = "--" + key.replace("_", "-")
        if isinstance(value, bool):
            flags += [name + ":bool", str(value).lower()]
        elif (
            value is None
            or isinstance(value, (list, dict))
            or (isinstance(value, str) and (value.startswith(("-", "@")) or value == ""))
        ):
            flags += [name + ":json", json.dumps(value)]
        elif isinstance(value, int):
            flags += [name + ":int", str(value)]
        elif isinstance(value, float):
            flags += [name + ":float", str(value)]
        else:
            flags += [name, str(value)]
    return flags


class Runner:
    """A real CLI driver shared by independently maintained semantic scenarios."""

    def __init__(
        self,
        fixture: Path,
        output: Path,
        *,
        mode: str,
        argument_style: str,
        endpoint: str | None = None,
        server: Any = None,
        env: dict[str, str] | None = None,
        timeout: float = 180,
        cli_worker: Any = None,
        wire_observer: Any = None,
    ):
        self.fixture = fixture.resolve()
        self.output = output.resolve()
        self.output.mkdir(parents=True, exist_ok=True)
        self.mode = mode
        self.argument_style = argument_style
        self.endpoint = endpoint
        self.server = server
        self.env = dict(os.environ if env is None else env)
        self.timeout = timeout
        self.cli_worker = cli_worker
        self.wire_observer = wire_observer
        self._parity_sequences: list[int] = []
        self.session_id = ""
        self.function_start = 0
        self.symbols: dict[str, int] = {}
        self.events: list[dict[str, Any]] = []
        self.assertions: list[dict[str, Any]] = []
        self.opened_sessions: set[str] = set()
        self._sequence = 0
        self._successful_calls: dict[str, list[int]] = {}
        self._trace = self.output / "trace.jsonl"
        self._assertion_file = self.output / "assertions.jsonl"
        self._initial_source_hashes = {
            p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")
        }
        self._initial_input_hash = sha256(self.fixture)
        (self.output / "provenance-start.json").write_text(
            json.dumps(
                {
                    "source_hashes": self._initial_source_hashes,
                    "input_sha256": self._initial_input_hash,
                    "python": sys.version,
                    "platform": platform.platform(),
                },
                indent=2,
            )
        )

    def _append(self, path: Path, data: dict[str, Any]) -> None:
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(data, sort_keys=True, default=str) + "\n")
            stream.flush()

    def tool(self, tool_name: str, **arguments: Any) -> dict[str, Any]:  # noqa: PLR0912, PLR0915
        name = tool_name
        if name not in CATALOG:
            raise VerificationFailure(f"unknown tool {name}")
        self._sequence += 1
        request_id = self._sequence
        batch = self.mode == "inprocess" and self.argument_style == "json"
        stdin = json.dumps({"tool": name, "arguments": arguments}) + "\n" if batch else ""
        argv = (
            ["batch", "-", "--no-autosession"]
            if batch
            else ["call", name]
            + (
                ["--json", json.dumps(arguments)]
                if self.argument_style == "json"
                else flags_for(arguments)
            )
        )
        if self.mode == "tcp":
            argv = ["--connect", str(self.endpoint), *argv]
        command = [sys.executable, "-m", "binary_ninja_headless_mcp.binja_cli", *argv]
        event = {
            "sequence": request_id,
            "tool": name,
            "arguments": arguments,
            "command": command,
            "stdin": stdin,
            "mode": self.mode,
            "argument_style": self.argument_style,
            "time": time.time(),
            "execution": "subprocess" if self.mode == "tcp" else "inprocess-main",
            "cli_argv": argv,
        }
        if self.cli_worker is not None:
            event.update(
                command=self.cli_worker.command,
                client_pid=self.cli_worker.pid,
                execution="persistent-cli-worker",
            )
        self._append(self._trace, {"event": "request", **event})
        start = time.monotonic()
        wire_calls = []
        wire_index = self.wire_observer.record_count if self.wire_observer else 0
        if self.mode == "tcp":
            try:
                if self.cli_worker is not None:
                    completed = self.cli_worker.invoke(argv, stdin=stdin, timeout=self.timeout)
                    code, stdout, stderr = (
                        completed["exit_code"],
                        completed["stdout"],
                        completed["stderr"],
                    )
                else:
                    completed = subprocess.run(
                        command,
                        input=stdin,
                        text=True,
                        capture_output=True,
                        env=self.env,
                        timeout=self.timeout,
                        check=False,
                    )
                    code, stdout, stderr = completed.returncode, completed.stdout, completed.stderr
            except (subprocess.TimeoutExpired, TimeoutError) as exc:
                self._append(self._trace, {"event": "timeout", **event, "error": str(exc)})
                raise VerificationFailure(f"{name} exceeded {self.timeout}s") from exc
        else:
            from .binja_cli import main

            captured_out, captured_err = io.StringIO(), io.StringIO()
            capture = contextlib.nullcontext()
            if self.server is not None:
                original = self.server.handle_request

                def observe(request):
                    result = original(request)
                    wire_calls.append({"request": request, "response": result})
                    return result

                capture = patch.object(self.server, "handle_request", side_effect=observe)
            with (
                capture,
                patch("sys.stdin", io.StringIO(stdin)),
                contextlib.redirect_stdout(captured_out),
                contextlib.redirect_stderr(captured_err),
            ):
                code = main(argv, server=self.server)
            stdout, stderr = captured_out.getvalue(), captured_err.getvalue()
        response = {
            "event": "response",
            **event,
            "exit_code": code,
            "stdout": stdout,
            "stderr": stderr,
            "elapsed": time.monotonic() - start,
        }
        self._append(self._trace, response)
        self.events.append(response)
        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, TypeError) as exc:
            raise VerificationFailure(
                f"{name}: non-JSON CLI response: {stdout!r} {stderr}"
            ) from exc
        if code or (isinstance(payload, dict) and payload.get("isError")):
            self.record(name, "command", False, "CLI command succeeds", response)
            raise VerificationFailure(f"{name}: CLI exit {code}: {payload}; {stderr}")
        if batch:
            payload = payload.get("structuredContent", {})
        if not isinstance(payload, dict):
            raise VerificationFailure(f"{name}: unexpected non-object payload {payload!r}")
        if self.wire_observer is not None:
            wire_calls = self.wire_observer.snapshot(wire_index)
        matching = [entry for entry in wire_calls if entry["request"].get("method") == "tools/call"]
        if self.server is not None or self.wire_observer is not None:
            exact = len(matching) == 1 and (
                matching[0]["request"]["params"] == {"name": name, "arguments": arguments}
                and matching[0]["response"]["result"].get("structuredContent", {}) == payload
                and not matching[0]["response"]["result"].get("isError", False)
            )
            self._append(
                self._trace,
                {
                    "event": "native-mcp-parity",
                    "sequence": request_id,
                    "passed": exact,
                    "wire": matching,
                },
            )
            if exact:
                self._parity_sequences.append(request_id)
            if not exact:
                raise VerificationFailure(
                    f"{name}: CLI arguments/output differ from actual native MCP response"
                )
        if name in {"session.open", "session.open_bytes", "session.open_existing"}:
            self.opened_sessions.add(payload["session_id"])
        elif name == "session.close":
            self.opened_sessions.discard(arguments["session_id"])
        self._successful_calls.setdefault(name, []).append(request_id)
        return payload

    def record(
        self, name: str, variant: str, passed: bool, expectation: str, details: Any = None
    ) -> None:
        if name not in CATALOG:
            raise VerificationFailure(f"oracle references unknown tool {name}")
        item = {
            "tool": name,
            "variant": variant,
            "passed": bool(passed),
            "expectation": expectation,
            "details": details,
            "sequence": self._sequence,
            "invocation_sequence": (self._successful_calls.get(name) or [None])[-1],
            "mode": self.mode,
            "argument_style": self.argument_style,
            "time": time.time(),
        }
        self.assertions.append(item)
        self._append(self._assertion_file, item)
        if not passed:
            raise VerificationFailure(f"{name}/{variant}: {expectation}; observed {details!r}")

    def verify(
        self,
        name: str,
        variant: str,
        arguments: dict[str, Any],
        predicate: Callable[[dict[str, Any]], bool],
        expectation: str,
    ) -> dict[str, Any]:
        payload = self.tool(name, **arguments)
        self.record(name, variant, bool(predicate(payload)), expectation, payload)
        return payload

    def native(self, code: str) -> Any:
        arguments = {"code": code}
        if self.session_id:
            arguments["session_id"] = self.session_id
        return self.tool("binja.eval", **arguments)["result"]

    def refresh_symbols(self) -> None:
        symbols = self.native("{s.raw_name: s.address for s in bv.get_symbols()}")
        self.symbols = {key: int(value) for key, value in symbols.items()}
        self.function_start = self.symbols.get("cli_add", self.function_start)

    @contextlib.contextmanager
    def isolated(self, **open_options: Any):
        old = self.session_id, self.function_start, self.symbols
        self._sequence += 1
        binary = self.output / f"working-{self._sequence}-{self.fixture.name}"
        shutil.copy2(self.fixture, binary)
        params = {
            "path": str(binary),
            "read_only": False,
            "update_analysis": True,
            "deterministic": True,
            **open_options,
        }
        opened = self.tool("session.open", **params)
        self.session_id = opened["session_id"]
        try:
            self.refresh_symbols()
            yield self
        finally:
            try:
                self.tool("session.close", session_id=self.session_id)
            finally:
                self.session_id, self.function_start, self.symbols = old

    def summary(self) -> dict[str, Any]:
        ledger = {}
        for name, definition in CATALOG.items():
            assertions = [item for item in self.assertions if item["tool"] == name]
            successes = [
                item
                for item in assertions
                if item["passed"]
                and item.get("invocation_sequence") in self._successful_calls.get(name, [])
            ]
            missing_variants = sorted(
                REQUIRED_VARIANTS.get(name, set()) - {item["variant"] for item in successes}
            )
            failures = [item for item in assertions if not item["passed"]]
            ledger[name] = {
                "status": "failed"
                if failures
                else "verified"
                if successes and not missing_variants
                else "missing",
                "required_variants": sorted(REQUIRED_VARIANTS.get(name, set())),
                "missing_variants": missing_variants,
                "assertions": assertions,
                "attempts": sum(item["tool"] == name for item in self.events),
                "schema": definition["inputSchema"],
            }
        missing = [name for name, entry in ledger.items() if entry["status"] != "verified"]
        final_hashes = {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")}
        parity_complete = len(self._parity_sequences) == sum(
            map(len, self._successful_calls.values())
        )
        source_unchanged = final_hashes == self._initial_source_hashes
        input_unchanged = sha256(self.fixture) == self._initial_input_hash
        result = {
            "mode": self.mode,
            "argument_style": self.argument_style,
            "input": str(self.fixture),
            "input_sha256": sha256(self.fixture),
            "catalog_count": len(CATALOG),
            "verified_count": len(CATALOG) - len(missing),
            "incomplete": missing,
            "complete": not missing and source_unchanged and input_unchanged and parity_complete,
            "native_mcp_parity_complete": parity_complete,
            "native_mcp_parity_count": len(self._parity_sequences),
            "source_unchanged": source_unchanged,
            "input_unchanged": input_unchanged,
            "source_hashes_start": self._initial_source_hashes,
            "ledger": ledger,
            "source_hashes": {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")},
        }
        (self.output / "coverage.json").write_text(json.dumps(result, indent=2, default=str))
        return result

    def close(self) -> None:
        errors = []
        for session in sorted(self.opened_sessions):
            try:
                self.tool("session.close", session_id=session)
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise VerificationFailure("cleanup failed: " + "; ".join(errors))


def settle(r: Runner, task: dict[str, Any]) -> dict[str, Any]:
    deadline = time.monotonic() + r.timeout
    while time.monotonic() < deadline:
        state = r.tool("task.status", task_id=task["task_id"])
        if state["result_ready"]:
            r.record(
                "task.status",
                "terminal",
                state["status"] in {"completed", "cancelled"},
                "Task reaches a successful or cancelled terminal state",
                state,
            )
            return r.tool("task.result", task_id=task["task_id"])
        time.sleep(0.02)
    raise VerificationFailure(f"task did not terminate: {task}")


def run_core(r: Runner) -> None:
    sid = r.session_id
    session = {"session_id": sid}
    r.verify("health.ping", "healthy", {}, lambda p: p.get("status") == "ok", "Backend is healthy")
    info = r.tool("binja.info")
    version = r.native("bn.core_version()")
    r.record(
        "binja.info",
        "native-version",
        info["version"] == version and "fake" not in version.lower(),
        "Reported version equals real licensed native runtime",
        info,
    )
    r.verify(
        "binja.eval",
        "expression",
        {**session, "code": "21 * 2"},
        lambda p: p["result"] == 42,
        "Native expression evaluation returns 42",
    )
    r.verify(
        "binja.eval",
        "statements",
        {**session, "code": "print('CLI_STDOUT'); _ = 6 * 7"},
        lambda p: p["result"] == 42 and p["stdout"] == "CLI_STDOUT\n",
        "Statement result and captured stdout are preserved",
    )
    r.verify(
        "binja.call",
        "property",
        {**session, "target": "bv.start"},
        lambda p: p["result"] == r.native("bv.start"),
        "API property equals native view start",
    )
    r.verify(
        "binja.call",
        "function",
        {"target": "bn.core_version"},
        lambda p: p["result"] == version,
        "API callable returns native core version",
    )
    r.verify(
        "mcp.response_format",
        "contract",
        {},
        lambda p: p["canonical_field"] == "structuredContent" and p["error_field"] == "isError",
        "Response descriptor identifies fields present in actual CLI batches",
    )
    listed = r.tool("session.list")
    r.record(
        "session.list",
        "open-session",
        any(x["session_id"] == sid for x in listed["sessions"]),
        "Session listing includes the exact opened fixture",
        listed,
    )
    for read_only in (True, False):
        r.tool("session.set_mode", **session, read_only=read_only)
        mode = r.tool("session.mode", **session)
        r.record(
            "session.set_mode",
            str(read_only),
            mode["read_only"] == read_only,
            "Mode change is observed by separate mode readback",
            mode,
        )
        r.record(
            "session.mode",
            str(read_only),
            mode["read_only"] == read_only,
            "Mode query reflects requested access policy",
            mode,
        )
    source = r.tool("session.open_existing", source_session_id=sid, update_analysis=True)
    r.record(
        "session.open_existing",
        "reopen-original",
        source["function_count"] >= 3,
        "Reopened input has the known compiled functions",
        source,
    )
    r.tool("session.close", session_id=source["session_id"])
    listing = r.tool("session.list")
    r.record(
        "session.close",
        "removed",
        source["session_id"] not in [x["session_id"] for x in listing["sessions"]],
        "Closed session is absent",
        listing,
    )
    uploaded = r.tool(
        "session.open_bytes",
        data_base64=base64.b64encode(r.fixture.read_bytes()).decode(),
        filename=r.fixture.name,
        update_analysis=True,
        read_only=False,
    )
    r.record(
        "session.open_bytes",
        "real-elf",
        uploaded["function_count"] >= 3,
        "Uploaded bytes produce the known ELF functions",
        uploaded,
    )
    r.tool("session.close", session_id=uploaded["session_id"])
    r.tool("analysis.update_and_wait", **session)
    state = r.tool("analysis.status", **session)
    r.record(
        "analysis.update_and_wait",
        "completed",
        state.get("status") == "completed",
        "Synchronous update reaches completed managed state",
        state,
    )
    r.record(
        "analysis.status",
        "native-state",
        "Idle" in str(state.get("state")),
        "Analyzed fixture native state is Idle",
        state,
    )
    progress = r.tool("analysis.progress", **session)
    r.record(
        "analysis.progress",
        "native-progress",
        progress.get("progress") == state.get("progress"),
        "Progress matches independent status query",
        progress,
    )
    for tool_name in ("analysis.update", "task.analysis_update"):
        task = r.tool(tool_name, **session)
        result = settle(r, task)
        r.record(
            tool_name,
            "async-complete",
            result["status"] == "completed",
            "Asynchronous analysis reaches completed state",
            result,
        )
        r.record(
            "task.result",
            "analysis",
            result["status"] == "completed" and isinstance(result.get("result"), dict),
            "Completed task carries analysis result",
            result,
        )
    search = settle(
        r, r.tool("task.search_text", **session, query="BINJA_CLI_NATIVE_SENTINEL", limit=100)
    )
    r.record(
        "task.search_text",
        "known-function",
        search["status"] == "completed" and bool(search["result"].get("items")),
        "Search task finds known function name",
        search,
    )
    r.tool("analysis.set_hold", **session, hold=True)
    held = r.native(
        f"bv.get_function_at({r.function_start}).reanalyze(); _ = bv.analysis_progress.state.name"
    )
    r.record(
        "analysis.set_hold",
        "hold",
        held == "HoldState",
        "Native reanalysis enters HoldState while held",
        held,
    )
    r.tool("analysis.set_hold", **session, hold=False)
    r.tool("analysis.update_and_wait", **session)
    released = r.tool("analysis.status", **session)
    r.record(
        "analysis.set_hold",
        "release",
        released["status"] == "completed",
        "Native reanalysis completes after release",
        released,
    )
    from .cli_verify_stateful import run_cancellation

    run_cancellation(r)
    r.tool("analysis.abort", **session)
    aborted = r.tool("analysis.status", **session)
    r.record(
        "analysis.abort",
        "native-abort",
        aborted["is_aborted"] is True,
        "Abort sets native aborted state",
        aborted,
    )
    r.tool("analysis.update_and_wait", **session)


def run_database(r: Runner) -> None:
    with r.isolated():
        session = {"session_id": r.session_id}
        path = r.output / "persistent.bndb"
        r.tool("metadata.store", **session, key="cli-persistence", value={"answer": 42})
        created = r.tool("database.create_bndb", **session, path=str(path))
        r.record(
            "database.create_bndb",
            "disk",
            created["created"] and path.is_file() and path.stat().st_size > 0,
            "Native database is created on disk",
            created,
        )
        r.tool("database.write_global", **session, key="cli-global", value="native-value")
        readback = r.tool("database.read_global", **session, key="cli-global")
        r.record(
            "database.write_global",
            "readback",
            readback["value"] == "native-value",
            "Database global persists exact value",
            readback,
        )
        r.record(
            "database.read_global",
            "readback",
            readback["value"] == "native-value",
            "Global query recovers expected value",
            readback,
        )
        saved = r.tool("database.save_auto_snapshot", **session)
        snapshots = r.tool("database.snapshots", **session)
        r.record(
            "database.save_auto_snapshot",
            "snapshot",
            saved["saved"] and len(snapshots["items"]) >= 1,
            "Saved snapshot appears in native database listing",
            snapshots,
        )
        native_ids = r.native("[s.id for s in bv.file.database.snapshots]")
        r.record(
            "database.snapshots",
            "native-ids",
            [s["id"] for s in snapshots["items"]] == native_ids,
            "Snapshot identifiers match direct native database",
            snapshots,
        )
        info = r.tool("database.info", **session)
        r.record(
            "database.info",
            "native-count",
            info["snapshot_count"] == len(native_ids),
            "Database summary count matches native snapshots",
            info,
        )
        reopened = r.tool("session.open", path=str(path), read_only=False, update_analysis=True)
        value = r.tool("metadata.query", session_id=reopened["session_id"], key="cli-persistence")
        r.record(
            "database.create_bndb",
            "reopen",
            value["value"] == {"answer": 42},
            "Database reopened in a new session preserves metadata",
            value,
        )
        value = r.tool("database.read_global", session_id=reopened["session_id"], key="cli-global")
        r.record(
            "database.write_global",
            "reopen",
            value["value"] == "native-value",
            "Database global survives reopen",
            value,
        )
        r.tool("session.close", session_id=reopened["session_id"])
        destination = r.output / "saved-binary"
        saved = r.tool("binary.save", **session, path=str(destination))
        r.record(
            "binary.save",
            "byte-identity",
            saved["saved"] and sha256(destination) == sha256(r.fixture),
            "Saving unchanged fixture preserves its exact input bytes",
            saved,
        )


def native_il_signature(r: Runner, expression: str) -> Any:
    return r.native(f"""def semantic(value):
    if hasattr(value, 'operation') and hasattr(value, 'operands'):
        return [value.address, value.operation.name, value.size,
                [semantic(v) for v in value.operands]]
    if isinstance(value, (list, tuple)):
        return [semantic(v) for v in value]
    if hasattr(value, 'identifier'):
        return [type(value).__name__, value.identifier]
    return str(value)
_ = [semantic(i) for i in {expression}.instructions]
""")


def run_rewrites(r: Runner) -> None:
    for level, native_attr in (
        ("llil", "low_level_il"),
        ("mlil", "medium_level_il"),
        ("hlil", "high_level_il"),
    ):
        with r.isolated():
            args = {"session_id": r.session_id, "function_start": r.function_start, "level": level}
            expr = f"bv.get_function_at({r.function_start}).{native_attr}"
            caps = r.tool("il.rewrite.capabilities", **args)
            native = r.native(
                f"{{'replace_expr':hasattr({expr},'replace_expr'), "
                f"'translate':hasattr({expr},'translate')}}"
            )
            r.record(
                "il.rewrite.capabilities",
                level,
                caps["supports_replace_expr"] == native["replace_expr"]
                and caps["supports_translate"] == native["translate"],
                "Capability flags match real native IL objects",
                caps,
            )
            before = native_il_signature(r, expr)
            r.tool("il.rewrite.noop_replace", **args, index=0)
            after = native_il_signature(r, expr)
            r.record(
                "il.rewrite.noop_replace",
                level,
                before == after and bool(before),
                "No-op rewrite preserves every native IL instruction",
                {"before": before, "after": after},
            )
            if native["translate"]:
                r.native(f"""il = {expr}
kind = type(il)
original_translate = kind.translate
bn._cli_translation_original = original_translate
bn._cli_translation_kind = kind
bn._cli_translation_capture = None
def capture(self, callback):
    translated = bn._cli_translation_original(self, callback)
    bn._cli_translation_capture = translated
    return translated
kind.translate = capture
_ = True
""")
                try:
                    translated = r.tool("il.rewrite.translate_identity", **args)
                    observed = r.native(f"""def semantic(value):
    if hasattr(value, 'operation') and hasattr(value, 'operands'):
        return [value.address, value.operation.name, value.size,
                [semantic(v) for v in value.operands]]
    if isinstance(value, (list, tuple)):
        return [semantic(v) for v in value]
    if hasattr(value, 'identifier'):
        return [type(value).__name__, value.identifier]
    return str(value)
_ = {{'source': [semantic(i) for i in {expr}.instructions],
     'translated': [semantic(i) for i in bn._cli_translation_capture.instructions]}}
""")
                    r.record(
                        "il.rewrite.translate_identity",
                        level,
                        bool(observed["source"])
                        and observed["source"] == observed["translated"]
                        and translated["translated_instruction_count"] == len(observed["source"]),
                        "Every copied expression, operand, address and operation matches source",
                        observed,
                    )
                finally:
                    r.native(
                        "bn._cli_translation_kind.translate = bn._cli_translation_original; "
                        "bn._cli_translation_capture = None; _ = True"
                    )
    with r.isolated():
        args = {"session_id": r.session_id, "function_start": r.function_start}
        parsed = r.tool(
            "uidf.parse_possible_value",
            session_id=r.session_id,
            value="0x2a",
            state="ConstantValue",
        )
        r.record(
            "uidf.parse_possible_value",
            "constant",
            "2a" in str(parsed["parsed"]).lower() or "42" in str(parsed["parsed"]),
            "Possible value parser preserves constant 42",
            parsed,
        )
        name = r.native(f"bv.get_function_at({r.function_start}).parameter_vars[0].name")
        varargs = {**args, "variable_name": name, "def_addr": r.function_start}
        for after in (True, False):
            r.tool(
                "uidf.set_user_var_value",
                **varargs,
                value="0x2a",
                state="ConstantValue",
                after=after,
            )
            listed = r.tool("uidf.list_user_var_values", **args)
            raw = r.native(
                "import ctypes\nfrom binaryninja import _binaryninjacore as core\n"
                f"f=bv.get_function_at({r.function_start})\ncount=ctypes.c_ulonglong()\n"
                "values=core.BNGetAllUserVariableValues(f.handle,count)\n"
                "try:\n"
                " _=[{'address': values[i].defSite.address, 'after': bool(values[i].after), "
                "'value': values[i].value.value} for i in range(count.value)]\n"
                "finally:\n core.BNFreeUserVariableValues(values)"
            )
            expected = [{"address": r.function_start, "after": after, "value": 42}]
            correct_listing = len(listed["items"]) == 1 and (
                listed["items"][0]["variable"]["name"] == name
                and listed["items"][0]["definitions"][0]["address"] == hex(r.function_start)
                and listed["items"][0]["definitions"][0]["value"] == "<const 0x2a>"
            )
            r.record(
                "uidf.set_user_var_value",
                f"after-{after}",
                raw == expected and correct_listing,
                "Native value is exactly 42 at requested definition site and before/after position",
                {"native": raw, "listing": listed},
            )
            r.record(
                "uidf.list_user_var_values",
                f"after-{after}",
                correct_listing,
                "Listing contains exact constant, variable, and definition address",
                listed,
            )
            r.tool("uidf.clear_user_var_value", **varargs, after=after)
            empty = r.tool("uidf.list_user_var_values", **args)
            r.record(
                "uidf.clear_user_var_value",
                f"after-{after}",
                not empty["items"],
                "Clearing parameter value removes it from native listing",
                empty,
            )


def run_baseaddr(r: Runner) -> None:
    firmware = r.output / "baseaddr-firmware.bin"
    r.native(rf"""arch=bn.Architecture['x86_64']
base=0x400000
buf=bytearray(0x10000)
for n in range(64):
    offset=0x1000+n*64
    target=base+0x8000+n*64
    code=arch.assemble(f'push rbp\nmov rbp, rsp\nmovzx eax, byte [{{target}}]\npop rbp\nret',offset)
    buf[offset:offset+len(code)]=code
    buf[0x7000+n*8:0x7008+n*8]=target.to_bytes(8,'little')
    msg=f'BASE_DETECTION_UNIQUE_SENTINEL_{{n:04d}}_abcdefghijklmnop'.encode()+b'\0'
    buf[0x8000+n*64:0x8000+n*64+len(msg)]=msg
calls='\n'.join(f'call {{0x1000+n*64}}' for n in range(64))
entry=arch.assemble('push rbp\nmov rbp, rsp\n'+calls+'\npop rbp\nret',0)
buf[:len(entry)]=entry
from pathlib import Path
Path({str(firmware)!r}).write_bytes(buf)
_=len(buf)
""")
    (r.output / "baseaddr-firmware-identity.json").write_text(
        json.dumps(
            {
                "path": str(firmware),
                "sha256": sha256(firmware),
                "expected_base": "0x400000",
                "expected_string_offsets": [hex(0x8000 + i * 64) for i in range(64)],
                "provenance": "Native assembler generation command preserved in trace.jsonl",
            },
            indent=2,
        )
    )
    opened = r.tool(
        "session.open",
        path=str(firmware),
        update_analysis=False,
        read_only=False,
        options={
            "loader.platform": "linux-x86_64",
            "loader.architecture": "x86_64",
            "loader.entryPoint": 0,
        },
    )
    args = {
        "session_id": opened["session_id"],
        "arch_name": "x86_64",
        "low_boundary": 0x3F0000,
        "high_boundary": 0x410000,
    }
    try:
        instruction = r.tool(
            "baseaddr.detect",
            **args,
            algorithm="instruction",
            analysis="basic",
            alignment=4096,
            max_pointers=128,
        )
        r.record(
            "baseaddr.detect",
            "instruction-bounded",
            instruction["score_count"] == len(instruction["scores"])
            and instruction["detected"] == bool(instruction["scores"]),
            "Bounded native instruction algorithm reports coherent candidate presence",
            instruction,
        )
        sampled = r.tool("baseaddr.detect", **args, algorithm="sampling")
        r.record(
            "baseaddr.detect",
            "sampling-known-base",
            sampled["detected"]
            and sampled["preferred_base_address"] == "0x400000"
            and sampled["score_count"] == len(sampled["scores"])
            and sampled["scores"][0]["score"] >= 64,
            "Native sampling recovers known firmware base with all 64 string pointers",
            sampled,
        )
        reasons = r.tool("baseaddr.reasons", session_id=opened["session_id"], base_address=0x400000)
        expected = {(0x400000 + 0x8000 + i * 64, 0x8000 + i * 64) for i in range(64)}
        actual = {(int(x["pointer"], 0), int(x["offset"], 0)) for x in reasons["items"]}
        r.record(
            "baseaddr.reasons",
            "known-pointer-offset-pairs",
            expected <= actual and reasons["count"] == len(reasons["items"]),
            "Every known firmware pointer and corresponding string offset explains candidate",
            reasons,
        )
        aborted = r.tool("baseaddr.abort", session_id=opened["session_id"])
        r.record(
            "baseaddr.abort",
            "abort-context",
            aborted["aborted"] is True,
            "Native detector reports aborted state",
            aborted,
        )
    finally:
        r.tool("session.close", session_id=opened["session_id"])


@contextlib.contextmanager
def tcp_server(output: Path, env: dict[str, str]):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    server_env = {**env, "BINJA_CLI_HOME": str(output / "managed-state")}
    prefix = [sys.executable, "-m", "binary_ninja_headless_mcp.binja_cli", "server"]
    command = [*prefix, "start", "--host", "127.0.0.1", "--port", str(port)]
    started = subprocess.run(
        command, env=server_env, capture_output=True, text=True, timeout=90, check=False
    )
    (output / "server-start.json").write_text(
        json.dumps(
            {
                "command": command,
                "exit_code": started.returncode,
                "stdout": started.stdout,
                "stderr": started.stderr,
            },
            indent=2,
        )
    )
    if started.returncode:
        raise VerificationFailure(f"Managed TCP server failed to start: {started.stderr}")
    try:
        from .cli_verify_wire import record_proxy

        with record_proxy("127.0.0.1", port, output / "native-wire.jsonl") as proxy:
            yield proxy
    finally:
        command = [*prefix, "stop"]
        stopped = subprocess.run(
            command, env=server_env, capture_output=True, text=True, timeout=90, check=False
        )
        (output / "server-stop.json").write_text(
            json.dumps(
                {
                    "command": command,
                    "exit_code": stopped.returncode,
                    "stdout": stopped.stdout,
                    "stderr": stopped.stderr,
                },
                indent=2,
            )
        )
        if stopped.returncode:
            raise VerificationFailure(f"Managed TCP server failed to stop: {stopped.stderr}")


def run_matrix(  # noqa: PLR0912, PLR0915 - isolated matrix lifecycle
    fixture: Path,
    output: Path,
    modes: list[str],
    styles: list[str],
    groups: list[str],
    *,
    timeout: float = 180,
    special: Any = None,
    tcp_process_mode: str = "worker",
) -> dict[str, Any]:
    initial_sources = {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")}
    input_hash = sha256(fixture)
    from .cli_verify_mutations import run_mutations
    from .cli_verify_reads import run_reads
    from .cli_verify_stateful import run_stateful

    callbacks = {
        "core": run_core,
        "reads": run_reads,
        "mutations": run_mutations,
        "database": run_database,
        "rewrites": run_rewrites,
        "baseaddr": run_baseaddr,
        "stateful": run_stateful,
    }
    if special is not None:
        from .cli_verify_special import run_special

        callbacks["special"] = lambda runner: run_special(runner, special)
    env = dict(os.environ)
    for key in (
        "BN_DISABLE_USER_PLUGINS",
        "BN_DISABLE_USER_SETTINGS",
        "BN_DISABLE_REPOSITORY_PLUGINS",
    ):
        env.pop(key, None)
    if special is not None:
        env.update(special.env)
    if env.get("BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND") == "1":
        raise VerificationFailure("Native verification refuses fake-backend environment")
    summaries, errors = [], []
    with patch.dict(os.environ, env, clear=True):
        for mode in modes:
            for style in styles:
                directory = output / f"{mode}-{style}"
                directory.mkdir(parents=True, exist_ok=True)
                backend = None
                runner = None
                try:
                    with contextlib.ExitStack() as stack:
                        if mode == "inprocess":
                            from .backend import BinjaBackend
                            from .cli import load_binja_module
                            from .server import SimpleMcpServer

                            backend = BinjaBackend(load_binja_module(False))
                            server = SimpleMcpServer(backend)
                            endpoint = None
                            wire_observer = None
                        else:
                            server = None
                            proxy = stack.enter_context(tcp_server(directory, env))
                            endpoint = proxy.endpoint
                            wire_observer = proxy
                        client_worker = None
                        if mode == "tcp" and tcp_process_mode == "worker":
                            from .cli_verify_worker import CliWorker

                            client_worker = stack.enter_context(CliWorker(env=env))
                            (directory / "client-worker.json").write_text(
                                json.dumps(
                                    {
                                        "command": client_worker.command,
                                        "pid": client_worker.pid,
                                        "execution": "real CLI main per request",
                                    },
                                    indent=2,
                                )
                            )
                        runner = Runner(
                            fixture,
                            directory,
                            mode=mode,
                            argument_style=style,
                            endpoint=endpoint,
                            server=server,
                            env=env,
                            timeout=timeout,
                            cli_worker=client_worker,
                            wire_observer=wire_observer,
                        )
                        try:
                            runner.tool("binja.eval", code="bn._init_plugins(); _ = True")
                            for group in groups:
                                if group not in callbacks:
                                    errors.append(
                                        {
                                            "mode": mode,
                                            "style": style,
                                            "group": group,
                                            "error": "scenario group unavailable",
                                        }
                                    )
                                    continue
                                print(f"[{mode}/{style}] {group}", flush=True)
                                try:
                                    with runner.isolated(
                                        **(
                                            {
                                                "options": {
                                                    "analysis.debugInfo.internal": False,
                                                    "analysis.debugInfo.external": False,
                                                }
                                            }
                                            if group == "special"
                                            else {}
                                        )
                                    ):
                                        runner.record(
                                            "session.open",
                                            "fixture",
                                            {"cli_add", "cli_branch", "main"}
                                            <= runner.symbols.keys(),
                                            "Opened native fixture contains known symbols",
                                            runner.symbols,
                                        )
                                        callbacks[group](runner)
                                except Exception as exc:
                                    failure = {
                                        "mode": mode,
                                        "style": style,
                                        "group": group,
                                        "error": str(exc),
                                        "traceback": traceback.format_exc(),
                                    }
                                    errors.append(failure)
                                    runner._append(directory / "errors.jsonl", failure)
                                    print(f"  FAILED: {exc}", file=sys.stderr, flush=True)
                        finally:
                            runner.close()
                            summaries.append(runner.summary())
                except Exception as exc:
                    errors.append(
                        {
                            "mode": mode,
                            "style": style,
                            "error": str(exc),
                            "traceback": traceback.format_exc(),
                        }
                    )
                    if runner is not None:
                        runner.summary()
                finally:
                    if backend is not None:
                        backend.shutdown()
    errors.extend(matrix_errors(summaries, modes, styles, input_hash, initial_sources))
    result = {
        "complete": len(summaries) == len(modes) * len(styles)
        and not errors
        and all(s["complete"] for s in summaries),
        "matrix": [{key: value for key, value in s.items() if key != "ledger"} for s in summaries],
        "errors": errors,
    }
    (output / "summary.json").write_text(json.dumps(result, indent=2))
    return result


def matrix_errors(summaries, modes, styles, input_hash, initial_sources):
    """Reject omitted/duplicated cells and results spanning different source revisions."""
    problems = []
    expected = {(mode, style) for mode in modes for style in styles}
    observed = [(item.get("mode"), item.get("argument_style")) for item in summaries]
    if len(observed) != len(expected) or set(observed) != expected:
        problems.append(
            {
                "error": "matrix cells differ from exact requested combinations",
                "expected": sorted(expected),
                "observed": observed,
            }
        )
    current = {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")}
    if initial_sources != current:
        problems.append({"error": "source changed during matrix"})
    for item in summaries:
        if (
            item.get("source_hashes_start") != initial_sources
            or item.get("source_hashes") != initial_sources
            or item.get("input_sha256") != input_hash
        ):
            problems.append(
                {
                    "error": "matrix cell source/input identity differs",
                    "mode": item.get("mode"),
                    "style": item.get("argument_style"),
                }
            )
    return problems


def main(argv: list[str] | None = None) -> int:  # noqa: PLR0915 - process-isolated evidence lifecycle
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--binary", type=Path, help="Previously compiled controlled CLI fixture")
    parser.add_argument("--compiler", default="cc")
    parser.add_argument("--mode", choices=("inprocess", "tcp", "both"), default="both")
    parser.add_argument("--argument-style", choices=("json", "flags", "both"), default="both")
    parser.add_argument(
        "--groups", default="core,reads,mutations,database,rewrites,baseaddr,stateful,special"
    )
    parser.add_argument("--timeout", type=float, default=180)
    parser.add_argument(
        "--tcp-process-mode",
        choices=("worker", "subprocess"),
        default="worker",
        help="Reuse an isolated real CLI process, or start one for every TCP call",
    )
    parser.add_argument(
        "--without-special",
        action="store_true",
        help="Omit isolated native plugins (their coverage remains incomplete)",
    )
    args = parser.parse_args(argv)
    args.output = args.output.resolve()
    if args.output.exists() and any(args.output.iterdir()):
        parser.error("--output must be new or empty; existing evidence is never overwritten")
    args.output.mkdir(parents=True, exist_ok=True)
    fixture = (
        args.binary.resolve()
        if args.binary
        else build_fixture(args.output / "fixture", args.compiler)
    )
    modes = ["inprocess", "tcp"] if args.mode == "both" else [args.mode]
    styles = ["json", "flags"] if args.argument_style == "both" else [args.argument_style]
    groups = args.groups.split(",")
    initial_sources = {p.name: sha256(p) for p in Path(__file__).parent.glob("*.py")}
    input_hash = sha256(fixture)
    if len(modes) * len(styles) > 1:
        # Native plugin/core settings are process-global, so every matrix cell has
        # a fresh process and isolated user directory before the first BN import.
        results, errors = [], []
        for mode in modes:
            for style in styles:
                cell = args.output / f"cell-{mode}-{style}"
                command = [
                    sys.executable,
                    "-m",
                    "binary_ninja_headless_mcp.cli_verify",
                    "--output",
                    str(cell),
                    "--binary",
                    str(fixture),
                    "--mode",
                    mode,
                    "--argument-style",
                    style,
                    "--groups",
                    args.groups,
                    "--timeout",
                    str(args.timeout),
                    "--tcp-process-mode",
                    args.tcp_process_mode,
                ]
                if args.without_special:
                    command.append("--without-special")
                with (
                    (args.output / f"{mode}-{style}.stdout").open("w") as stdout,
                    (args.output / f"{mode}-{style}.stderr").open("w") as stderr,
                ):
                    print(f"Verifying fresh process {mode}/{style}", flush=True)
                    try:
                        completed = subprocess.run(
                            command,
                            stdout=stdout,
                            stderr=stderr,
                            timeout=max(600, args.timeout * 20),
                            check=False,
                        )
                        cell_summary = cell / "summary.json"
                        if cell_summary.exists():
                            result = json.loads(cell_summary.read_text())
                            results.extend(result["matrix"])
                            errors.extend(result["errors"])
                        if completed.returncode:
                            errors.append(
                                {
                                    "mode": mode,
                                    "style": style,
                                    "exit_code": completed.returncode,
                                    "command": command,
                                }
                            )
                    except subprocess.TimeoutExpired:
                        cleanup = {"attempted": False}
                        if mode == "tcp":
                            stop_command = [
                                sys.executable,
                                "-m",
                                "binary_ninja_headless_mcp.binja_cli",
                                "server",
                                "stop",
                            ]
                            stop_env = {
                                **os.environ,
                                "BINJA_CLI_HOME": str(cell / f"tcp-{style}" / "managed-state"),
                            }
                            try:
                                stopped = subprocess.run(
                                    stop_command,
                                    env=stop_env,
                                    text=True,
                                    capture_output=True,
                                    timeout=90,
                                    check=False,
                                )
                                cleanup = {
                                    "attempted": True,
                                    "command": stop_command,
                                    "exit_code": stopped.returncode,
                                    "stdout": stopped.stdout,
                                    "stderr": stopped.stderr,
                                }
                            except subprocess.TimeoutExpired:
                                cleanup = {"attempted": True, "timeout": True}
                        (cell / "special" / "user" / "license.dat").unlink(missing_ok=True)
                        errors.append(
                            {
                                "mode": mode,
                                "style": style,
                                "timeout": True,
                                "command": command,
                                "cleanup": cleanup,
                            }
                        )
        errors.extend(matrix_errors(results, modes, styles, input_hash, initial_sources))
        result = {
            "complete": len(results) == len(modes) * len(styles)
            and not errors
            and all(item["complete"] for item in results),
            "matrix": results,
            "errors": errors,
        }
        (args.output / "summary.json").write_text(json.dumps(result, indent=2))
        print(
            json.dumps(
                {"complete": result["complete"], "summary": str(args.output / "summary.json")}
            )
        )
        return 0 if result["complete"] else 1
    special_context = contextlib.nullcontext(None)
    if not args.without_special:
        from .cli_verify_special import prepare_special

        special_context = prepare_special(args.output / "special")
    with special_context as special:
        result = run_matrix(
            fixture,
            args.output,
            modes,
            styles,
            groups,
            timeout=args.timeout,
            special=special,
            tcp_process_mode=args.tcp_process_mode,
        )
    print(
        json.dumps(
            {
                "complete": result["complete"],
                "summary": str(args.output / "summary.json"),
                "matrix": [
                    {
                        "mode": m["mode"],
                        "argument_style": m["argument_style"],
                        "verified": m["verified_count"],
                        "total": m["catalog_count"],
                    }
                    for m in result["matrix"]
                ],
            },
            indent=2,
        )
    )
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
