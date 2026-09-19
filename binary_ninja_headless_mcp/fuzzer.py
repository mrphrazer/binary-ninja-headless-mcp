"""Feature fuzzer for the Binary Ninja Headless MCP server.

The fuzzer opens a sample binary (defaults to ``samples/ls``), enumerates the MCP tool
catalog, and exercises a broad set of tool calls with schema-driven arguments.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import random
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .backend import BinjaBackend
from .cli import load_binja_module
from .server import JsonRpcError, SimpleMcpServer

ADDRESS_KEYS = {
    "address",
    "start",
    "end",
    "entry_point",
    "function_start",
    "source_address",
    "target_address",
    "base_address",
    "def_addr",
    "here",
}

DEFERRED_TOOLS = {
    "loader.rebase",
    "project.close",
    "session.close",
}

HEAVY_RANDOM_TOOLS = {
    "analysis.update_and_wait",
    "baseaddr.detect",
    "task.analysis_update",
}

RANDOM_EXCLUDED_TOOLS = {
    "database.create_bndb",
    "project.create",
    "project.open",
    "session.open",
    "session.open_bytes",
    "session.open_existing",
    "type_archive.create",
    "type_archive.open",
    "type_library.create",
    "type_library.load",
}

EXTERNAL_ACTION_TOOLS = {
    "plugin.execute",
    "plugin_repo.check_updates",
    "plugin_repo.plugin_action",
}

_MISSING = object()


@dataclass
class ToolStats:
    attempts: int = 0
    successes: int = 0
    errors: int = 0
    last_error: str | None = None


@dataclass
class FuzzState:
    sample_path: Path
    sample_data_b64: str
    work_dir: Path
    active_session_id: str | None = None
    active_project_id: str | None = None
    active_repository_path: str | None = None
    session_ids: set[str] = field(default_factory=set)
    task_ids: set[str] = field(default_factory=set)
    project_ids: set[str] = field(default_factory=set)
    project_paths: set[str] = field(default_factory=set)
    folder_ids: set[str] = field(default_factory=set)
    type_library_ids: set[str] = field(default_factory=set)
    type_library_paths: set[str] = field(default_factory=set)
    type_archive_ids: set[str] = field(default_factory=set)
    type_archive_paths: set[str] = field(default_factory=set)
    type_names: set[str] = field(default_factory=lambda: {"mcp_fuzz_type"})
    workflow_names: set[str] = field(default_factory=set)
    workflow_activities: set[str] = field(default_factory=set)
    plugin_command_names: set[str] = field(default_factory=set)
    load_setting_types: set[str] = field(default_factory=set)
    transaction_ids: set[str] = field(default_factory=set)
    addresses: set[int] = field(default_factory=set)
    symbol_addresses: set[int] = field(default_factory=set)
    function_starts: set[int] = field(default_factory=set)
    variable_names: set[str] = field(default_factory=set)
    register_names: set[str] = field(default_factory=set)
    external_library_names: set[str] = field(default_factory=set)
    repository_paths: set[str] = field(default_factory=set)
    repository_plugins: dict[str, set[str]] = field(default_factory=dict)
    database_session_ids: set[str] = field(default_factory=set)
    bndb_paths: set[str] = field(default_factory=set)
    start_address: int | None = None
    end_address: int | None = None


class LocalMcpClient:
    """In-process JSON-RPC helper that talks to ``SimpleMcpServer``."""

    def __init__(self, server: SimpleMcpServer):
        self._server = server
        self._request_id = 0

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._request_id += 1
        request = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
            "params": params or {},
        }
        response = self._server.handle_request(request)
        if response is None:
            raise JsonRpcError(code=-32603, message=f"No response for method: {method}")

        error = response.get("error")
        if isinstance(error, dict):
            raise JsonRpcError(
                code=int(error.get("code", -32603)),
                message=str(error.get("message", "JSON-RPC error")),
                data=error.get("data"),
            )

        result = response.get("result")
        if not isinstance(result, dict):
            raise JsonRpcError(code=-32603, message=f"Invalid result payload for method: {method}")
        return result

    def list_all_tools(self, page_size: int = 100) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        offset = 0

        while True:
            page = self.call(
                "tools/list",
                {"offset": offset, "limit": page_size},
            )
            items = page.get("tools", [])
            if not isinstance(items, list):
                break
            tools.extend(item for item in items if isinstance(item, dict))

            has_more = bool(page.get("has_more"))
            if not has_more:
                break
            offset += len(items)

        return tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> tuple[bool, dict[str, Any], str]:
        result = self.call("tools/call", {"name": name, "arguments": arguments})
        is_error = bool(result.get("isError"))

        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict):
            payload = {"raw": payload}

        text = ""
        content = result.get("content")
        if isinstance(content, list) and content:
            first = content[0]
            if isinstance(first, dict):
                maybe_text = first.get("text")
                if isinstance(maybe_text, str):
                    text = maybe_text

        return is_error, payload, text


class McpFeatureFuzzer:
    """Schema-driven MCP feature fuzzer with lightweight state tracking."""

    def __init__(
        self,
        server: SimpleMcpServer,
        binary_path: Path,
        *,
        iterations: int,
        seed: int,
        update_analysis: bool,
        verbose: bool,
        trace_path: Path | None = None,
        load_options: dict[str, Any] | None = None,
        analysis_database: Path | None = None,
    ):
        self._client = LocalMcpClient(server)
        self._source_hashes = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(Path(__file__).parent.glob("*.py"))
        }
        self._rng = random.Random(seed)
        self._iterations = max(iterations, 0)
        self._seed = seed
        self._update_analysis = update_analysis
        self._verbose = verbose
        self._trace_path = trace_path
        self._load_options = dict(load_options or {})
        if trace_path is not None:
            trace_path.parent.mkdir(parents=True, exist_ok=True)
        self._task_states: dict[str, str] = {}
        self._unavailable_calls: list[dict[str, str]] = []
        self._stats: dict[str, ToolStats] = {}
        self._attempted_tools: set[str] = set()
        self._successful_tools: set[str] = set()
        self._counter = 0
        self._work_dir = Path(
            tempfile.mkdtemp(
                prefix="binja-mcp-fuzzer-",
                dir=trace_path.parent if trace_path else None,
            )
        )

        self._analysis_database = None
        if analysis_database is not None:
            self._analysis_database = self._work_dir / "seed.bndb"
            shutil.copy2(analysis_database, self._analysis_database)
        sample_data_b64 = base64.b64encode(binary_path.read_bytes()).decode("ascii")
        self._state = FuzzState(
            sample_path=binary_path,
            sample_data_b64=sample_data_b64,
            work_dir=self._work_dir,
        )

    def close(self) -> None:
        shutil.rmtree(self._work_dir, ignore_errors=True)

    def run(self) -> dict[str, Any]:
        self._client.call("initialize", {})
        self._client.call("ping", {})

        tool_defs = self._client.list_all_tools()
        tools_by_name = {
            tool["name"]: tool for tool in tool_defs if isinstance(tool.get("name"), str)
        }

        self._seed_state(tools_by_name)

        ordered_tools = self._ordered_tool_names(tools_by_name)
        for tool_name in ordered_tools:
            if tool_name in EXTERNAL_ACTION_TOOLS or tool_name in self._attempted_tools:
                continue
            tool_def = tools_by_name[tool_name]
            args = self._build_arguments(tool_name, tool_def, fuzz=False)
            self._invoke(tool_name, args)

        for tool_name in ordered_tools:
            if tool_name in EXTERNAL_ACTION_TOOLS:
                continue
            if tool_name in self._attempted_tools:
                continue
            tool_def = tools_by_name[tool_name]
            args = self._build_arguments(tool_name, tool_def, fuzz=False)
            self._invoke(tool_name, args)

        random_tools = [
            name
            for name in ordered_tools
            if name not in HEAVY_RANDOM_TOOLS
            and name not in RANDOM_EXCLUDED_TOOLS
            and name not in EXTERNAL_ACTION_TOOLS
        ]
        for _ in range(self._iterations):
            if not random_tools:
                break
            tool_name = self._rng.choice(random_tools)
            tool_def = tools_by_name[tool_name]
            args = self._build_arguments(tool_name, tool_def, fuzz=True)
            self._invoke(tool_name, args)

        self._deferred_cleanup()

        self._client.call("shutdown", {})
        return self._summary(tool_defs)

    def _ordered_tool_names(self, tools_by_name: dict[str, dict[str, Any]]) -> list[str]:
        seed_priority = [
            "health.ping",
            "binja.info",
            "session.open",
            "analysis.update",
            "analysis.progress",
            "binary.summary",
            "binary.functions",
            "binary.strings",
            "binary.sections",
            "binary.segments",
            "binary.symbols",
            "binary.data_vars",
            "arch.info",
            "function.variables",
            "function.var_refs",
            "value.flags_at",
            "value.possible",
            "workflow.describe",
            "loader.load_settings_types",
            "plugin.valid_commands",
            "plugin_repo.status",
            "type.parse_string",
            "type.define_user",
            "type_library.create",
            "type_archive.create",
            "project.create",
            "project.create_folder",
            "baseaddr.detect",
            "database.create_bndb",
            "database.write_global",
            "task.search_text",
            "task.analysis_update",
        ]

        names = [
            name for name in seed_priority if name in tools_by_name and name not in DEFERRED_TOOLS
        ]
        remaining = sorted(
            name for name in tools_by_name if name not in names and name not in DEFERRED_TOOLS
        )
        return names + remaining

    def _seed_state(self, tools_by_name: dict[str, dict[str, Any]]) -> None:
        if "session.open" in tools_by_name:
            self._invoke(
                "session.open",
                {
                    "path": str(self._analysis_database or self._state.sample_path),
                    "read_only": False,
                    "deterministic": True,
                    "update_analysis": self._update_analysis,
                    "options": self._load_options,
                },
            )

        if (
            "analysis.update_and_wait" in tools_by_name
            and self._state.active_session_id is not None
        ):
            self._invoke(
                "analysis.update_and_wait",
                {"session_id": self._state.active_session_id},
            )

        seed_calls = [
            "binary.summary",
            "binary.functions",
            "binary.strings",
            "binary.sections",
            "binary.segments",
            "binary.symbols",
            "binary.data_vars",
            "arch.info",
            "workflow.describe",
            "loader.load_settings_types",
            "plugin.valid_commands",
            "plugin_repo.status",
        ]
        for name in seed_calls:
            if name not in tools_by_name:
                continue
            args = self._build_arguments(name, tools_by_name[name], fuzz=False)
            self._invoke(name, args)

        if "type.parse_string" in tools_by_name and self._state.active_session_id is not None:
            self._invoke(
                "type.parse_string",
                {
                    "session_id": self._state.active_session_id,
                    "type_source": "int mcp_fuzz_type;",
                },
            )

        if "type.define_user" in tools_by_name and self._state.active_session_id is not None:
            self._invoke(
                "type.define_user",
                {
                    "session_id": self._state.active_session_id,
                    "type_source": "int mcp_fuzz_defined_type;",
                    "name": "mcp_fuzz_defined_type",
                },
            )
            self._state.type_names.add("mcp_fuzz_defined_type")

        if "type_library.create" in tools_by_name and self._state.active_session_id is not None:
            lib_path = self._next_path("seed_type_library", ".bntl")
            self._invoke(
                "type_library.create",
                {
                    "session_id": self._state.active_session_id,
                    "name": self._next_name("seed_type_library"),
                    "path": str(lib_path),
                    "add_to_view": True,
                },
            )
            self._state.type_library_paths.add(str(lib_path))

        if "type_archive.create" in tools_by_name and self._state.active_session_id is not None:
            archive_path = self._next_path("seed_type_archive", ".bnta")
            self._invoke(
                "type_archive.create",
                {
                    "session_id": self._state.active_session_id,
                    "path": str(archive_path),
                    "attach": True,
                },
            )
            self._state.type_archive_paths.add(str(archive_path))

        if "project.create" in tools_by_name:
            project_path = self._state.work_dir / self._next_name("seed_project")
            self._invoke(
                "project.create",
                {
                    "path": str(project_path),
                    "name": self._next_name("seed_project_name"),
                },
            )
            self._state.project_paths.add(str(project_path))

        if "task.search_text" in tools_by_name and self._state.active_session_id is not None:
            self._invoke(
                "task.search_text",
                {"session_id": self._state.active_session_id, "query": "main", "limit": 5},
            )

        if "task.analysis_update" in tools_by_name and self._state.active_session_id is not None:
            self._invoke(
                "task.analysis_update",
                {"session_id": self._state.active_session_id},
            )

        self._stabilize_known_tasks(max_rounds=6)

    def _deferred_cleanup(self) -> None:
        # Rebase a fresh original view: a .bndb view may legitimately refuse it.
        self._invoke(
            "session.open",
            {
                "path": str(self._state.sample_path),
                "read_only": False,
                "update_analysis": False,
            },
        )
        if self._state.active_session_id is not None:
            self._invoke(
                "loader.rebase",
                {
                    "session_id": self._state.active_session_id,
                    "address": self._pick_start_address(),
                    "force": False,
                },
            )

        for project_id in sorted(self._state.project_ids):
            self._invoke("project.close", {"project_id": project_id})

        for session_id in sorted(self._state.session_ids):
            self._invoke("session.close", {"session_id": session_id})

    def _stabilize_known_tasks(self, *, max_rounds: int) -> None:
        # Retain the argument for callers of the old exploratory harness. A fixed
        # number of polls is not a completion criterion for native analysis.
        _ = max_rounds
        deadline = time.monotonic() + 300
        while True:
            pending = []
            for task_id in sorted(self._state.task_ids):
                is_error, payload, _text = self._client.call_tool(
                    "task.status", {"task_id": task_id}
                )
                if is_error:
                    raise RuntimeError(f"cannot inspect task {task_id}: {payload}")
                status = payload.get("status")
                self._task_states[task_id] = status
                if status not in {"completed", "failed", "cancelled"}:
                    pending.append(task_id)
                elif status == "failed":
                    raise RuntimeError(f"background task failed: {payload}")
            if not pending:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"tasks failed to finish within 300 seconds: {pending}")
            time.sleep(0.05)

    def _trace(self, event: dict[str, Any]) -> None:
        if self._trace_path is not None:
            with self._trace_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(event, sort_keys=True) + "\n")

    def _invoke(self, tool_name: str, arguments: dict[str, Any]) -> None:
        self._trace(
            {"event": "request", "tool": tool_name, "arguments": arguments, "time": time.time()}
        )
        if self._verbose:
            print(f"[fuzzer] calling {tool_name}", flush=True)

        self._attempted_tools.add(tool_name)
        stats = self._stats.setdefault(tool_name, ToolStats())
        stats.attempts += 1

        try:
            is_error, payload, text = self._client.call_tool(tool_name, arguments)
        except Exception as exc:  # pragma: no cover - network/serialization edge cases
            self._trace({"event": "exception", "tool": tool_name, "error": str(exc)})
            stats.errors += 1
            stats.last_error = f"json-rpc failure: {type(exc).__name__}: {exc}"
            return

        self._trace(
            {
                "event": "response",
                "tool": tool_name,
                "is_error": is_error,
                "payload": payload,
                "time": time.time(),
            }
        )
        if is_error:
            stats.errors += 1
            error_text = payload.get("error") if isinstance(payload.get("error"), str) else text
            stats.last_error = error_text or "tool call returned isError=true"
            if (
                tool_name == "debug.parse_and_apply"
                and error_text == "no debug info parser is available for this view"
            ):
                self._unavailable_calls.append({"tool": tool_name, "reason": error_text})
            return

        stats.successes += 1
        self._successful_tools.add(tool_name)
        self._update_state(tool_name, arguments, payload)
        if tool_name in {"analysis.update", "task.analysis_update"}:
            self._stabilize_known_tasks(max_rounds=0)
        if tool_name == "analysis.abort":
            # Restore analysis before testing IL and mutation tools on this view.
            self._invoke("analysis.update_and_wait", {"session_id": arguments["session_id"]})
        if tool_name == "analysis.set_hold" and arguments.get("hold"):
            self._client.call_tool(
                "analysis.set_hold",
                {
                    "session_id": arguments["session_id"],
                    "hold": False,
                },
            )

    def _update_state(  # noqa: PLR0912, PLR0915
        self, tool_name: str, arguments: dict[str, Any], payload: dict[str, Any]
    ) -> None:
        if tool_name == "session.open_bytes" and self._analysis_database is not None:
            # This unanalysed probe must not pollute the active view's address pool.
            self._state.session_ids.add(payload["session_id"])
            self._invoke("session.close", {"session_id": payload["session_id"]})
            return
        self._collect_ids_and_addresses(payload)

        if tool_name == "session.close":
            sid = arguments["session_id"]
            self._state.session_ids.discard(sid)
            if self._state.active_session_id == sid:
                self._state.active_session_id = None
        if tool_name in {"session.open", "session.open_bytes", "session.open_existing"}:
            previous = self._state.active_session_id
            self._state.session_ids.add(payload["session_id"])
            self._state.active_session_id = payload["session_id"]
            if previous and previous != payload["session_id"]:
                self._invoke("session.close", {"session_id": previous})
            path_value = arguments.get("path", payload.get("filename", ""))
            if isinstance(path_value, str) and path_value.endswith(".bndb"):
                self._state.database_session_ids.add(payload["session_id"])
            # Addresses/variables belong to this view, not previously opened views.
            # In particular, a saved database may reopen at a different load base.
            for values in (
                self._state.addresses,
                self._state.symbol_addresses,
                self._state.function_starts,
                self._state.variable_names,
            ):
                values.clear()
            self._state.start_address = None
            self._state.end_address = None
            for name in ("binary.summary", "binary.functions", "binary.symbols"):
                self._invoke(name, {"session_id": payload["session_id"]})

        if tool_name == "binary.summary":
            start = self._as_int(payload.get("start"))
            end = self._as_int(payload.get("end"))
            if start is not None:
                self._state.start_address = start
                self._state.addresses.add(start)
            if end is not None:
                self._state.end_address = end
                self._state.addresses.add(end)

        if tool_name == "binary.functions":
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                start = self._as_int(item.get("start"))
                if start is not None:
                    self._state.function_starts.add(start)
                    self._state.addresses.add(start)

        if tool_name == "binary.symbols":
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                address = self._as_int(item.get("address"))
                if address is not None:
                    self._state.symbol_addresses.add(address)
                    self._state.addresses.add(address)

        if tool_name == "binary.data_vars":
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                address = self._as_int(item.get("address"))
                if address is not None:
                    self._state.addresses.add(address)

        if tool_name == "function.variables":
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if isinstance(name, str) and name:
                    self._state.variable_names.add(name)

        if tool_name == "arch.info":
            for register in payload.get("registers", []):
                if isinstance(register, str) and register:
                    self._state.register_names.add(register)

        if tool_name == "loader.load_settings_types":
            for type_name in payload.get("items", []):
                if isinstance(type_name, str) and type_name:
                    self._state.load_setting_types.add(type_name)

        if tool_name == "plugin.valid_commands":
            for item in payload.get("items", []):
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                if isinstance(name, str) and name:
                    self._state.plugin_command_names.add(name)

        if tool_name == "workflow.describe":
            workflow_name = payload.get("name")
            if isinstance(workflow_name, str) and workflow_name:
                self._state.workflow_names.add(workflow_name)
            for key in ("roots", "subactivities"):
                values = payload.get(key, [])
                if isinstance(values, list):
                    for value in values:
                        if isinstance(value, str) and value:
                            self._state.workflow_activities.add(value)

        if tool_name == "workflow.clone":
            workflow_name = payload.get("workflow")
            if isinstance(workflow_name, str) and workflow_name:
                self._state.workflow_names.add(workflow_name)

        if tool_name == "type.parse_string":
            parsed_name = payload.get("parsed_name")
            if isinstance(parsed_name, str) and parsed_name:
                self._state.type_names.add(parsed_name)

        if tool_name in {"type.define_user", "type.rename", "type.export_to_library"}:
            name = payload.get("name")
            if isinstance(name, str) and name:
                self._state.type_names.add(name)

        if tool_name == "project.create":
            project = payload.get("project")
            if isinstance(project, dict):
                project_path = project.get("path")
                if isinstance(project_path, str) and project_path:
                    self._state.project_paths.add(project_path)
                project_id = project.get("project_id")
                if isinstance(project_id, str) and project_id:
                    self._state.active_project_id = project_id

        if tool_name == "project.create_folder":
            folder = payload.get("folder")
            if isinstance(folder, dict):
                folder_id = folder.get("id")
                if isinstance(folder_id, str) and folder_id:
                    self._state.folder_ids.add(folder_id)

        if tool_name == "type_library.create":
            path = arguments.get("path")
            if isinstance(path, str) and path:
                self._state.type_library_paths.add(path)

        if tool_name == "type_archive.create":
            path = arguments.get("path")
            if isinstance(path, str) and path:
                self._state.type_archive_paths.add(path)

        if tool_name == "database.create_bndb":
            path = arguments.get("path")
            if isinstance(path, str) and path:
                self._state.bndb_paths.add(path)

        if tool_name == "plugin_repo.status":
            repositories = payload.get("repositories", [])
            if isinstance(repositories, list):
                for repository in repositories:
                    if not isinstance(repository, dict):
                        continue
                    path = repository.get("path")
                    if not isinstance(path, str) or not path:
                        continue
                    self._state.repository_paths.add(path)
                    self._state.active_repository_path = path
                    plugin_set = self._state.repository_plugins.setdefault(path, set())
                    plugins = repository.get("plugins", [])
                    if isinstance(plugins, list):
                        for plugin in plugins:
                            if not isinstance(plugin, dict):
                                continue
                            plugin_path = plugin.get("path")
                            plugin_name = plugin.get("name")
                            if isinstance(plugin_path, str) and plugin_path:
                                plugin_set.add(plugin_path)
                            elif isinstance(plugin_name, str) and plugin_name:
                                plugin_set.add(plugin_name)

    def _collect_ids_and_addresses(  # noqa: PLR0912
        self, value: Any, key: str | None = None
    ) -> None:
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if child_key == "task_id" and isinstance(child_value, str):
                    self._state.task_ids.add(child_value)
                if child_key == "project_id" and isinstance(child_value, str):
                    self._state.project_ids.add(child_value)
                if child_key == "type_library_id" and isinstance(child_value, str):
                    self._state.type_library_ids.add(child_value)
                if child_key == "type_archive_id" and isinstance(child_value, str):
                    self._state.type_archive_ids.add(child_value)
                if child_key == "transaction_id" and isinstance(child_value, str):
                    self._state.transaction_ids.add(child_value)
                if child_key in ADDRESS_KEYS:
                    parsed = self._as_int(child_value)
                    if parsed is not None:
                        self._state.addresses.add(parsed)
                self._collect_ids_and_addresses(child_value, child_key)
            return

        if isinstance(value, list):
            for item in value:
                self._collect_ids_and_addresses(item, key)
            return

        if key in ADDRESS_KEYS:
            parsed = self._as_int(value)
            if parsed is not None:
                self._state.addresses.add(parsed)

    @staticmethod
    def _as_int(value: Any) -> int | None:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError:
                return None
        return None

    def _build_arguments(  # noqa: PLR0912,PLR0915
        self, tool_name: str, tool_def: dict[str, Any], *, fuzz: bool
    ) -> dict[str, Any]:
        if tool_name == "plugin_repo.plugin_action":
            special = self._build_plugin_repo_action_arguments()
            if special is not None:
                return special

        schema = tool_def.get("inputSchema")
        if not isinstance(schema, dict):
            return {}

        properties = schema.get("properties")
        if not isinstance(properties, dict):
            properties = {}

        required = schema.get("required")
        if not isinstance(required, list):
            required = []

        arguments: dict[str, Any] = {}

        for key in required:
            if not isinstance(key, str):
                continue
            value = self._value_for_field(tool_name, key, properties.get(key, {}), required=True)
            if value is _MISSING:
                value = self._fallback_value(tool_name, key, properties.get(key, {}), required=True)
            arguments[key] = value

        include_probability = 0.45 if fuzz else 0.2
        for key, prop_schema in properties.items():
            if key in arguments:
                continue
            if self._rng.random() > include_probability:
                continue
            value = self._value_for_field(tool_name, key, prop_schema, required=False)
            if value is _MISSING:
                continue
            arguments[key] = value

        if tool_name in {"session.open", "session.open_bytes", "session.open_existing"}:
            arguments.setdefault("read_only", False)
            arguments.setdefault("deterministic", True)
            arguments.setdefault("update_analysis", self._update_analysis)
            if self._load_options:
                arguments["options"] = self._load_options
            if tool_name == "session.open_bytes" and self._analysis_database is not None:
                arguments["update_analysis"] = False

        if tool_name == "session.set_mode":
            arguments.setdefault("read_only", False)

        if tool_name == "plugin.execute":
            arguments.setdefault("perform", False)
        if tool_name == "external.location_add":
            arguments.setdefault("target_symbol", "mcp_fuzz_external")
        if tool_name == "annotation.define_data_var":
            arguments["type_name"] = "char"
        if tool_name in {"annotation.rename_data_var", "data.typed_at"}:
            error, variables, _ = self._client.call_tool(
                "binary.data_vars",
                {
                    "session_id": self._pick_session_id(),
                    "limit": 1,
                },
            )
            if not error and variables.get("items"):
                arguments["address"] = variables["items"][0]["address"]
        if tool_name in {"annotation.rename_symbol", "annotation.undefine_symbol"}:
            arguments["address"] = self._pick_address(prefer_symbol=True)
        if tool_name == "baseaddr.detect":
            # Bound this unrelated native heuristic during broad catalog coverage.
            # Lifecycle fuzzing separately runs the normal full analysis pipeline.
            base = self._pick_start_address()
            arguments.update(
                analysis="basic",
                low_boundary=base,
                high_boundary=base + 0x10000,
                alignment=4096,
                max_pointers=16,
            )
        if tool_name.startswith("workflow.machine."):
            # A cloned definition has no machine; control the session's bound workflow.
            arguments.pop("workflow_name", None)
        if tool_name in {"type_archive.push", "type_archive.pull", "type_archive.references"}:
            # A fresh archive is empty, and earlier rename/undefine calls can make
            # cached names stale. Establish an actual type and archive entry.
            archive_type = "mcp_fuzz_archive_type"
            session_id = self._pick_session_id()
            self._invoke(
                "type.define_user",
                {"session_id": session_id, "name": archive_type, "type_source": "int"},
            )
            if tool_name == "type_archive.references":
                arguments["name"] = archive_type
            else:
                arguments["names"] = [archive_type]
            if tool_name != "type_archive.push":
                self._invoke(
                    "type_archive.push",
                    {
                        "session_id": session_id,
                        "type_archive_id": arguments["type_archive_id"],
                        "names": [archive_type],
                    },
                )
        if tool_name == "transform.inspect":
            arguments.setdefault("session_id", self._pick_session_id())
        if tool_name.startswith("value.") and "function_start" in arguments:
            arguments["address"] = arguments["function_start"]
        addressed_il = tool_name == "binary.get_function_il_at"
        needs_il = addressed_il or (
            "function_start" in arguments
            and (
                tool_name.startswith(("il.", "function.ssa_"))
                or tool_name
                in {
                    "value.flags_at",
                    "value.possible",
                    "uidf.set_user_var_value",
                    "uidf.clear_user_var_value",
                }
            )
        )
        if needs_il:
            # Earlier mutation tools can invalidate IL and schedule native updates.
            # Establish the prerequisite before choosing a function to query/rewrite.
            self._invoke("analysis.update_and_wait", {"session_id": self._pick_session_id()})
            for start in sorted(self._state.function_starts):
                query = {
                    "session_id": self._pick_session_id(),
                    "address" if addressed_il else "function_start": start,
                    "level": "llil"
                    if tool_name == "value.flags_at"
                    else arguments.get("level", "mlil"),
                    "ssa": arguments.get("ssa", False) or tool_name.startswith("function.ssa_"),
                }
                if not addressed_il:
                    query["limit"] = 1
                error, il, _ = self._client.call_tool(
                    "binary.get_function_il_at" if addressed_il else "il.function", query
                )
                if not error and il.get("items"):
                    if "function_start" in arguments:
                        arguments["function_start"] = start
                    if "address" in arguments:
                        arguments["address"] = start if addressed_il else il["items"][0]["address"]
                    break
        if "variable_name" in arguments and "function_start" in arguments:
            for start in sorted(self._state.function_starts):
                if tool_name == "function.ssa_var_def_use":
                    error, il, _ = self._client.call_tool(
                        "il.function",
                        {
                            "session_id": self._pick_session_id(),
                            "function_start": start,
                            "level": arguments.get("level", "mlil"),
                            "ssa": True,
                            "limit": 1,
                        },
                    )
                    if error or not il.get("items"):
                        continue
                error, variables, _ = self._client.call_tool(
                    "function.variables",
                    {
                        "session_id": self._pick_session_id(),
                        "function_start": start,
                    },
                )
                candidates = variables.get("items", []) if not error else []
                if tool_name in {"uidf.set_user_var_value", "uidf.clear_user_var_value"}:
                    # Native API defines parameters (index 0) at the function entry.
                    # Other variables require an actual MLIL definition-site address.
                    candidates = [var for var in candidates if var.get("index") == 0]
                if candidates:
                    arguments["function_start"] = start
                    if "def_addr" in properties:
                        arguments["def_addr"] = start
                    arguments["variable_name"] = candidates[0]["name"]
                    break
        if tool_name == "uidf.clear_user_var_value":
            # Clear an actual value we set at the same definition site.
            self._invoke(
                "uidf.set_user_var_value", {**arguments, "value": "0x2a", "state": "ConstantValue"}
            )

        if tool_name == "disasm.function":
            has_function_start = "function_start" in arguments
            has_address = "address" in arguments
            if not has_function_start and not has_address:
                if fuzz and self._rng.choice([True, False]):
                    arguments["address"] = self._pick_function_start()
                else:
                    arguments["function_start"] = self._pick_function_start()
            elif has_function_start and has_address:
                if fuzz:
                    if self._rng.choice([True, False]):
                        arguments.pop("address", None)
                    else:
                        arguments.pop("function_start", None)
                else:
                    arguments.pop("address", None)

            if "function_start" in arguments:
                arguments.setdefault("offset", 0)
                arguments.setdefault("limit", 20)

        return arguments

    def _build_plugin_repo_action_arguments(self) -> dict[str, Any] | None:
        repository_path = self._pick_repository_path()
        plugin_path = self._pick_repository_plugin(repository_path)
        if not repository_path or not plugin_path:
            return {
                "repository_path": "missing-repository",
                "plugin_path": "missing-plugin",
                "action": "enable",
            }
        return {
            "repository_path": repository_path,
            "plugin_path": plugin_path,
            "action": self._rng.choice(["enable", "disable", "install", "uninstall"]),
        }

    def _value_for_field(  # noqa: PLR0911, PLR0912, PLR0915
        self,
        tool_name: str,
        key: str,
        schema: Any,
        *,
        required: bool,
    ) -> Any:
        if key == "session_id":
            return self._pick_session_id()
        if key == "source_session_id":
            return self._pick_session_id(default="missing-source-session")
        if key == "task_id":
            return self._pick_one(self._state.task_ids, "missing-task-id")
        if key == "project_id":
            return self._pick_project_id()
        if key == "folder_id":
            return self._pick_one(self._state.folder_ids, "missing-folder-id")
        if key == "type_library_id":
            return self._pick_one(self._state.type_library_ids, "missing-type-library-id")
        if key == "type_archive_id":
            return self._pick_one(self._state.type_archive_ids, "missing-type-archive-id")
        if key == "transaction_id":
            return self._pick_one(self._state.transaction_ids, "missing-transaction-id")

        if key == "path":
            return self._path_for_tool(tool_name)

        if key == "function_start":
            return self._pick_function_start()

        if key == "address" and tool_name in {
            "binary.get_function_at",
            "binary.get_function_disassembly_at",
            "binary.get_function_il_at",
            "disasm.function",
        }:
            return self._pick_function_start()

        if key in {"address", "source_address", "target_address", "def_addr", "here"}:
            return self._pick_address(prefer_symbol=(key == "source_address"))

        if key == "start":
            return self._pick_start_address()

        if key == "end":
            return self._pick_end_address()

        if key == "base_address":
            return self._pick_end_address()

        if key == "register" and "boolean" not in self._schema_types(schema):
            return self._pick_one(self._state.register_names, "x0")

        if key == "variable_name":
            return self._pick_one(self._state.variable_names, "var_0")

        if key == "level":
            return "mlil"

        if key == "state":
            return "ConstantValue"

        if key == "value_type":
            return "string"

        if key == "query":
            return self._rng.choice(["main", "printf", "Usage", "--help"])

        if key == "data_hex":
            return self._rng.choice(["90", "9090", "48656c6c6f"])

        if key == "code":
            return "1 + 1"

        if key == "target":
            return "bn.core_version"

        if key == "asm":
            return "nop"

        if key == "declarations":
            return "typedef struct { int x; } mcp_fuzz_s; int mcp_fuzz_fn(int v);"

        if key == "type_source":
            return "int mcp_fuzz_type;"

        if key == "name":
            return self._name_for_tool(tool_name)

        if key == "old_name":
            return self._pick_one(self._state.type_names, "mcp_fuzz_type")

        if key == "new_name":
            return self._next_name("renamed")

        if key == "comment":
            return self._next_name("fuzz_comment")

        if key == "tag_type":
            return "fuzz-tag"

        if key == "symbol_type":
            return "FunctionSymbol"

        if key == "type_name":
            return self._pick_one(self._state.load_setting_types, "char")

        if key == "key":
            return "mcp.fuzz.key"

        if key == "value":
            return self._value_for_value_field(tool_name, schema)

        if key == "width":
            return self._pick_integer(schema, default=4)

        if key == "length":
            return self._length_for_tool(tool_name, schema)

        if key == "size":
            return self._pick_integer(schema, default=8)

        if key == "stack_offset":
            return 0

        if key == "offset":
            return self._pick_integer(schema, default=0)

        if key == "limit":
            return self._pick_integer(schema, default=20)

        if key == "constant":
            return 1

        if key == "action" and tool_name == "workflow.machine.control":
            return "enable"

        if key == "activities":
            activity = self._pick_activity()
            return [activity]

        if key == "activity":
            return self._pick_activity()

        if key == "workflow_name":
            return self._pick_one(self._state.workflow_names, "core.function.metaAnalysis")

        if key == "names":
            return [self._pick_one(self._state.type_names, "mcp_fuzz_type")]

        if key == "options":
            if tool_name == "type.parse_declarations":
                return []
            return {}

        if key == "include_dirs":
            return []

        if key == "kwargs":
            return {}

        if key == "args":
            return []

        if key == "data_base64":
            if tool_name == "session.open_bytes":
                return self._state.sample_data_b64
            return base64.b64encode(b"fuzz-data").decode("ascii")

        if key in {"analysis", "mode"}:
            return "basic" if key == "analysis" else "full"

        if key in {
            "read_only",
            "deterministic",
            "update_analysis",
            "hold",
            "after",
            "regex",
            "perform",
            "attach",
            "add_to_view",
            "auto",
            "advanced",
            "incremental",
            "immediate",
            "sequential",
            "import_dependencies",
            "register",
            "generate_ssa_form",
            "finalize",
            "force",
            "enable",
            "process",
        }:
            if key == "read_only":
                return False
            if key == "deterministic":
                return True
            if key == "update_analysis":
                return self._update_analysis
            if key == "perform":
                return False
            return self._rng.choice([True, False]) if not required else False

        return _MISSING

    def _value_for_value_field(self, tool_name: str, schema: Any) -> Any:
        if tool_name in {"uidf.parse_possible_value", "uidf.set_user_var_value"}:
            return "0x2a"
        types = self._schema_types(schema)
        if "integer" in types:
            return 42
        if "string" in types:
            return "fuzz-value"
        if tool_name in {"project.metadata_store", "metadata.store", "function.metadata_store"}:
            return {"fuzz": True, "n": 1}
        return "fuzz-value"

    def _fallback_value(  # noqa: PLR0911
        self, tool_name: str, key: str, schema: Any, *, required: bool
    ) -> Any:
        types = self._schema_types(schema)

        if "array" in types:
            return []
        if "object" in types:
            return {}
        if "boolean" in types:
            return False
        if "integer" in types:
            return self._pick_integer(schema, default=1)
        if "string" in types:
            return f"fuzz-{tool_name}-{key}"

        if required:
            return f"fuzz-{key}"
        return {}

    def _schema_types(self, schema: Any) -> set[str]:
        if not isinstance(schema, dict):
            return set()

        types: set[str] = set()
        schema_type = schema.get("type")
        if isinstance(schema_type, str):
            types.add(schema_type)
        elif isinstance(schema_type, list):
            for item in schema_type:
                if isinstance(item, str):
                    types.add(item)

        one_of = schema.get("oneOf")
        if isinstance(one_of, list):
            for item in one_of:
                types.update(self._schema_types(item))

        return types

    def _schema_minimum(self, schema: Any) -> int | None:
        if not isinstance(schema, dict):
            return None

        minimum = schema.get("minimum")
        if isinstance(minimum, int):
            return minimum

        one_of = schema.get("oneOf")
        if isinstance(one_of, list):
            minima = [self._schema_minimum(item) for item in one_of]
            minima = [value for value in minima if value is not None]
            if minima:
                return max(minima)

        return None

    def _pick_integer(self, schema: Any, *, default: int) -> int:
        minimum = self._schema_minimum(schema)
        if minimum is None:
            return default
        return max(default, minimum)

    def _length_for_tool(self, tool_name: str, schema: Any) -> int:
        if tool_name == "memory.read":
            return 32
        if tool_name == "disasm.range":
            return 64
        if tool_name == "memory.remove":
            return 1
        if tool_name.startswith("xref."):
            return 1
        return self._pick_integer(schema, default=16)

    def _pick_one(self, values: set[str] | set[int], fallback: str | int) -> str | int:
        if not values:
            return fallback
        as_list = list(values)
        return self._rng.choice(as_list)

    def _pick_session_id(self, default: str = "missing-session-id") -> str:
        if self._state.active_session_id:
            return self._state.active_session_id
        value = self._pick_one(self._state.session_ids, default)
        assert isinstance(value, str)
        return value

    def _pick_project_id(self) -> str:
        if self._state.active_project_id:
            return self._state.active_project_id
        value = self._pick_one(self._state.project_ids, "missing-project-id")
        assert isinstance(value, str)
        return value

    def _pick_repository_path(self) -> str | None:
        if self._state.active_repository_path:
            return self._state.active_repository_path
        if self._state.repository_paths:
            value = self._pick_one(self._state.repository_paths, "")
            assert isinstance(value, str)
            return value
        return None

    def _pick_repository_plugin(self, repository_path: str | None) -> str | None:
        if not repository_path:
            return None
        plugins = self._state.repository_plugins.get(repository_path)
        if not plugins:
            return None
        value = self._pick_one(plugins, "")
        assert isinstance(value, str)
        return value

    def _pick_address(self, *, prefer_symbol: bool = False) -> int:
        if prefer_symbol and self._state.symbol_addresses:
            value = self._pick_one(self._state.symbol_addresses, 0x1000)
            assert isinstance(value, int)
            return value

        if self._state.addresses:
            value = self._pick_one(self._state.addresses, 0x1000)
            assert isinstance(value, int)
            return value

        if self._state.start_address is not None:
            return self._state.start_address
        return 0x1000

    def _pick_start_address(self) -> int:
        if self._state.start_address is not None:
            return self._state.start_address
        return self._pick_address()

    def _pick_end_address(self) -> int:
        if self._state.end_address is not None:
            return self._state.end_address
        start = self._pick_start_address()
        return start + 0x100

    def _pick_function_start(self) -> int:
        if self._state.function_starts:
            value = self._pick_one(self._state.function_starts, 0x1000)
            assert isinstance(value, int)
            return value
        return self._pick_address()

    def _pick_activity(self) -> str:
        value = self._pick_one(self._state.workflow_activities, "core.function.metaAnalysis")
        assert isinstance(value, str)
        return value

    def _name_for_tool(self, tool_name: str) -> str:  # noqa: PLR0911
        if tool_name == "plugin.execute":
            value = self._pick_one(self._state.plugin_command_names, "")
            if isinstance(value, str) and value:
                return value
            return self._next_name("plugin")

        if tool_name == "external.library_remove":
            value = self._pick_one(self._state.external_library_names, "mcp_ext_lib")
            assert isinstance(value, str)
            return value

        if tool_name == "external.library_add":
            name = self._next_name("mcp_ext_lib")
            self._state.external_library_names.add(name)
            return name

        if tool_name == "type.undefine_user":
            value = self._pick_one(self._state.type_names, "mcp_fuzz_type")
            assert isinstance(value, str)
            return value

        if tool_name in {"type.import_library_type", "type.import_library_object"}:
            value = self._pick_one(self._state.type_names, "mcp_fuzz_type")
            assert isinstance(value, str)
            return value

        if tool_name == "workflow.clone":
            name = self._next_name("workflow")
            self._state.workflow_names.add(name)
            return name

        if tool_name == "project.create":
            return self._next_name("project")

        if tool_name == "project.create_folder":
            return self._next_name("folder")

        if tool_name == "project.create_file":
            return f"{self._next_name('file')}.bin"

        return self._next_name("name")

    def _path_for_tool(self, tool_name: str) -> str:  # noqa: PLR0911, PLR0912
        if tool_name == "session.open":
            return str(self._analysis_database or self._state.sample_path)

        if tool_name == "session.open_bytes":
            return str(self._state.sample_path)

        if tool_name == "database.create_bndb":
            path = self._next_path("fuzz_db", ".bndb")
            self._state.bndb_paths.add(str(path))
            return str(path)

        if tool_name == "binary.save":
            return str(self._next_path("fuzz_binary", ".bin"))

        if tool_name == "project.create":
            path = self._state.work_dir / self._next_name("project_dir")
            self._state.project_paths.add(str(path))
            return str(path)

        if tool_name == "project.open":
            if self._state.project_paths:
                value = self._pick_one(self._state.project_paths, str(self._state.work_dir))
                assert isinstance(value, str)
                return value
            return str(self._state.work_dir)

        if tool_name == "type_library.create":
            path = self._next_path("fuzz_type_library", ".bntl")
            self._state.type_library_paths.add(str(path))
            return str(path)

        if tool_name == "type_library.load":
            if self._state.type_library_paths:
                value = self._pick_one(self._state.type_library_paths, "")
                assert isinstance(value, str)
                return value
            path = self._next_path("fuzz_type_library", ".bntl")
            return str(path)

        if tool_name == "type_archive.create":
            path = self._next_path("fuzz_type_archive", ".bnta")
            self._state.type_archive_paths.add(str(path))
            return str(path)

        if tool_name == "type_archive.open":
            if self._state.type_archive_paths:
                value = self._pick_one(self._state.type_archive_paths, "")
                assert isinstance(value, str)
                return value
            path = self._next_path("fuzz_type_archive", ".bnta")
            return str(path)

        if tool_name == "transform.inspect":
            return str(self._state.sample_path)

        if tool_name == "debug.parse_and_apply":
            return str(self._state.sample_path)

        return str(self._state.sample_path)

    def _next_name(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}_{self._counter:04d}"

    def _next_path(self, stem: str, suffix: str) -> Path:
        filename = f"{self._next_name(stem)}{suffix}"
        return self._state.work_dir / filename

    def _summary(self, tool_defs: list[dict[str, Any]]) -> dict[str, Any]:
        total_calls = sum(stats.attempts for stats in self._stats.values())
        successful_calls = sum(stats.successes for stats in self._stats.values())
        error_calls = sum(stats.errors for stats in self._stats.values())

        all_tool_names = sorted(
            tool.get("name") for tool in tool_defs if isinstance(tool.get("name"), str)
        )
        unattempted = [name for name in all_tool_names if name not in self._attempted_tools]

        failed_tools = []
        for name in sorted(self._stats):
            stats = self._stats[name]
            if stats.errors == 0:
                continue
            failed_tools.append(
                {
                    "name": name,
                    "errors": stats.errors,
                    "successes": stats.successes,
                    "last_error": stats.last_error,
                }
            )

        summary = {
            "source_hashes": self._source_hashes,
            "load_options": self._load_options,
            "used_analysis_database": self._analysis_database is not None,
            "input_sha256": hashlib.sha256(
                base64.b64decode(self._state.sample_data_b64)
            ).hexdigest(),
            "seed": self._seed,
            "iterations": self._iterations,
            "total_tools": len(all_tool_names),
            "attempted_tools": len(self._attempted_tools),
            "successful_tools": len(self._successful_tools),
            "tool_success_rate": (
                round(100.0 * len(self._successful_tools) / len(all_tool_names), 2)
                if all_tool_names
                else 0.0
            ),
            "total_calls": total_calls,
            "successful_calls": successful_calls,
            "error_calls": error_calls,
            "unexpected_error_calls": error_calls - len(self._unavailable_calls),
            "unavailable_calls": self._unavailable_calls,
            "call_success_rate": round(100.0 * successful_calls / total_calls, 2)
            if total_calls
            else 0.0,
            "unattempted_tools": unattempted,
            "excluded_external_actions": sorted(EXTERNAL_ACTION_TOOLS),
            "failed_tools": failed_tools,
        }

        print("[fuzzer] completed")
        print(
            "[fuzzer] tools: "
            f"{summary['successful_tools']}/{summary['total_tools']} successful "
            f"({summary['tool_success_rate']}%)"
        )
        print(
            "[fuzzer] calls: "
            f"{summary['successful_calls']}/{summary['total_calls']} successful "
            f"({summary['call_success_rate']}%)"
        )
        if failed_tools:
            print("[fuzzer] top failures:")
            for item in failed_tools[:10]:
                print(
                    f"  - {item['name']}: errors={item['errors']} last_error={item['last_error']}"
                )

        return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="MCP feature fuzzer for binary_ninja_headless_mcp")
    parser.add_argument(
        "--binary",
        default="samples/ls",
        help="Path to target binary (default: samples/ls)",
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=120,
        help="Extra randomized tool-call iterations after the full tool sweep",
    )
    parser.add_argument("--seed", type=int, default=1337, help="RNG seed")
    parser.add_argument(
        "--load-options",
        type=json.loads,
        default={},
        help="JSON object of explicit Binary Ninja load/analysis options",
    )
    parser.add_argument(
        "--fake-backend",
        action="store_true",
        help="Use fake backend instead of real binaryninja module",
    )
    parser.add_argument(
        "--update-analysis",
        action="store_true",
        help="Pass update_analysis=true on session.open",
    )
    parser.add_argument(
        "--analysis-database",
        type=Path,
        help="Reuse a completed analysis in a private copy; probe raw bytes without analysis",
    )
    parser.add_argument("--verbose", action="store_true", help="Print each tool call as it runs")
    parser.add_argument("--trace-jsonl", help="Incremental request/response trace path")
    parser.add_argument(
        "--allow-tool-errors",
        action="store_true",
        help="Exploratory sweep only: allow reported tool errors in the exit code",
    )
    parser.add_argument(
        "--report-json",
        help="Optional path to write machine-readable summary JSON",
    )
    parser.add_argument(
        "--min-success-tools",
        type=int,
        default=0,
        help="Exit non-zero when successful tool count is below this threshold",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not isinstance(args.load_options, dict):
        parser.error("--load-options must be a JSON object")

    binary_path = Path(args.binary).resolve()
    if not binary_path.exists():
        parser.error(f"binary path does not exist: {binary_path}")

    bn_module = load_binja_module(args.fake_backend)
    backend = BinjaBackend(bn_module)
    server = SimpleMcpServer(backend)
    fuzzer = McpFeatureFuzzer(
        server,
        binary_path,
        iterations=args.iterations,
        seed=args.seed,
        update_analysis=args.update_analysis,
        verbose=args.verbose,
        trace_path=Path(args.trace_jsonl) if args.trace_jsonl else None,
        load_options=args.load_options,
        analysis_database=args.analysis_database,
    )

    try:
        summary = fuzzer.run()
    finally:
        # Retain the work directory if shutdown cannot drain native users of it.
        backend.shutdown()
        fuzzer.close()

    if args.report_json:
        report_path = Path(args.report_json)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")

    min_success_tools = max(args.min_success_tools, 0)
    if summary["successful_tools"] < min_success_tools:
        print(
            "[fuzzer] threshold not met: "
            f"successful_tools={summary['successful_tools']} "
            f"< min_success_tools={min_success_tools}"
        )
        return 1

    if summary["unexpected_error_calls"] and not args.allow_tool_errors:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
