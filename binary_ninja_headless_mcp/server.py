"""Minimal MCP (JSON-RPC) server with Binja-backed tools."""

from __future__ import annotations

import json
import socketserver
import sys
from dataclasses import dataclass
from typing import Any, TextIO

from .backend import BinjaBackend, BinjaBackendError


@dataclass
class JsonRpcError(Exception):
    """Represents a JSON-RPC error payload."""

    code: int
    message: str
    data: Any = None


class _ThreadingTcpServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class SimpleMcpServer:
    """Simple MCP-compatible server exposing Binja tools."""

    def __init__(self, backend: BinjaBackend):
        self._backend = backend
        self._tool_handlers = {
            "health.ping": self._tool_ping,
            "binja.info": self._tool_binja_info,
            "binja.call": self._tool_binja_call,
            "binja.eval": self._tool_binja_eval,
            "session.open": self._tool_session_open,
            "session.open_bytes": self._tool_session_open_bytes,
            "session.open_existing": self._tool_session_open_existing,
            "session.close": self._tool_session_close,
            "session.list": self._tool_session_list,
            "session.mode": self._tool_session_mode,
            "session.set_mode": self._tool_session_set_mode,
            "analysis.status": self._tool_analysis_status,
            "analysis.progress": self._tool_analysis_progress,
            "analysis.update": self._tool_analysis_update,
            "analysis.update_and_wait": self._tool_analysis_update_and_wait,
            "analysis.abort": self._tool_analysis_abort,
            "analysis.set_hold": self._tool_analysis_set_hold,
            "binary.summary": self._tool_binary_summary,
            "binary.save": self._tool_binary_save,
            "binary.functions": self._tool_binary_functions,
            "binary.strings": self._tool_binary_strings,
            "binary.search_text": self._tool_binary_search_text,
            "binary.sections": self._tool_binary_sections,
            "binary.segments": self._tool_binary_segments,
            "binary.symbols": self._tool_binary_symbols,
            "binary.data_vars": self._tool_binary_data_vars,
            "binary.get_function_at": self._tool_binary_get_function_at,
            "binary.get_function_disassembly_at": self._tool_binary_get_function_disassembly_at,
            "binary.get_function_il_at": self._tool_binary_get_function_il_at,
            "binary.functions_at": self._tool_binary_functions_at,
            "binary.basic_blocks_at": self._tool_binary_basic_blocks_at,
            "function.basic_blocks": self._tool_function_basic_blocks,
            "disasm.linear": self._tool_disasm_linear,
            "search.data": self._tool_search_data,
            "search.next_text": self._tool_search_next_text,
            "search.all_text": self._tool_search_all_text,
            "search.next_data": self._tool_search_next_data,
            "search.all_data": self._tool_search_all_data,
            "search.next_constant": self._tool_search_next_constant,
            "search.all_constant": self._tool_search_all_constant,
            "xref.code_refs_to": self._tool_xref_code_refs_to,
            "xref.code_refs_from": self._tool_xref_code_refs_from,
            "xref.data_refs_to": self._tool_xref_data_refs_to,
            "xref.data_refs_from": self._tool_xref_data_refs_from,
            "function.callers": self._tool_function_callers,
            "function.callees": self._tool_function_callees,
            "function.variables": self._tool_function_variables,
            "function.var_refs": self._tool_function_var_refs,
            "function.var_refs_from": self._tool_function_var_refs_from,
            "function.ssa_var_def_use": self._tool_function_ssa_var_def_use,
            "function.ssa_memory_def_use": self._tool_function_ssa_memory_def_use,
            "value.reg": self._tool_value_reg,
            "value.stack": self._tool_value_stack,
            "value.possible": self._tool_value_possible,
            "value.flags_at": self._tool_value_flags_at,
            "memory.read": self._tool_memory_read,
            "memory.write": self._tool_memory_write,
            "memory.insert": self._tool_memory_insert,
            "memory.remove": self._tool_memory_remove,
            "memory.reader_read": self._tool_memory_reader_read,
            "memory.writer_write": self._tool_memory_writer_write,
            "data.typed_at": self._tool_data_typed_at,
            "annotation.rename_function": self._tool_annotation_rename_function,
            "annotation.rename_symbol": self._tool_annotation_rename_symbol,
            "annotation.undefine_symbol": self._tool_annotation_undefine_symbol,
            "annotation.define_symbol": self._tool_annotation_define_symbol,
            "annotation.rename_data_var": self._tool_annotation_rename_data_var,
            "annotation.define_data_var": self._tool_annotation_define_data_var,
            "annotation.undefine_data_var": self._tool_annotation_undefine_data_var,
            "annotation.set_comment": self._tool_annotation_set_comment,
            "annotation.get_comment": self._tool_annotation_get_comment,
            "annotation.add_tag": self._tool_annotation_add_tag,
            "annotation.get_tags": self._tool_annotation_get_tags,
            "metadata.store": self._tool_metadata_store,
            "metadata.query": self._tool_metadata_query,
            "metadata.remove": self._tool_metadata_remove,
            "function.metadata_store": self._tool_function_metadata_store,
            "function.metadata_query": self._tool_function_metadata_query,
            "function.metadata_remove": self._tool_function_metadata_remove,
            "patch.assemble": self._tool_patch_assemble,
            "patch.status": self._tool_patch_status,
            "patch.convert_to_nop": self._tool_patch_convert_to_nop,
            "patch.always_branch": self._tool_patch_always_branch,
            "patch.never_branch": self._tool_patch_never_branch,
            "patch.invert_branch": self._tool_patch_invert_branch,
            "patch.skip_and_return_value": self._tool_patch_skip_and_return_value,
            "undo.begin": self._tool_undo_begin,
            "undo.commit": self._tool_undo_commit,
            "undo.revert": self._tool_undo_revert,
            "undo.undo": self._tool_undo_undo,
            "undo.redo": self._tool_undo_redo,
            "disasm.function": self._tool_disasm_function,
            "disasm.range": self._tool_disasm_range,
            "il.function": self._tool_il_function,
            "il.instruction_by_addr": self._tool_il_instruction_by_addr,
            "il.address_to_index": self._tool_il_address_to_index,
            "il.index_to_address": self._tool_il_index_to_address,
            "task.analysis_update": self._tool_task_analysis_update,
            "task.search_text": self._tool_task_search_text,
            "task.status": self._tool_task_status,
            "task.result": self._tool_task_result,
            "task.cancel": self._tool_task_cancel,
            "database.create_bndb": self._tool_database_create_bndb,
            "database.save_auto_snapshot": self._tool_database_save_auto_snapshot,
            "type.parse_string": self._tool_type_parse_string,
            "type.parse_declarations": self._tool_type_parse_declarations,
            "type.define_user": self._tool_type_define_user,
            "type.rename": self._tool_type_rename,
            "type.undefine_user": self._tool_type_undefine_user,
            "type.import_library_type": self._tool_type_import_library_type,
            "type.import_library_object": self._tool_type_import_library_object,
            "type.export_to_library": self._tool_type_export_to_library,
            "type_library.create": self._tool_type_library_create,
            "type_library.load": self._tool_type_library_load,
            "type_library.list": self._tool_type_library_list,
            "type_library.get": self._tool_type_library_get,
            "type_archive.create": self._tool_type_archive_create,
            "type_archive.open": self._tool_type_archive_open,
            "type_archive.list": self._tool_type_archive_list,
            "type_archive.get": self._tool_type_archive_get,
            "type_archive.pull": self._tool_type_archive_pull,
            "type_archive.push": self._tool_type_archive_push,
            "type_archive.references": self._tool_type_archive_references,
            "debug.parsers": self._tool_debug_parsers,
            "debug.parse_and_apply": self._tool_debug_parse_and_apply,
            "workflow.list": self._tool_workflow_list,
            "workflow.describe": self._tool_workflow_describe,
            "workflow.clone": self._tool_workflow_clone,
            "workflow.insert": self._tool_workflow_insert,
            "workflow.insert_after": self._tool_workflow_insert_after,
            "workflow.remove": self._tool_workflow_remove,
            "workflow.graph": self._tool_workflow_graph,
            "workflow.machine.status": self._tool_workflow_machine_status,
            "workflow.machine.control": self._tool_workflow_machine_control,
            "il.rewrite.capabilities": self._tool_il_rewrite_capabilities,
            "il.rewrite.noop_replace": self._tool_il_rewrite_noop_replace,
            "il.rewrite.translate_identity": self._tool_il_rewrite_translate_identity,
            "uidf.parse_possible_value": self._tool_uidf_parse_possible_value,
            "uidf.set_user_var_value": self._tool_uidf_set_user_var_value,
            "uidf.clear_user_var_value": self._tool_uidf_clear_user_var_value,
            "uidf.list_user_var_values": self._tool_uidf_list_user_var_values,
            "loader.rebase": self._tool_loader_rebase,
            "loader.load_settings_types": self._tool_loader_load_settings_types,
            "loader.load_settings_get": self._tool_loader_load_settings_get,
            "loader.load_settings_set": self._tool_loader_load_settings_set,
            "segment.add_user": self._tool_segment_add_user,
            "segment.remove_user": self._tool_segment_remove_user,
            "section.add_user": self._tool_section_add_user,
            "section.remove_user": self._tool_section_remove_user,
            "external.library_add": self._tool_external_library_add,
            "external.library_list": self._tool_external_library_list,
            "external.library_remove": self._tool_external_library_remove,
            "external.location_add": self._tool_external_location_add,
            "external.location_get": self._tool_external_location_get,
            "external.location_remove": self._tool_external_location_remove,
            "arch.info": self._tool_arch_info,
            "arch.disasm_bytes": self._tool_arch_disasm_bytes,
            "arch.assemble": self._tool_arch_assemble,
            "transform.inspect": self._tool_transform_inspect,
            "project.create": self._tool_project_create,
            "project.open": self._tool_project_open,
            "project.close": self._tool_project_close,
            "project.list": self._tool_project_list,
            "project.create_folder": self._tool_project_create_folder,
            "project.create_file": self._tool_project_create_file,
            "project.metadata_store": self._tool_project_metadata_store,
            "project.metadata_query": self._tool_project_metadata_query,
            "project.metadata_remove": self._tool_project_metadata_remove,
            "database.info": self._tool_database_info,
            "database.snapshots": self._tool_database_snapshots,
            "database.read_global": self._tool_database_read_global,
            "database.write_global": self._tool_database_write_global,
            "plugin.valid_commands": self._tool_plugin_valid_commands,
            "plugin.execute": self._tool_plugin_execute,
            "plugin_repo.status": self._tool_plugin_repo_status,
            "plugin_repo.check_updates": self._tool_plugin_repo_check_updates,
            "plugin_repo.plugin_action": self._tool_plugin_repo_plugin_action,
            "baseaddr.detect": self._tool_baseaddr_detect,
            "baseaddr.reasons": self._tool_baseaddr_reasons,
            "baseaddr.abort": self._tool_baseaddr_abort,
        }

    def serve_stdio(
        self,
        input_stream: TextIO | None = None,
        output_stream: TextIO | None = None,
    ) -> None:
        """Run line-delimited JSON-RPC over stdio."""

        in_stream = input_stream or sys.stdin
        out_stream = output_stream or sys.stdout

        for raw_line in in_stream:
            line = raw_line.strip()
            if not line:
                continue

            response = self.handle_json_line(line)
            if response is None:
                continue

            out_stream.write(response)
            out_stream.write("\n")
            out_stream.flush()

    def serve_tcp(self, host: str, port: int) -> None:
        """Run line-delimited JSON-RPC over TCP."""

        parent = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self) -> None:
                while True:
                    raw_line = self.rfile.readline()
                    if not raw_line:
                        return
                    line = raw_line.decode("utf-8").strip()
                    if not line:
                        continue

                    response = parent.handle_json_line(line)
                    if response is None:
                        continue

                    self.wfile.write(response.encode("utf-8"))
                    self.wfile.write(b"\n")
                    self.wfile.flush()

        with _ThreadingTcpServer((host, port), Handler) as server:
            server.serve_forever()

    def handle_json_line(self, line: str) -> str | None:
        """Handle one JSON-RPC line and return a serialized response line."""

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            error = JsonRpcError(code=-32700, message="Parse error", data=str(exc))
            return json.dumps(self._error_response(None, error), sort_keys=True)

        response = self.handle_request(request)
        if response is None:
            return None
        try:
            return json.dumps(response, sort_keys=True)
        except TypeError as exc:
            request_id = request.get("id") if isinstance(request, dict) else None
            fallback = self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"failed to serialize response: {exc}",
                ),
            )
            return json.dumps(fallback, sort_keys=True)

    def handle_request(self, request: dict[str, Any]) -> dict[str, Any] | None:
        """Handle one JSON-RPC request object."""

        if not isinstance(request, dict):
            return self._error_response(None, JsonRpcError(-32600, "Invalid Request"))

        request_id = request.get("id")
        method = request.get("method")
        params = request.get("params", {})

        try:
            if not isinstance(method, str):
                raise JsonRpcError(-32600, "Invalid Request")
            if not isinstance(params, dict):
                raise JsonRpcError(-32602, "Invalid params")

            if method == "notifications/initialized":
                return None

            result = self._dispatch(method, params)
            return self._success_response(request_id, result)
        except JsonRpcError as exc:
            return self._error_response(request_id, exc)
        except Exception as exc:
            return self._error_response(
                request_id,
                JsonRpcError(
                    code=-32603,
                    message="Internal error",
                    data=f"{type(exc).__name__}: {exc}",
                ),
            )

    def _dispatch(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        if method == "initialize":
            return {
                "protocolVersion": "2024-11-05",
                "serverInfo": {
                    "name": "binary_ninja_headless_mcp",
                    "version": "0.2.0",
                },
                "capabilities": {
                    "tools": {},
                },
            }

        if method == "ping":
            return {"status": "ok"}

        if method == "tools/list":
            return self._dispatch_tools_list(params)

        if method == "tools/call":
            return self._dispatch_tool_call(params)

        if method == "shutdown":
            self._backend.shutdown()
            return {"ok": True}

        raise JsonRpcError(code=-32601, message=f"Method not found: {method}")

    def _dispatch_tools_list(self, params: dict[str, Any]) -> dict[str, Any]:
        paginate = "offset" in params or "limit" in params
        offset = params.get("offset", 0)
        limit = params.get("limit", 50 if paginate else None)
        prefix = params.get("prefix")
        query = params.get("query")

        if not isinstance(offset, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be an integer",
            )
        if limit is not None and not isinstance(limit, int):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be an integer",
            )
        if offset < 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'offset' must be >= 0",
            )
        if limit is not None and limit <= 0:
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'limit' must be > 0",
            )
        if prefix is not None and not isinstance(prefix, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'prefix' must be a string",
            )
        if query is not None and not isinstance(query, str):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/list 'query' must be a string",
            )

        tools = self._tool_definitions()
        if prefix is not None:
            tools = [tool for tool in tools if tool["name"].startswith(prefix)]
        if query is not None:
            lowered = query.lower()
            tools = [
                tool
                for tool in tools
                if lowered in tool["name"].lower() or lowered in tool["description"].lower()
            ]

        total = len(tools)
        if limit is None:
            items = tools[offset:]
            effective_limit = len(items)
        else:
            items = tools[offset : offset + limit]
            effective_limit = limit

        has_more = offset + len(items) < total
        response = {
            "tools": items,
            "offset": offset,
            "limit": effective_limit,
            "total": total,
            "has_more": has_more,
        }
        if has_more:
            response["next_offset"] = offset + len(items)
            response["notice"] = (
                "tool list is truncated; request the next page via tools/list with "
                f"offset={response['next_offset']}"
            )
        return response

    def _dispatch_tool_call(self, params: dict[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})

        if not isinstance(name, str):
            raise JsonRpcError(code=-32602, message="Invalid params: tools/call requires 'name'")
        if not isinstance(arguments, dict):
            raise JsonRpcError(
                code=-32602,
                message="Invalid params: tools/call 'arguments' must be an object",
            )

        handler = self._tool_handlers.get(name)
        if handler is None:
            raise JsonRpcError(code=-32601, message=f"Tool not found: {name}")

        try:
            payload = handler(arguments)
            return self._tool_result(payload)
        except BinjaBackendError as exc:
            return self._tool_result({"error": str(exc)}, is_error=True)
        except Exception as exc:
            return self._tool_result(
                {"error": f"unexpected tool failure: {type(exc).__name__}: {exc}"},
                is_error=True,
            )

    @staticmethod
    def _tool_result(payload: dict[str, Any], *, is_error: bool = False) -> dict[str, Any]:
        try:
            _ = json.dumps(payload, sort_keys=True)
            structured_payload = payload
        except TypeError as exc:
            structured_payload = {
                "error": "tool returned a non-JSON-serializable payload",
                "detail": str(exc),
            }
            is_error = True

        text = SimpleMcpServer._tool_summary_text(structured_payload, is_error=is_error)
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": structured_payload,
            "isError": is_error,
        }

    @staticmethod
    def _tool_summary_text(payload: dict[str, Any], *, is_error: bool) -> str:
        if is_error:
            error = payload.get("error")
            if isinstance(error, str) and error:
                return f"error: {error}"
            return "error"

        keys = (
            "session_id",
            "task_id",
            "project_id",
            "type_library_id",
            "type_archive_id",
            "status",
            "count",
            "total",
            "offset",
            "limit",
        )
        parts = ["ok"]
        for key in keys:
            value = payload.get(key)
            if value is not None:
                parts.append(f"{key}={value}")
        return " ".join(parts)

    @staticmethod
    def _success_response(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error_response(request_id: Any, error: JsonRpcError) -> dict[str, Any]:
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {
                "code": error.code,
                "message": error.message,
            },
        }
        if error.data is not None:
            payload["error"]["data"] = error.data
        return payload

    def _tool_definitions(self) -> list[dict[str, Any]]:
        return [
            self._tool("health.ping", "Health check."),
            self._tool("binja.info", "Return Binary Ninja version/install info."),
            self._tool(
                "binja.call",
                "Generic API bridge: call `bn.*` or `bv.*` target path.",
                {
                    "target": {"type": "string"},
                    "session_id": {"type": "string"},
                    "args": {"type": "array"},
                    "kwargs": {"type": "object"},
                },
                ["target"],
            ),
            self._tool(
                "binja.eval",
                "Evaluate Python code with `bn`, `sessions`, and optional `bv`.",
                {
                    "code": {"type": "string"},
                    "session_id": {"type": "string"},
                },
                ["code"],
            ),
            self._tool(
                "session.open",
                "Open a binary and create a session.",
                {
                    "path": {"type": "string"},
                    "update_analysis": {"type": "boolean"},
                    "options": {"type": "object"},
                    "read_only": {"type": "boolean"},
                    "deterministic": {"type": "boolean"},
                },
                ["path"],
            ),
            self._tool(
                "session.open_bytes",
                "Open a binary session from base64-encoded bytes.",
                {
                    "data_base64": {"type": "string"},
                    "filename": {"type": "string"},
                    "update_analysis": {"type": "boolean"},
                    "options": {"type": "object"},
                    "read_only": {"type": "boolean"},
                    "deterministic": {"type": "boolean"},
                },
                ["data_base64"],
            ),
            self._tool(
                "session.open_existing",
                "Open another session from an existing session's file.",
                {
                    "source_session_id": {"type": "string"},
                    "update_analysis": {"type": "boolean"},
                    "options": {"type": "object"},
                    "read_only": {"type": "boolean"},
                    "deterministic": {"type": "boolean"},
                },
                ["source_session_id"],
            ),
            self._tool(
                "session.close",
                "Close one open session.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool("session.list", "List open sessions."),
            self._tool(
                "session.mode",
                "Get session safety/determinism mode.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "session.set_mode",
                "Update session safety/determinism mode.",
                {
                    "session_id": {"type": "string"},
                    "read_only": {"type": "boolean"},
                    "deterministic": {"type": "boolean"},
                },
                ["session_id"],
            ),
            self._tool(
                "analysis.status",
                "Get analysis status.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "analysis.progress",
                "Get analysis progress snapshot.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "analysis.update",
                "Trigger async analysis update.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "analysis.update_and_wait",
                "Run analysis update and wait for completion.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "analysis.abort",
                "Abort analysis.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "analysis.set_hold",
                "Hold/release analysis queue.",
                {
                    "session_id": {"type": "string"},
                    "hold": {"type": "boolean"},
                },
                ["session_id", "hold"],
            ),
            self._tool(
                "binary.summary",
                "Get binary/session summary.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "binary.save",
                "Save the current binary view to a file path.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                },
                ["session_id", "path"],
            ),
            self._tool(
                "binary.functions",
                "List functions with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.strings",
                "List discovered strings with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.search_text",
                "Search raw text/bytes in a session.",
                {
                    "session_id": {"type": "string"},
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "query"],
            ),
            self._tool(
                "binary.sections",
                "List sections with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.segments",
                "List segments with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.symbols",
                "List symbols with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.data_vars",
                "List data variables with pagination.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "binary.get_function_at",
                "Find function by address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "address"],
            ),
            self._tool(
                "binary.get_function_disassembly_at",
                "Get full disassembly for the function containing an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "address"],
            ),
            self._tool(
                "binary.get_function_il_at",
                "Get full IL for the function containing an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "binary.functions_at",
                "List functions at an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "address"],
            ),
            self._tool(
                "binary.basic_blocks_at",
                "List basic blocks at an address with pagination.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "function.basic_blocks",
                "List basic blocks in a function with pagination.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "disasm.linear",
                "Get linear disassembly lines.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id"],
            ),
            self._tool(
                "search.data",
                "Search for raw byte patterns (hex string).",
                {
                    "session_id": {"type": "string"},
                    "data_hex": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "data_hex"],
            ),
            self._tool(
                "search.next_text",
                "Find next text match.",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "query": {"type": "string"},
                },
                ["session_id", "start", "query"],
            ),
            self._tool(
                "search.all_text",
                "Find all text matches in range (regex optional).",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "query": {"type": "string"},
                    "regex": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "start", "end", "query"],
            ),
            self._tool(
                "search.next_data",
                "Find next data/byte-pattern match.",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_hex": {"type": "string"},
                },
                ["session_id", "start", "data_hex"],
            ),
            self._tool(
                "search.all_data",
                "Find all data/byte-pattern matches in range.",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_hex": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "start", "end", "data_hex"],
            ),
            self._tool(
                "search.next_constant",
                "Find next constant occurrence.",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "constant": {"type": "integer"},
                },
                ["session_id", "start", "constant"],
            ),
            self._tool(
                "search.all_constant",
                "Find all constant occurrences in range.",
                {
                    "session_id": {"type": "string"},
                    "start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "end": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "constant": {"type": "integer"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "start", "end", "constant"],
            ),
            self._tool(
                "xref.code_refs_to",
                "Code references to an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "xref.code_refs_from",
                "Code references from an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "length": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "xref.data_refs_to",
                "Data references to an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "xref.data_refs_from",
                "Data references from an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "length": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "function.callers",
                "Callers of a function.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "function.callees",
                "Callees of a function.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "function.variables",
                "List function variables.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "function.var_refs",
                "List variable references in MLIL/HLIL.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "variable_name": {"type": "string"},
                    "level": {"type": "string", "enum": ["mlil", "hlil"]},
                },
                ["session_id", "function_start", "variable_name"],
            ),
            self._tool(
                "function.var_refs_from",
                "List variable references originating from an address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "level": {"type": "string", "enum": ["mlil", "hlil"]},
                    "length": {"type": "integer", "minimum": 1},
                },
                ["session_id", "function_start", "address"],
            ),
            self._tool(
                "function.ssa_var_def_use",
                "Get SSA variable definition and uses.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "variable_name": {"type": "string"},
                    "version": {"type": "integer", "minimum": 0},
                    "level": {"type": "string", "enum": ["mlil", "hlil"]},
                },
                ["session_id", "function_start", "variable_name", "version"],
            ),
            self._tool(
                "function.ssa_memory_def_use",
                "Get SSA memory definition and uses by memory version.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "version": {"type": "integer", "minimum": 0},
                    "level": {"type": "string", "enum": ["mlil", "hlil"]},
                },
                ["session_id", "function_start", "version"],
            ),
            self._tool(
                "value.reg",
                "Get register value at/after an address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "register": {"type": "string"},
                    "after": {"type": "boolean"},
                },
                ["session_id", "function_start", "address", "register"],
            ),
            self._tool(
                "value.stack",
                "Get stack contents at/after an address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "stack_offset": {"type": "integer"},
                    "size": {"type": "integer", "minimum": 1},
                    "after": {"type": "boolean"},
                },
                ["session_id", "function_start", "address", "stack_offset", "size"],
            ),
            self._tool(
                "value.possible",
                "Get IL possible value set at an address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                },
                ["session_id", "function_start", "address"],
            ),
            self._tool(
                "value.flags_at",
                "Get lifted IL flag read/write state at an address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "function_start", "address"],
            ),
            self._tool(
                "memory.read",
                "Read bytes from the view.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer", "minimum": 1, "maximum": 65536},
                },
                ["session_id", "address", "length"],
            ),
            self._tool(
                "memory.write",
                "Write bytes (hex) to the view.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_hex": {"type": "string"},
                },
                ["session_id", "address", "data_hex"],
            ),
            self._tool(
                "memory.insert",
                "Insert bytes (hex) into the view.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "data_hex": {"type": "string"},
                },
                ["session_id", "address", "data_hex"],
            ),
            self._tool(
                "memory.remove",
                "Remove bytes from the view.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "length": {"type": "integer", "minimum": 1},
                },
                ["session_id", "address", "length"],
            ),
            self._tool(
                "memory.reader_read",
                "Read integer values via BinaryReader.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "width": {"type": "integer", "enum": [1, 2, 4, 8]},
                    "endian": {"type": "string", "enum": ["little", "big"]},
                },
                ["session_id", "address", "width"],
            ),
            self._tool(
                "memory.writer_write",
                "Write integer values via BinaryWriter.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "width": {"type": "integer", "enum": [1, 2, 4, 8]},
                    "value": {"type": "integer"},
                    "endian": {"type": "string", "enum": ["little", "big"]},
                },
                ["session_id", "address", "width", "value"],
            ),
            self._tool(
                "data.typed_at",
                "Get typed data variable at an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "disasm.function",
                "Get full disassembly for the function containing an address.",
                {
                    "session_id": {"type": "string"},
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                },
                ["session_id", "address"],
            ),
            self._tool(
                "disasm.range",
                "Address-range disassembly lines.",
                {
                    "session_id": {"type": "string"},
                    "start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "length": {"type": "integer", "minimum": 1},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "start", "length"],
            ),
            self._tool(
                "il.function",
                "IL function listing.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                    "offset": {"type": "integer", "minimum": 0},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "il.instruction_by_addr",
                "Get IL instruction by source address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                },
                ["session_id", "function_start", "address"],
            ),
            self._tool(
                "il.address_to_index",
                "Map address to IL index/indices.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "address": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                },
                ["session_id", "function_start", "address"],
            ),
            self._tool(
                "il.index_to_address",
                "Map IL index to source address.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "index": {"type": "integer", "minimum": 0},
                    "level": {"type": "string", "enum": ["llil", "mlil", "hlil"]},
                    "ssa": {"type": "boolean"},
                },
                ["session_id", "function_start", "index"],
            ),
            self._tool(
                "annotation.rename_function",
                "Rename a function.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "new_name": {"type": "string"},
                },
                ["session_id", "function_start", "new_name"],
            ),
            self._tool(
                "annotation.rename_symbol",
                "Rename symbol at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "new_name": {"type": "string"},
                },
                ["session_id", "address", "new_name"],
            ),
            self._tool(
                "annotation.undefine_symbol",
                "Undefine user symbol at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "annotation.define_symbol",
                "Define symbol at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "name": {"type": "string"},
                    "symbol_type": {"type": "string"},
                },
                ["session_id", "address", "name"],
            ),
            self._tool(
                "annotation.rename_data_var",
                "Rename data variable.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "new_name": {"type": "string"},
                },
                ["session_id", "address", "new_name"],
            ),
            self._tool(
                "annotation.define_data_var",
                "Define data variable.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "type_name": {"type": "string"},
                    "width": {"type": "integer", "minimum": 1},
                    "name": {"type": "string"},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "annotation.undefine_data_var",
                "Undefine data variable.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "annotation.set_comment",
                "Set comment at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "comment": {"type": "string"},
                },
                ["session_id", "address", "comment"],
            ),
            self._tool(
                "annotation.get_comment",
                "Get comment at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "annotation.add_tag",
                "Add user data tag at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "tag_type": {"type": "string"},
                    "data": {"type": "string"},
                    "icon": {"type": "string"},
                },
                ["session_id", "address", "tag_type", "data"],
            ),
            self._tool(
                "annotation.get_tags",
                "Get tags at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "metadata.store",
                "Store metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {},
                },
                ["session_id", "key", "value"],
            ),
            self._tool(
                "metadata.query",
                "Query metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                },
                ["session_id", "key"],
            ),
            self._tool(
                "metadata.remove",
                "Remove metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                },
                ["session_id", "key"],
            ),
            self._tool(
                "function.metadata_store",
                "Store function metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "key": {"type": "string"},
                    "value": {},
                },
                ["session_id", "function_start", "key", "value"],
            ),
            self._tool(
                "function.metadata_query",
                "Query function metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "key": {"type": "string"},
                },
                ["session_id", "function_start", "key"],
            ),
            self._tool(
                "function.metadata_remove",
                "Remove function metadata by key.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {
                        "oneOf": [{"type": "integer"}, {"type": "string"}],
                    },
                    "key": {"type": "string"},
                },
                ["session_id", "function_start", "key"],
            ),
            self._tool(
                "patch.assemble",
                "Assemble and patch instruction bytes at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "asm": {"type": "string"},
                },
                ["session_id", "address", "asm"],
            ),
            self._tool(
                "patch.status",
                "Inspect patch availability at address.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "patch.convert_to_nop",
                "Patch instruction to NOP when supported.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "patch.always_branch",
                "Patch conditional branch to always branch when supported.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "patch.never_branch",
                "Patch conditional branch to never branch when supported.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "patch.invert_branch",
                "Patch conditional branch by inversion when supported.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "patch.skip_and_return_value",
                "Patch instruction to skip and return value when supported.",
                {
                    "session_id": {"type": "string"},
                    "address": {"oneOf": [{"type": "integer"}, {"type": "string"}]},
                    "value": {"type": "integer"},
                },
                ["session_id", "address", "value"],
            ),
            self._tool(
                "undo.begin",
                "Begin undo transaction.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "undo.commit",
                "Commit undo transaction.",
                {
                    "session_id": {"type": "string"},
                    "transaction_id": {"type": "string"},
                },
                ["session_id"],
            ),
            self._tool(
                "undo.revert",
                "Revert undo transaction.",
                {
                    "session_id": {"type": "string"},
                    "transaction_id": {"type": "string"},
                },
                ["session_id"],
            ),
            self._tool(
                "undo.undo",
                "Perform undo.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "undo.redo",
                "Perform redo.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "task.analysis_update",
                "Start async analysis update task.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "task.search_text",
                "Start async search task.",
                {
                    "session_id": {"type": "string"},
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "minimum": 1},
                },
                ["session_id", "query"],
            ),
            self._tool(
                "task.status",
                "Get task status.",
                {"task_id": {"type": "string"}},
                ["task_id"],
            ),
            self._tool(
                "task.result",
                "Get task result.",
                {"task_id": {"type": "string"}},
                ["task_id"],
            ),
            self._tool(
                "task.cancel",
                "Cancel task (best-effort).",
                {"task_id": {"type": "string"}},
                ["task_id"],
            ),
            self._tool(
                "database.create_bndb",
                "Create .bndb from session.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                },
                ["session_id", "path"],
            ),
            self._tool(
                "database.save_auto_snapshot",
                "Save auto snapshot.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "type.parse_string",
                "Parse a single type string.",
                {
                    "session_id": {"type": "string"},
                    "type_source": {"type": "string"},
                    "import_dependencies": {"type": "boolean"},
                },
                ["session_id", "type_source"],
            ),
            self._tool(
                "type.parse_declarations",
                "Parse C declarations for types/variables/functions.",
                {
                    "session_id": {"type": "string"},
                    "declarations": {"type": "string"},
                    "options": {"type": "array"},
                    "include_dirs": {"type": "array"},
                    "import_dependencies": {"type": "boolean"},
                },
                ["session_id", "declarations"],
            ),
            self._tool(
                "type.define_user",
                "Define user type from type source.",
                {
                    "session_id": {"type": "string"},
                    "type_source": {"type": "string"},
                    "name": {"type": "string"},
                    "import_dependencies": {"type": "boolean"},
                },
                ["session_id", "type_source"],
            ),
            self._tool(
                "type.rename",
                "Rename a type.",
                {
                    "session_id": {"type": "string"},
                    "old_name": {"type": "string"},
                    "new_name": {"type": "string"},
                },
                ["session_id", "old_name", "new_name"],
            ),
            self._tool(
                "type.undefine_user",
                "Undefine a user type.",
                {"session_id": {"type": "string"}, "name": {"type": "string"}},
                ["session_id", "name"],
            ),
            self._tool(
                "type.import_library_type",
                "Import type from type library.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "type_library_id": {"type": "string"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "type.import_library_object",
                "Import object type from type library.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "type_library_id": {"type": "string"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "type.export_to_library",
                "Export type into a type library.",
                {
                    "session_id": {"type": "string"},
                    "type_library_id": {"type": "string"},
                    "type_source": {"type": "string"},
                    "name": {"type": "string"},
                    "import_dependencies": {"type": "boolean"},
                },
                ["session_id", "type_library_id", "type_source"],
            ),
            self._tool(
                "type_library.create",
                "Create and optionally attach a type library.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "path": {"type": "string"},
                    "add_to_view": {"type": "boolean"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "type_library.load",
                "Load and optionally attach a type library.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "add_to_view": {"type": "boolean"},
                },
                ["session_id", "path"],
            ),
            self._tool(
                "type_library.list",
                "List type libraries attached to the view.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "type_library.get",
                "Get one tracked type library.",
                {
                    "session_id": {"type": "string"},
                    "type_library_id": {"type": "string"},
                },
                ["session_id", "type_library_id"],
            ),
            self._tool(
                "type_archive.create",
                "Create and optionally attach a type archive.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "platform_name": {"type": "string"},
                    "attach": {"type": "boolean"},
                },
                ["session_id", "path"],
            ),
            self._tool(
                "type_archive.open",
                "Open and optionally attach a type archive.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "attach": {"type": "boolean"},
                },
                ["session_id", "path"],
            ),
            self._tool(
                "type_archive.list",
                "List attached type archives.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "type_archive.get",
                "Get one tracked type archive.",
                {
                    "session_id": {"type": "string"},
                    "type_archive_id": {"type": "string"},
                },
                ["session_id", "type_archive_id"],
            ),
            self._tool(
                "type_archive.pull",
                "Pull types from a type archive.",
                {
                    "session_id": {"type": "string"},
                    "type_archive_id": {"type": "string"},
                    "names": {"type": "array"},
                },
                ["session_id", "type_archive_id", "names"],
            ),
            self._tool(
                "type_archive.push",
                "Push types to a type archive.",
                {
                    "session_id": {"type": "string"},
                    "type_archive_id": {"type": "string"},
                    "names": {"type": "array"},
                },
                ["session_id", "type_archive_id", "names"],
            ),
            self._tool(
                "type_archive.references",
                "Query archive incoming/outgoing references for one type.",
                {
                    "type_archive_id": {"type": "string"},
                    "name": {"type": "string"},
                },
                ["type_archive_id", "name"],
            ),
            self._tool(
                "debug.parsers",
                "List debug info parsers valid for this view.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "debug.parse_and_apply",
                "Parse debug info and apply it to the view.",
                {
                    "session_id": {"type": "string"},
                    "debug_path": {"type": "string"},
                    "parser_name": {"type": "string"},
                },
                ["session_id"],
            ),
            self._tool("workflow.list", "List registered workflows."),
            self._tool(
                "workflow.describe",
                "Describe workflow topology and settings.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "activity": {"type": "string"},
                    "immediate": {"type": "boolean"},
                },
                ["session_id"],
            ),
            self._tool(
                "workflow.clone",
                "Clone workflow.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "register": {"type": "boolean"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "workflow.insert",
                "Insert activities before an activity.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "activity": {"type": "string"},
                    "activities": {"type": ["array", "string"]},
                },
                ["session_id", "activity", "activities"],
            ),
            self._tool(
                "workflow.insert_after",
                "Insert activities after an activity.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "activity": {"type": "string"},
                    "activities": {"type": ["array", "string"]},
                },
                ["session_id", "activity", "activities"],
            ),
            self._tool(
                "workflow.remove",
                "Remove workflow activity.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "activity": {"type": "string"},
                },
                ["session_id", "activity"],
            ),
            self._tool(
                "workflow.graph",
                "Summarize workflow graph.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "activity": {"type": "string"},
                    "sequential": {"type": "boolean"},
                },
                ["session_id"],
            ),
            self._tool(
                "workflow.machine.status",
                "Get workflow machine status.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                },
                ["session_id"],
            ),
            self._tool(
                "workflow.machine.control",
                "Control workflow machine runtime.",
                {
                    "session_id": {"type": "string"},
                    "workflow_name": {"type": "string"},
                    "action": {"type": "string"},
                    "advanced": {"type": "boolean"},
                    "incremental": {"type": "boolean"},
                    "activities": {"type": ["array", "string"]},
                    "activity": {"type": "string"},
                    "enable": {"type": "boolean"},
                },
                ["session_id", "action"],
            ),
            self._tool(
                "il.rewrite.capabilities",
                "List IL rewrite support for one function and IL level.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                    "level": {"type": "string"},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "il.rewrite.noop_replace",
                "Perform no-op IL expression replacement.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                    "level": {"type": "string"},
                    "index": {"type": "integer"},
                    "finalize": {"type": "boolean"},
                    "generate_ssa_form": {"type": "boolean"},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "il.rewrite.translate_identity",
                "Translate IL with identity mapping callback.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                    "level": {"type": "string"},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "uidf.parse_possible_value",
                "Parse user-informed possible value set string.",
                {
                    "session_id": {"type": "string"},
                    "value": {"type": "string"},
                    "state": {"type": "string"},
                    "here": {"type": ["integer", "string"]},
                },
                ["session_id", "value", "state"],
            ),
            self._tool(
                "uidf.set_user_var_value",
                "Set function user variable value.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                    "variable_name": {"type": "string"},
                    "def_addr": {"type": ["integer", "string"]},
                    "value": {"type": "string"},
                    "state": {"type": "string"},
                    "after": {"type": "boolean"},
                },
                ["session_id", "function_start", "variable_name", "def_addr", "value", "state"],
            ),
            self._tool(
                "uidf.clear_user_var_value",
                "Clear function user variable value.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                    "variable_name": {"type": "string"},
                    "def_addr": {"type": ["integer", "string"]},
                    "after": {"type": "boolean"},
                },
                ["session_id", "function_start", "variable_name", "def_addr"],
            ),
            self._tool(
                "uidf.list_user_var_values",
                "List all user variable values for a function.",
                {
                    "session_id": {"type": "string"},
                    "function_start": {"type": ["integer", "string"]},
                },
                ["session_id", "function_start"],
            ),
            self._tool(
                "loader.rebase",
                "Rebase BinaryView.",
                {
                    "session_id": {"type": "string"},
                    "address": {"type": ["integer", "string"]},
                    "force": {"type": "boolean"},
                },
                ["session_id", "address"],
            ),
            self._tool(
                "loader.load_settings_types",
                "List loader settings type names.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "loader.load_settings_get",
                "Get loader settings values.",
                {
                    "session_id": {"type": "string"},
                    "type_name": {"type": "string"},
                },
                ["session_id", "type_name"],
            ),
            self._tool(
                "loader.load_settings_set",
                "Set one loader setting value.",
                {
                    "session_id": {"type": "string"},
                    "type_name": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {},
                    "value_type": {"type": "string"},
                },
                ["session_id", "type_name", "key", "value"],
            ),
            self._tool(
                "segment.add_user",
                "Add user segment.",
                {
                    "session_id": {"type": "string"},
                    "start": {"type": ["integer", "string"]},
                    "length": {"type": "integer"},
                    "data_offset": {"type": "integer"},
                    "data_length": {"type": "integer"},
                    "readable": {"type": "boolean"},
                    "writable": {"type": "boolean"},
                    "executable": {"type": "boolean"},
                    "contains_data": {"type": "boolean"},
                    "contains_code": {"type": "boolean"},
                },
                ["session_id", "start", "length"],
            ),
            self._tool(
                "segment.remove_user",
                "Remove user segment.",
                {
                    "session_id": {"type": "string"},
                    "start": {"type": ["integer", "string"]},
                    "length": {"type": "integer"},
                },
                ["session_id", "start"],
            ),
            self._tool(
                "section.add_user",
                "Add user section.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "start": {"type": ["integer", "string"]},
                    "length": {"type": "integer"},
                    "semantics": {"type": "string"},
                    "type_name": {"type": "string"},
                    "align": {"type": "integer"},
                    "entry_size": {"type": "integer"},
                },
                ["session_id", "name", "start", "length"],
            ),
            self._tool(
                "section.remove_user",
                "Remove user section.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "external.library_add",
                "Add external library.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "auto": {"type": "boolean"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "external.library_list",
                "List external libraries.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "external.library_remove",
                "Remove external library.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                },
                ["session_id", "name"],
            ),
            self._tool(
                "external.location_add",
                "Add external location mapping.",
                {
                    "session_id": {"type": "string"},
                    "source_address": {"type": ["integer", "string"]},
                    "library_name": {"type": "string"},
                    "target_symbol": {"type": "string"},
                    "target_address": {"type": ["integer", "string"]},
                    "auto": {"type": "boolean"},
                },
                ["session_id", "source_address"],
            ),
            self._tool(
                "external.location_get",
                "Get external location mapping.",
                {
                    "session_id": {"type": "string"},
                    "source_address": {"type": ["integer", "string"]},
                },
                ["session_id", "source_address"],
            ),
            self._tool(
                "external.location_remove",
                "Remove external location mapping.",
                {
                    "session_id": {"type": "string"},
                    "source_address": {"type": ["integer", "string"]},
                },
                ["session_id", "source_address"],
            ),
            self._tool(
                "arch.info",
                "Get architecture and platform metadata.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "arch.disasm_bytes",
                "Disassemble bytes with selected architecture.",
                {
                    "session_id": {"type": "string"},
                    "data_hex": {"type": "string"},
                    "address": {"type": ["integer", "string"]},
                    "arch_name": {"type": "string"},
                },
                ["session_id", "data_hex"],
            ),
            self._tool(
                "arch.assemble",
                "Assemble instruction text with selected architecture.",
                {
                    "session_id": {"type": "string"},
                    "asm": {"type": "string"},
                    "address": {"type": ["integer", "string"]},
                    "arch_name": {"type": "string"},
                },
                ["session_id", "asm"],
            ),
            self._tool(
                "transform.inspect",
                "Inspect/process transform pipeline. Requires session_id or path.",
                {
                    "session_id": {"type": "string"},
                    "path": {"type": "string"},
                    "mode": {"type": "string"},
                    "process": {"type": "boolean"},
                },
            ),
            self._tool(
                "project.create",
                "Create project.",
                {"path": {"type": "string"}, "name": {"type": "string"}},
                ["path", "name"],
            ),
            self._tool(
                "project.open",
                "Open project.",
                {"path": {"type": "string"}},
                ["path"],
            ),
            self._tool(
                "project.close",
                "Close tracked project.",
                {"project_id": {"type": "string"}},
                ["project_id"],
            ),
            self._tool(
                "project.list",
                "List project folders/files.",
                {"project_id": {"type": "string"}},
                ["project_id"],
            ),
            self._tool(
                "project.create_folder",
                "Create project folder.",
                {
                    "project_id": {"type": "string"},
                    "name": {"type": "string"},
                    "parent_folder_id": {"type": "string"},
                    "description": {"type": "string"},
                },
                ["project_id", "name"],
            ),
            self._tool(
                "project.create_file",
                "Create project file from base64 data.",
                {
                    "project_id": {"type": "string"},
                    "name": {"type": "string"},
                    "data_base64": {"type": "string"},
                    "folder_id": {"type": "string"},
                    "description": {"type": "string"},
                },
                ["project_id", "name", "data_base64"],
            ),
            self._tool(
                "project.metadata_store",
                "Store project metadata.",
                {
                    "project_id": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {},
                },
                ["project_id", "key", "value"],
            ),
            self._tool(
                "project.metadata_query",
                "Query project metadata.",
                {"project_id": {"type": "string"}, "key": {"type": "string"}},
                ["project_id", "key"],
            ),
            self._tool(
                "project.metadata_remove",
                "Remove project metadata.",
                {"project_id": {"type": "string"}, "key": {"type": "string"}},
                ["project_id", "key"],
            ),
            self._tool(
                "database.info",
                "Get database status for session.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
            self._tool(
                "database.snapshots",
                "List database snapshots.",
                {
                    "session_id": {"type": "string"},
                    "offset": {"type": "integer"},
                    "limit": {"type": "integer"},
                },
                ["session_id"],
            ),
            self._tool(
                "database.read_global",
                "Read database global string key.",
                {"session_id": {"type": "string"}, "key": {"type": "string"}},
                ["session_id", "key"],
            ),
            self._tool(
                "database.write_global",
                "Write database global string key.",
                {
                    "session_id": {"type": "string"},
                    "key": {"type": "string"},
                    "value": {"type": "string"},
                },
                ["session_id", "key", "value"],
            ),
            self._tool(
                "plugin.valid_commands",
                "List context-valid plugin commands.",
                {
                    "session_id": {"type": "string"},
                    "address": {"type": ["integer", "string"]},
                    "length": {"type": "integer"},
                },
                ["session_id"],
            ),
            self._tool(
                "plugin.execute",
                "Execute a context-valid plugin command.",
                {
                    "session_id": {"type": "string"},
                    "name": {"type": "string"},
                    "address": {"type": ["integer", "string"]},
                    "length": {"type": "integer"},
                    "perform": {"type": "boolean"},
                },
                ["session_id", "name"],
            ),
            self._tool("plugin_repo.status", "List plugin repositories and plugin states."),
            self._tool(
                "plugin_repo.check_updates",
                "Check plugin repository updates.",
                {"perform": {"type": "boolean"}},
            ),
            self._tool(
                "plugin_repo.plugin_action",
                "Run install/uninstall/enable/disable action on repository plugin.",
                {
                    "repository_path": {"type": "string"},
                    "plugin_path": {"type": "string"},
                    "action": {"type": "string"},
                },
                ["repository_path", "plugin_path", "action"],
            ),
            self._tool(
                "baseaddr.detect",
                "Run base-address detection.",
                {
                    "session_id": {"type": "string"},
                    "arch_name": {"type": "string"},
                    "analysis": {"type": "string"},
                    "min_strlen": {"type": "integer"},
                    "alignment": {"type": "integer"},
                    "low_boundary": {"type": "integer"},
                    "high_boundary": {"type": "integer"},
                    "max_pointers": {"type": "integer"},
                },
                ["session_id"],
            ),
            self._tool(
                "baseaddr.reasons",
                "Get base-address detection reasons.",
                {
                    "session_id": {"type": "string"},
                    "base_address": {"type": ["integer", "string"]},
                },
                ["session_id", "base_address"],
            ),
            self._tool(
                "baseaddr.abort",
                "Abort base-address detection.",
                {"session_id": {"type": "string"}},
                ["session_id"],
            ),
        ]

    @staticmethod
    def _tool(
        name: str,
        description: str,
        properties: dict[str, Any] | None = None,
        required: list[str] | None = None,
        schema_extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        input_schema: dict[str, Any] = {
            "type": "object",
            "properties": properties or {},
        }
        if required:
            input_schema["required"] = required
        if schema_extra:
            input_schema.update(schema_extra)

        return {
            "name": name,
            "description": description,
            "inputSchema": input_schema,
        }

    @staticmethod
    def _require_str(arguments: dict[str, Any], key: str) -> str:
        value = arguments.get(key)
        if not isinstance(value, str):
            raise BinjaBackendError(f"'{key}' must be a string")
        return value

    @staticmethod
    def _optional_bool(arguments: dict[str, Any], key: str) -> bool | None:
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, bool):
            raise BinjaBackendError(f"'{key}' must be a boolean")
        return value

    @staticmethod
    def _optional_int(arguments: dict[str, Any], key: str) -> int | None:
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, int):
            raise BinjaBackendError(f"'{key}' must be an integer")
        return value

    @staticmethod
    def _optional_int_or_str(arguments: dict[str, Any], key: str) -> int | str | None:
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, (int, str)):
            raise BinjaBackendError(f"'{key}' must be an integer or string")
        return value

    @staticmethod
    def _optional_str(arguments: dict[str, Any], key: str) -> str | None:
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise BinjaBackendError(f"'{key}' must be a string")
        return value

    @staticmethod
    def _optional_str_list(arguments: dict[str, Any], key: str) -> list[str] | None:
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise BinjaBackendError(f"'{key}' must be an array of strings")
        return value

    def _tool_ping(self, _: dict[str, Any]) -> dict[str, Any]:
        return self._backend.ping()

    def _tool_binja_info(self, _: dict[str, Any]) -> dict[str, Any]:
        return self._backend.core_info()

    def _tool_session_open(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._require_str(arguments, "path")

        update_analysis = arguments.get("update_analysis", True)
        if not isinstance(update_analysis, bool):
            raise BinjaBackendError("'update_analysis' must be a boolean")

        options = arguments.get("options", {})
        if not isinstance(options, dict):
            raise BinjaBackendError("'options' must be an object")

        read_only = arguments.get("read_only", True)
        if not isinstance(read_only, bool):
            raise BinjaBackendError("'read_only' must be a boolean")

        deterministic = arguments.get("deterministic", True)
        if not isinstance(deterministic, bool):
            raise BinjaBackendError("'deterministic' must be a boolean")

        return self._backend.open_session(
            path,
            update_analysis=update_analysis,
            options=options,
            read_only=read_only,
            deterministic=deterministic,
        )

    def _tool_session_open_bytes(self, arguments: dict[str, Any]) -> dict[str, Any]:
        data_base64 = self._require_str(arguments, "data_base64")

        filename = arguments.get("filename", "binary_ninja_headless_mcp_bytes.bin")
        if not isinstance(filename, str):
            raise BinjaBackendError("'filename' must be a string")

        update_analysis = arguments.get("update_analysis", True)
        if not isinstance(update_analysis, bool):
            raise BinjaBackendError("'update_analysis' must be a boolean")

        options = arguments.get("options", {})
        if not isinstance(options, dict):
            raise BinjaBackendError("'options' must be an object")

        read_only = arguments.get("read_only", True)
        if not isinstance(read_only, bool):
            raise BinjaBackendError("'read_only' must be a boolean")

        deterministic = arguments.get("deterministic", True)
        if not isinstance(deterministic, bool):
            raise BinjaBackendError("'deterministic' must be a boolean")

        return self._backend.open_session_from_bytes(
            data_base64,
            filename=filename,
            update_analysis=update_analysis,
            options=options,
            read_only=read_only,
            deterministic=deterministic,
        )

    def _tool_session_open_existing(self, arguments: dict[str, Any]) -> dict[str, Any]:
        source_session_id = self._require_str(arguments, "source_session_id")

        update_analysis = arguments.get("update_analysis", False)
        if not isinstance(update_analysis, bool):
            raise BinjaBackendError("'update_analysis' must be a boolean")

        options = arguments.get("options", {})
        if not isinstance(options, dict):
            raise BinjaBackendError("'options' must be an object")

        read_only = arguments.get("read_only", True)
        if not isinstance(read_only, bool):
            raise BinjaBackendError("'read_only' must be a boolean")

        deterministic = arguments.get("deterministic", True)
        if not isinstance(deterministic, bool):
            raise BinjaBackendError("'deterministic' must be a boolean")

        return self._backend.open_session_from_existing(
            source_session_id,
            update_analysis=update_analysis,
            options=options,
            read_only=read_only,
            deterministic=deterministic,
        )

    def _tool_session_close(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.close_session(session_id)

    def _tool_session_list(self, _: dict[str, Any]) -> dict[str, Any]:
        return self._backend.list_sessions()

    def _tool_session_mode(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.session_mode(session_id)

    def _tool_session_set_mode(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        read_only = self._optional_bool(arguments, "read_only")
        deterministic = self._optional_bool(arguments, "deterministic")
        return self._backend.set_session_mode(
            session_id,
            read_only=read_only,
            deterministic=deterministic,
        )

    def _tool_analysis_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.analysis_status(session_id)

    def _tool_analysis_progress(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.analysis_progress(session_id)

    def _tool_analysis_update(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.analysis_update(session_id, wait=False)

    def _tool_analysis_update_and_wait(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.analysis_update(session_id, wait=True)

    def _tool_analysis_abort(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.analysis_abort(session_id)

    def _tool_analysis_set_hold(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        hold = arguments.get("hold")
        if not isinstance(hold, bool):
            raise BinjaBackendError("'hold' must be a boolean")
        return self._backend.analysis_set_hold(session_id, hold)

    def _tool_binary_summary(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.binary_summary(session_id)

    def _tool_binary_save(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        path = self._require_str(arguments, "path")
        return self._backend.save_binary(session_id, path)

    def _tool_binary_functions(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")

        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")

        return self._backend.list_functions(session_id, offset=offset, limit=limit)

    def _tool_binary_strings(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")

        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")

        return self._backend.list_strings(session_id, offset=offset, limit=limit)

    def _tool_binary_search_text(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        query = self._require_str(arguments, "query")

        limit = arguments.get("limit", 50)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")

        return self._backend.search_text(session_id, query, limit=limit)

    def _tool_binary_sections(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_sections(session_id, offset=offset, limit=limit)

    def _tool_binary_segments(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_segments(session_id, offset=offset, limit=limit)

    def _tool_binary_symbols(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_symbols(session_id, offset=offset, limit=limit)

    def _tool_binary_data_vars(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_data_vars(session_id, offset=offset, limit=limit)

    def _tool_binary_get_function_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.get_function_at(session_id, address)

    def _tool_binary_get_function_disassembly_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.get_function_disassembly_at(session_id, address)

    def _tool_binary_get_function_il_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")
        return self._backend.get_function_il_at(
            session_id,
            address,
            level=level,
            ssa=ssa,
        )

    def _tool_binary_functions_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.list_functions_at(session_id, address)

    def _tool_binary_basic_blocks_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_basic_blocks_at(
            session_id,
            address,
            offset=offset,
            limit=limit,
        )

    def _tool_function_basic_blocks(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.list_function_basic_blocks(
            session_id,
            function_start,
            offset=offset,
            limit=limit,
        )

    def _tool_disasm_linear(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 200)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.disasm_linear(session_id, offset=offset, limit=limit)

    def _tool_search_data(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        data_hex = self._require_str(arguments, "data_hex")
        start = self._optional_int_or_str(arguments, "start")
        end = self._optional_int_or_str(arguments, "end")
        limit = arguments.get("limit", 100)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")
        return self._backend.search_data(session_id, data_hex, start=start, end=end, limit=limit)

    def _tool_search_next_text(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        query = self._require_str(arguments, "query")
        return self._backend.find_next_text(session_id, start, query)

    def _tool_search_all_text(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        end = self._optional_int_or_str(arguments, "end")
        if start is None or end is None:
            raise BinjaBackendError("'start' and 'end' are required")
        query = self._require_str(arguments, "query")
        regex = arguments.get("regex", False)
        if not isinstance(regex, bool):
            raise BinjaBackendError("'regex' must be a boolean")
        limit = arguments.get("limit", 100)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")
        return self._backend.find_all_text(
            session_id,
            start,
            end,
            query,
            regex=regex,
            limit=limit,
        )

    def _tool_search_next_data(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        data_hex = self._require_str(arguments, "data_hex")
        return self._backend.find_next_data(session_id, start, data_hex)

    def _tool_search_all_data(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        end = self._optional_int_or_str(arguments, "end")
        if start is None or end is None:
            raise BinjaBackendError("'start' and 'end' are required")
        data_hex = self._require_str(arguments, "data_hex")
        limit = arguments.get("limit", 100)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")
        return self._backend.find_all_data(session_id, start, end, data_hex, limit=limit)

    def _tool_search_next_constant(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        constant = arguments.get("constant")
        if not isinstance(constant, int):
            raise BinjaBackendError("'constant' must be an integer")
        return self._backend.find_next_constant(session_id, start, constant)

    def _tool_search_all_constant(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        end = self._optional_int_or_str(arguments, "end")
        if start is None or end is None:
            raise BinjaBackendError("'start' and 'end' are required")
        constant = arguments.get("constant")
        if not isinstance(constant, int):
            raise BinjaBackendError("'constant' must be an integer")
        limit = arguments.get("limit", 100)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")
        return self._backend.find_all_constant(session_id, start, end, constant, limit=limit)

    def _tool_xref_code_refs_to(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")

        return self._backend.code_refs_to(session_id, address, offset=offset, limit=limit)

    def _tool_xref_code_refs_from(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        length = self._optional_int(arguments, "length")
        return self._backend.code_refs_from(session_id, address, length=length)

    def _tool_xref_data_refs_to(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        limit = arguments.get("limit", 100)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")

        return self._backend.data_refs_to(session_id, address, limit=limit)

    def _tool_xref_data_refs_from(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        length = self._optional_int(arguments, "length")
        return self._backend.data_refs_from(session_id, address, length=length)

    def _tool_function_callers(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        return self._backend.function_callers(session_id, function_start)

    def _tool_function_callees(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        return self._backend.function_callees(session_id, function_start)

    def _tool_function_variables(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        return self._backend.function_variables(session_id, function_start)

    def _tool_function_var_refs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        variable_name = self._require_str(arguments, "variable_name")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        return self._backend.function_variable_refs(
            session_id,
            function_start,
            variable_name,
            level=level,
        )

    def _tool_function_var_refs_from(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        address = self._optional_int_or_str(arguments, "address")
        if function_start is None or address is None:
            raise BinjaBackendError("'function_start' and 'address' are required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        length = self._optional_int(arguments, "length")
        return self._backend.function_variable_refs_from(
            session_id,
            function_start,
            address,
            level=level,
            length=length,
        )

    def _tool_function_ssa_var_def_use(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        variable_name = self._require_str(arguments, "variable_name")
        version = arguments.get("version")
        if not isinstance(version, int):
            raise BinjaBackendError("'version' must be an integer")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        return self._backend.function_ssa_var_def_use(
            session_id,
            function_start,
            variable_name,
            version,
            level=level,
        )

    def _tool_function_ssa_memory_def_use(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        version = arguments.get("version")
        if not isinstance(version, int):
            raise BinjaBackendError("'version' must be an integer")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        return self._backend.function_ssa_memory_def_use(
            session_id,
            function_start,
            version,
            level=level,
        )

    def _tool_value_reg(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        address = self._optional_int_or_str(arguments, "address")
        if function_start is None or address is None:
            raise BinjaBackendError("'function_start' and 'address' are required")
        register = self._require_str(arguments, "register")
        after = arguments.get("after", False)
        if not isinstance(after, bool):
            raise BinjaBackendError("'after' must be a boolean")
        return self._backend.function_reg_value(
            session_id,
            function_start,
            address,
            register,
            after=after,
        )

    def _tool_value_stack(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        address = self._optional_int_or_str(arguments, "address")
        if function_start is None or address is None:
            raise BinjaBackendError("'function_start' and 'address' are required")
        stack_offset = arguments.get("stack_offset")
        size = arguments.get("size")
        if not isinstance(stack_offset, int) or not isinstance(size, int):
            raise BinjaBackendError("'stack_offset' and 'size' must be integers")
        after = arguments.get("after", False)
        if not isinstance(after, bool):
            raise BinjaBackendError("'after' must be a boolean")
        return self._backend.function_stack_contents(
            session_id,
            function_start,
            address,
            stack_offset,
            size,
            after=after,
        )

    def _tool_value_possible(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        address = self._optional_int_or_str(arguments, "address")
        if function_start is None or address is None:
            raise BinjaBackendError("'function_start' and 'address' are required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")
        return self._backend.il_possible_values(
            session_id,
            function_start,
            address,
            level=level,
            ssa=ssa,
        )

    def _tool_value_flags_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        address = self._optional_int_or_str(arguments, "address")
        if function_start is None or address is None:
            raise BinjaBackendError("'function_start' and 'address' are required")
        return self._backend.function_flags_at(session_id, function_start, address)

    def _tool_memory_read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        length = arguments.get("length")
        if address is None or not isinstance(length, int):
            raise BinjaBackendError("'address' and 'length' are required")
        return self._backend.read_bytes(session_id, address, length)

    def _tool_memory_write(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        data_hex = self._require_str(arguments, "data_hex")
        return self._backend.write_bytes(session_id, address, data_hex)

    def _tool_memory_insert(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        data_hex = self._require_str(arguments, "data_hex")
        return self._backend.insert_bytes(session_id, address, data_hex)

    def _tool_memory_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        length = arguments.get("length")
        if address is None or not isinstance(length, int):
            raise BinjaBackendError("'address' and 'length' are required")
        return self._backend.remove_bytes(session_id, address, length)

    def _tool_memory_reader_read(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        width = arguments.get("width")
        if address is None or not isinstance(width, int):
            raise BinjaBackendError("'address' and 'width' are required")
        endian = arguments.get("endian", "little")
        if not isinstance(endian, str):
            raise BinjaBackendError("'endian' must be a string")
        return self._backend.reader_read(session_id, address, width, endian=endian)

    def _tool_memory_writer_write(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        width = arguments.get("width")
        value = arguments.get("value")
        if address is None or not isinstance(width, int) or not isinstance(value, int):
            raise BinjaBackendError("'address', 'width', and 'value' are required")
        endian = arguments.get("endian", "little")
        if not isinstance(endian, str):
            raise BinjaBackendError("'endian' must be a string")
        return self._backend.writer_write(session_id, address, width, value, endian=endian)

    def _tool_data_typed_at(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.typed_data_at(session_id, address)

    def _tool_disasm_function(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.disasm_function(session_id, address)

    def _tool_disasm_range(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")

        length = arguments.get("length")
        if not isinstance(length, int):
            raise BinjaBackendError("'length' must be an integer")

        limit = arguments.get("limit", 200)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")

        return self._backend.disasm_range(
            session_id,
            start,
            length=length,
            limit=limit,
        )

    def _tool_il_function(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")

        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")

        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")

        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 200)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")

        return self._backend.il_function(
            session_id,
            function_start,
            level=level,
            ssa=ssa,
            offset=offset,
            limit=limit,
        )

    def _tool_il_instruction_by_addr(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")

        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")

        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")

        return self._backend.il_instruction_by_addr(
            session_id,
            function_start,
            address,
            level=level,
            ssa=ssa,
        )

    def _tool_il_address_to_index(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")

        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")

        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")

        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")

        return self._backend.il_address_to_index(
            session_id,
            function_start,
            address,
            level=level,
            ssa=ssa,
        )

    def _tool_il_index_to_address(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")

        index = arguments.get("index")
        if not isinstance(index, int):
            raise BinjaBackendError("'index' must be an integer")

        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")

        ssa = arguments.get("ssa", False)
        if not isinstance(ssa, bool):
            raise BinjaBackendError("'ssa' must be a boolean")

        return self._backend.il_index_to_address(
            session_id,
            function_start,
            index,
            level=level,
            ssa=ssa,
        )

    def _tool_binja_call(self, arguments: dict[str, Any]) -> dict[str, Any]:
        target = self._require_str(arguments, "target")

        args = arguments.get("args", [])
        kwargs = arguments.get("kwargs", {})
        session_id = arguments.get("session_id")

        if not isinstance(args, list):
            raise BinjaBackendError("'args' must be an array")
        if not isinstance(kwargs, dict):
            raise BinjaBackendError("'kwargs' must be an object")
        if session_id is not None and not isinstance(session_id, str):
            raise BinjaBackendError("'session_id' must be a string when provided")

        return self._backend.call_api(
            target,
            args=args,
            kwargs=kwargs,
            session_id=session_id,
        )

    def _tool_binja_eval(self, arguments: dict[str, Any]) -> dict[str, Any]:
        code = self._require_str(arguments, "code")

        session_id = arguments.get("session_id")
        if session_id is not None and not isinstance(session_id, str):
            raise BinjaBackendError("'session_id' must be a string when provided")

        return self._backend.eval_code(code, session_id=session_id)

    def _tool_annotation_rename_function(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        new_name = self._require_str(arguments, "new_name")
        return self._backend.rename_function(session_id, function_start, new_name)

    def _tool_annotation_rename_symbol(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        new_name = self._require_str(arguments, "new_name")
        return self._backend.rename_symbol(session_id, address, new_name)

    def _tool_annotation_undefine_symbol(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.undefine_symbol(session_id, address)

    def _tool_annotation_define_symbol(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        name = self._require_str(arguments, "name")
        symbol_type = arguments.get("symbol_type", "FunctionSymbol")
        if not isinstance(symbol_type, str):
            raise BinjaBackendError("'symbol_type' must be a string")
        return self._backend.define_symbol(session_id, address, name, symbol_type=symbol_type)

    def _tool_annotation_rename_data_var(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        new_name = self._require_str(arguments, "new_name")
        return self._backend.rename_data_var(session_id, address, new_name)

    def _tool_annotation_define_data_var(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        type_name = arguments.get("type_name", "char")
        width = arguments.get("width", 1)
        name = arguments.get("name")
        if not isinstance(type_name, str):
            raise BinjaBackendError("'type_name' must be a string")
        if not isinstance(width, int):
            raise BinjaBackendError("'width' must be an integer")
        if name is not None and not isinstance(name, str):
            raise BinjaBackendError("'name' must be a string when provided")
        return self._backend.define_data_var(
            session_id,
            address,
            type_name=type_name,
            width=width,
            name=name,
        )

    def _tool_annotation_undefine_data_var(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.undefine_data_var(session_id, address)

    def _tool_annotation_set_comment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        comment = self._require_str(arguments, "comment")
        return self._backend.set_comment(session_id, address, comment)

    def _tool_annotation_get_comment(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.get_comment(session_id, address)

    def _tool_annotation_add_tag(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        tag_type = self._require_str(arguments, "tag_type")
        data = self._require_str(arguments, "data")
        icon = arguments.get("icon", "M")
        if not isinstance(icon, str):
            raise BinjaBackendError("'icon' must be a string")
        return self._backend.add_tag(session_id, address, tag_type, data, icon=icon)

    def _tool_annotation_get_tags(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.get_tags_at(session_id, address)

    def _tool_metadata_store(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        key = self._require_str(arguments, "key")
        if "value" not in arguments:
            raise BinjaBackendError("'value' is required")
        return self._backend.metadata_store(session_id, key, arguments["value"])

    def _tool_metadata_query(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        key = self._require_str(arguments, "key")
        return self._backend.metadata_query(session_id, key)

    def _tool_metadata_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        key = self._require_str(arguments, "key")
        return self._backend.metadata_remove(session_id, key)

    def _tool_function_metadata_store(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        key = self._require_str(arguments, "key")
        if "value" not in arguments:
            raise BinjaBackendError("'value' is required")
        return self._backend.function_metadata_store(
            session_id,
            function_start,
            key,
            arguments["value"],
        )

    def _tool_function_metadata_query(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        key = self._require_str(arguments, "key")
        return self._backend.function_metadata_query(session_id, function_start, key)

    def _tool_function_metadata_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        key = self._require_str(arguments, "key")
        return self._backend.function_metadata_remove(session_id, function_start, key)

    def _tool_patch_assemble(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        asm = self._require_str(arguments, "asm")
        return self._backend.patch_assemble(session_id, address, asm)

    def _tool_patch_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.patch_status(session_id, address)

    def _tool_patch_convert_to_nop(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.patch_convert_to_nop(session_id, address)

    def _tool_patch_always_branch(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.patch_always_branch(session_id, address)

    def _tool_patch_never_branch(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.patch_never_branch(session_id, address)

    def _tool_patch_invert_branch(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        return self._backend.patch_invert_branch(session_id, address)

    def _tool_patch_skip_and_return_value(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        value = arguments.get("value")
        if not isinstance(value, int):
            raise BinjaBackendError("'value' must be an integer")
        return self._backend.patch_skip_and_return_value(session_id, address, value)

    def _tool_undo_begin(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.undo_begin(session_id)

    def _tool_undo_commit(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        transaction_id = arguments.get("transaction_id")
        if transaction_id is not None and not isinstance(transaction_id, str):
            raise BinjaBackendError("'transaction_id' must be a string when provided")
        return self._backend.undo_commit(session_id, transaction_id)

    def _tool_undo_revert(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        transaction_id = arguments.get("transaction_id")
        if transaction_id is not None and not isinstance(transaction_id, str):
            raise BinjaBackendError("'transaction_id' must be a string when provided")
        return self._backend.undo_revert(session_id, transaction_id)

    def _tool_undo_undo(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.undo(session_id)

    def _tool_undo_redo(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.redo(session_id)

    def _tool_task_analysis_update(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.task_start_analysis_update(session_id)

    def _tool_task_search_text(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        query = self._require_str(arguments, "query")

        limit = arguments.get("limit", 50)
        if not isinstance(limit, int):
            raise BinjaBackendError("'limit' must be an integer")

        return self._backend.task_start_search_text(session_id, query, limit=limit)

    def _tool_task_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        task_id = self._require_str(arguments, "task_id")
        return self._backend.task_status(task_id)

    def _tool_task_result(self, arguments: dict[str, Any]) -> dict[str, Any]:
        task_id = self._require_str(arguments, "task_id")
        return self._backend.task_result(task_id)

    def _tool_task_cancel(self, arguments: dict[str, Any]) -> dict[str, Any]:
        task_id = self._require_str(arguments, "task_id")
        return self._backend.task_cancel(task_id)

    def _tool_database_create_bndb(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        path = self._require_str(arguments, "path")
        return self._backend.create_database(session_id, path)

    def _tool_database_save_auto_snapshot(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.save_auto_snapshot(session_id)

    def _tool_type_parse_string(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_source = self._require_str(arguments, "type_source")
        import_dependencies = arguments.get("import_dependencies", True)
        if not isinstance(import_dependencies, bool):
            raise BinjaBackendError("'import_dependencies' must be a boolean")
        return self._backend.type_parse_string(
            session_id,
            type_source,
            import_dependencies=import_dependencies,
        )

    def _tool_type_parse_declarations(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        declarations = self._require_str(arguments, "declarations")
        options = self._optional_str_list(arguments, "options")
        include_dirs = self._optional_str_list(arguments, "include_dirs")
        import_dependencies = arguments.get("import_dependencies", True)
        if not isinstance(import_dependencies, bool):
            raise BinjaBackendError("'import_dependencies' must be a boolean")
        return self._backend.type_parse_declarations(
            session_id,
            declarations,
            options=options,
            include_dirs=include_dirs,
            import_dependencies=import_dependencies,
        )

    def _tool_type_define_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_source = self._require_str(arguments, "type_source")
        name = self._optional_str(arguments, "name")
        import_dependencies = arguments.get("import_dependencies", True)
        if not isinstance(import_dependencies, bool):
            raise BinjaBackendError("'import_dependencies' must be a boolean")
        return self._backend.type_define_user(
            session_id,
            type_source,
            name=name,
            import_dependencies=import_dependencies,
        )

    def _tool_type_rename(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        old_name = self._require_str(arguments, "old_name")
        new_name = self._require_str(arguments, "new_name")
        return self._backend.type_rename(session_id, old_name, new_name)

    def _tool_type_undefine_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        return self._backend.type_undefine_user(session_id, name)

    def _tool_type_import_library_type(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        type_library_id = self._optional_str(arguments, "type_library_id")
        return self._backend.type_import_library_type(
            session_id,
            name,
            type_library_id=type_library_id,
        )

    def _tool_type_import_library_object(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        type_library_id = self._optional_str(arguments, "type_library_id")
        return self._backend.type_import_library_object(
            session_id,
            name,
            type_library_id=type_library_id,
        )

    def _tool_type_export_to_library(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_library_id = self._require_str(arguments, "type_library_id")
        type_source = self._require_str(arguments, "type_source")
        name = self._optional_str(arguments, "name")
        import_dependencies = arguments.get("import_dependencies", True)
        if not isinstance(import_dependencies, bool):
            raise BinjaBackendError("'import_dependencies' must be a boolean")
        return self._backend.type_export_to_library(
            session_id,
            type_library_id,
            type_source,
            name=name,
            import_dependencies=import_dependencies,
        )

    def _tool_type_library_create(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        path = self._optional_str(arguments, "path")
        add_to_view = arguments.get("add_to_view", True)
        if not isinstance(add_to_view, bool):
            raise BinjaBackendError("'add_to_view' must be a boolean")
        return self._backend.type_library_create(
            session_id,
            name,
            path=path,
            add_to_view=add_to_view,
        )

    def _tool_type_library_load(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        path = self._require_str(arguments, "path")
        add_to_view = arguments.get("add_to_view", True)
        if not isinstance(add_to_view, bool):
            raise BinjaBackendError("'add_to_view' must be a boolean")
        return self._backend.type_library_load(session_id, path, add_to_view=add_to_view)

    def _tool_type_library_list(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.type_library_list(session_id)

    def _tool_type_library_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_library_id = self._require_str(arguments, "type_library_id")
        return self._backend.type_library_get(session_id, type_library_id)

    def _tool_type_archive_create(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        path = self._require_str(arguments, "path")
        platform_name = self._optional_str(arguments, "platform_name")
        attach = arguments.get("attach", True)
        if not isinstance(attach, bool):
            raise BinjaBackendError("'attach' must be a boolean")
        return self._backend.type_archive_create(
            session_id,
            path,
            platform_name=platform_name,
            attach=attach,
        )

    def _tool_type_archive_open(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        path = self._require_str(arguments, "path")
        attach = arguments.get("attach", True)
        if not isinstance(attach, bool):
            raise BinjaBackendError("'attach' must be a boolean")
        return self._backend.type_archive_open(session_id, path, attach=attach)

    def _tool_type_archive_list(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.type_archive_list(session_id)

    def _tool_type_archive_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_archive_id = self._require_str(arguments, "type_archive_id")
        return self._backend.type_archive_get(session_id, type_archive_id)

    def _tool_type_archive_pull(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_archive_id = self._require_str(arguments, "type_archive_id")
        names = self._optional_str_list(arguments, "names")
        if not names:
            raise BinjaBackendError("'names' must be a non-empty string array")
        return self._backend.type_archive_pull(session_id, type_archive_id, names)

    def _tool_type_archive_push(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_archive_id = self._require_str(arguments, "type_archive_id")
        names = self._optional_str_list(arguments, "names")
        if not names:
            raise BinjaBackendError("'names' must be a non-empty string array")
        return self._backend.type_archive_push(session_id, type_archive_id, names)

    def _tool_type_archive_references(self, arguments: dict[str, Any]) -> dict[str, Any]:
        type_archive_id = self._require_str(arguments, "type_archive_id")
        name = self._require_str(arguments, "name")
        return self._backend.type_archive_references(type_archive_id, name)

    def _tool_debug_parsers(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.debug_list_parsers(session_id)

    def _tool_debug_parse_and_apply(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        debug_path = self._optional_str(arguments, "debug_path")
        parser_name = self._optional_str(arguments, "parser_name")
        return self._backend.debug_parse_and_apply(
            session_id,
            debug_path=debug_path,
            parser_name=parser_name,
        )

    def _tool_workflow_list(self, _: dict[str, Any]) -> dict[str, Any]:
        return self._backend.workflow_list()

    def _tool_workflow_describe(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        workflow_name = self._optional_str(arguments, "workflow_name")
        activity = arguments.get("activity", "")
        if not isinstance(activity, str):
            raise BinjaBackendError("'activity' must be a string")
        immediate = arguments.get("immediate", True)
        if not isinstance(immediate, bool):
            raise BinjaBackendError("'immediate' must be a boolean")
        return self._backend.workflow_describe(
            session_id,
            workflow_name=workflow_name,
            activity=activity,
            immediate=immediate,
        )

    def _tool_workflow_clone(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        register = arguments.get("register", False)
        if not isinstance(register, bool):
            raise BinjaBackendError("'register' must be a boolean")
        return self._backend.workflow_clone(session_id, name, register=register)

    def _tool_workflow_insert(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._tool_workflow_insert_common(arguments, after=False)

    def _tool_workflow_insert_after(self, arguments: dict[str, Any]) -> dict[str, Any]:
        return self._tool_workflow_insert_common(arguments, after=True)

    def _tool_workflow_insert_common(
        self,
        arguments: dict[str, Any],
        *,
        after: bool,
    ) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        workflow_name = self._optional_str(arguments, "workflow_name")
        activity = self._require_str(arguments, "activity")
        activities_raw = arguments.get("activities")
        if not isinstance(activities_raw, (str, list)):
            raise BinjaBackendError("'activities' must be a string or array of strings")
        if isinstance(activities_raw, list) and not all(
            isinstance(item, str) for item in activities_raw
        ):
            raise BinjaBackendError("'activities' list must only contain strings")
        return self._backend.workflow_insert(
            session_id,
            activity,
            activities_raw,
            workflow_name=workflow_name,
            after=after,
        )

    def _tool_workflow_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        workflow_name = self._optional_str(arguments, "workflow_name")
        activity = self._require_str(arguments, "activity")
        return self._backend.workflow_remove(
            session_id,
            activity,
            workflow_name=workflow_name,
        )

    def _tool_workflow_graph(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        workflow_name = self._optional_str(arguments, "workflow_name")
        activity = arguments.get("activity", "")
        if not isinstance(activity, str):
            raise BinjaBackendError("'activity' must be a string")
        sequential = arguments.get("sequential", False)
        if not isinstance(sequential, bool):
            raise BinjaBackendError("'sequential' must be a boolean")
        return self._backend.workflow_graph(
            session_id,
            workflow_name=workflow_name,
            activity=activity,
            sequential=sequential,
        )

    def _tool_workflow_machine_status(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        workflow_name = self._optional_str(arguments, "workflow_name")
        return self._backend.workflow_machine_status(session_id, workflow_name=workflow_name)

    def _tool_workflow_machine_control(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        action = self._require_str(arguments, "action")
        workflow_name = self._optional_str(arguments, "workflow_name")
        advanced = arguments.get("advanced", True)
        if not isinstance(advanced, bool):
            raise BinjaBackendError("'advanced' must be a boolean")
        incremental = arguments.get("incremental", False)
        if not isinstance(incremental, bool):
            raise BinjaBackendError("'incremental' must be a boolean")
        activities_raw = arguments.get("activities")
        if activities_raw is not None and not isinstance(activities_raw, (str, list)):
            raise BinjaBackendError("'activities' must be a string or array of strings")
        if isinstance(activities_raw, list) and not all(
            isinstance(item, str) for item in activities_raw
        ):
            raise BinjaBackendError("'activities' list must only contain strings")
        activity = self._optional_str(arguments, "activity")
        enable = self._optional_bool(arguments, "enable")
        return self._backend.workflow_machine_control(
            session_id,
            action,
            workflow_name=workflow_name,
            advanced=advanced,
            incremental=incremental,
            activities=activities_raw,
            activity=activity,
            enable=enable,
        )

    def _tool_il_rewrite_capabilities(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        return self._backend.il_rewrite_capabilities(
            session_id,
            function_start,
            level=level,
        )

    def _tool_il_rewrite_noop_replace(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        index = self._optional_int(arguments, "index")
        finalize = arguments.get("finalize", True)
        if not isinstance(finalize, bool):
            raise BinjaBackendError("'finalize' must be a boolean")
        generate_ssa_form = arguments.get("generate_ssa_form", True)
        if not isinstance(generate_ssa_form, bool):
            raise BinjaBackendError("'generate_ssa_form' must be a boolean")
        return self._backend.il_rewrite_noop_replace(
            session_id,
            function_start,
            level=level,
            index=index,
            finalize=finalize,
            generate_ssa_form=generate_ssa_form,
        )

    def _tool_il_rewrite_translate_identity(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        level = arguments.get("level", "mlil")
        if not isinstance(level, str):
            raise BinjaBackendError("'level' must be a string")
        return self._backend.il_translate_identity(session_id, function_start, level=level)

    def _tool_uidf_parse_possible_value(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        value = self._require_str(arguments, "value")
        state = self._require_str(arguments, "state")
        here = self._optional_int_or_str(arguments, "here")
        return self._backend.uidf_parse_possible_value(session_id, value, state, here=here)

    def _tool_uidf_set_user_var_value(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        variable_name = self._require_str(arguments, "variable_name")
        def_addr = self._optional_int_or_str(arguments, "def_addr")
        if def_addr is None:
            raise BinjaBackendError("'def_addr' is required")
        value = self._require_str(arguments, "value")
        state = self._require_str(arguments, "state")
        after = arguments.get("after", True)
        if not isinstance(after, bool):
            raise BinjaBackendError("'after' must be a boolean")
        return self._backend.uidf_set_user_var_value(
            session_id,
            function_start,
            variable_name,
            def_addr,
            value,
            state,
            after=after,
        )

    def _tool_uidf_clear_user_var_value(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        variable_name = self._require_str(arguments, "variable_name")
        def_addr = self._optional_int_or_str(arguments, "def_addr")
        if def_addr is None:
            raise BinjaBackendError("'def_addr' is required")
        after = arguments.get("after", True)
        if not isinstance(after, bool):
            raise BinjaBackendError("'after' must be a boolean")
        return self._backend.uidf_clear_user_var_value(
            session_id,
            function_start,
            variable_name,
            def_addr,
            after=after,
        )

    def _tool_uidf_list_user_var_values(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        function_start = self._optional_int_or_str(arguments, "function_start")
        if function_start is None:
            raise BinjaBackendError("'function_start' is required")
        return self._backend.uidf_list_user_var_values(session_id, function_start)

    def _tool_loader_rebase(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        if address is None:
            raise BinjaBackendError("'address' is required")
        force = arguments.get("force", False)
        if not isinstance(force, bool):
            raise BinjaBackendError("'force' must be a boolean")
        return self._backend.loader_rebase(session_id, address, force=force)

    def _tool_loader_load_settings_types(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.loader_load_settings_types(session_id)

    def _tool_loader_load_settings_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_name = self._require_str(arguments, "type_name")
        return self._backend.loader_load_settings_get(session_id, type_name)

    def _tool_loader_load_settings_set(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        type_name = self._require_str(arguments, "type_name")
        key = self._require_str(arguments, "key")
        if "value" not in arguments:
            raise BinjaBackendError("'value' is required")
        value = arguments["value"]
        value_type = arguments.get("value_type", "string")
        if not isinstance(value_type, str):
            raise BinjaBackendError("'value_type' must be a string")
        return self._backend.loader_load_settings_set(
            session_id,
            type_name,
            key,
            value,
            value_type=value_type,
        )

    def _tool_segment_add_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        length = self._optional_int(arguments, "length")
        if length is None:
            raise BinjaBackendError("'length' is required")
        data_offset = arguments.get("data_offset", 0)
        data_length = arguments.get("data_length", 0)
        readable = arguments.get("readable", True)
        writable = arguments.get("writable", False)
        executable = arguments.get("executable", False)
        contains_data = arguments.get("contains_data", True)
        contains_code = arguments.get("contains_code", False)
        bool_fields = {
            "readable": readable,
            "writable": writable,
            "executable": executable,
            "contains_data": contains_data,
            "contains_code": contains_code,
        }
        if not isinstance(data_offset, int) or not isinstance(data_length, int):
            raise BinjaBackendError("'data_offset' and 'data_length' must be integers")
        for field_name, field_value in bool_fields.items():
            if not isinstance(field_value, bool):
                raise BinjaBackendError(f"'{field_name}' must be a boolean")
        return self._backend.segment_add_user(
            session_id,
            start,
            length,
            data_offset=data_offset,
            data_length=data_length,
            readable=readable,
            writable=writable,
            executable=executable,
            contains_data=contains_data,
            contains_code=contains_code,
        )

    def _tool_segment_remove_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        length = arguments.get("length", 0)
        if not isinstance(length, int):
            raise BinjaBackendError("'length' must be an integer")
        return self._backend.segment_remove_user(session_id, start, length=length)

    def _tool_section_add_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        start = self._optional_int_or_str(arguments, "start")
        if start is None:
            raise BinjaBackendError("'start' is required")
        length = self._optional_int(arguments, "length")
        if length is None:
            raise BinjaBackendError("'length' is required")
        semantics = arguments.get("semantics", "DefaultSectionSemantics")
        if not isinstance(semantics, str):
            raise BinjaBackendError("'semantics' must be a string")
        type_name = arguments.get("type_name", "")
        if not isinstance(type_name, str):
            raise BinjaBackendError("'type_name' must be a string")
        align = arguments.get("align", 1)
        entry_size = arguments.get("entry_size", 1)
        if not isinstance(align, int) or not isinstance(entry_size, int):
            raise BinjaBackendError("'align' and 'entry_size' must be integers")
        return self._backend.section_add_user(
            session_id,
            name,
            start,
            length,
            semantics=semantics,
            type_name=type_name,
            align=align,
            entry_size=entry_size,
        )

    def _tool_section_remove_user(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        return self._backend.section_remove_user(session_id, name)

    def _tool_external_library_add(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        auto = arguments.get("auto", False)
        if not isinstance(auto, bool):
            raise BinjaBackendError("'auto' must be a boolean")
        return self._backend.external_library_add(session_id, name, auto=auto)

    def _tool_external_library_list(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.external_library_list(session_id)

    def _tool_external_library_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        return self._backend.external_library_remove(session_id, name)

    def _tool_external_location_add(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        source_address = self._optional_int_or_str(arguments, "source_address")
        if source_address is None:
            raise BinjaBackendError("'source_address' is required")
        library_name = self._optional_str(arguments, "library_name")
        target_symbol = self._optional_str(arguments, "target_symbol")
        target_address = self._optional_int_or_str(arguments, "target_address")
        auto = arguments.get("auto", False)
        if not isinstance(auto, bool):
            raise BinjaBackendError("'auto' must be a boolean")
        return self._backend.external_location_add(
            session_id,
            source_address,
            library_name=library_name,
            target_symbol=target_symbol,
            target_address=target_address,
            auto=auto,
        )

    def _tool_external_location_get(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        source_address = self._optional_int_or_str(arguments, "source_address")
        if source_address is None:
            raise BinjaBackendError("'source_address' is required")
        return self._backend.external_location_get(session_id, source_address)

    def _tool_external_location_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        source_address = self._optional_int_or_str(arguments, "source_address")
        if source_address is None:
            raise BinjaBackendError("'source_address' is required")
        return self._backend.external_location_remove(session_id, source_address)

    def _tool_arch_info(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.arch_info(session_id)

    def _tool_arch_disasm_bytes(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        data_hex = self._require_str(arguments, "data_hex")
        address = arguments.get("address", 0)
        if not isinstance(address, (int, str)):
            raise BinjaBackendError("'address' must be an integer or string")
        arch_name = self._optional_str(arguments, "arch_name")
        return self._backend.arch_disasm_bytes(
            session_id,
            data_hex,
            address=address,
            arch_name=arch_name,
        )

    def _tool_arch_assemble(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        asm = self._require_str(arguments, "asm")
        address = arguments.get("address", 0)
        if not isinstance(address, (int, str)):
            raise BinjaBackendError("'address' must be an integer or string")
        arch_name = self._optional_str(arguments, "arch_name")
        return self._backend.arch_assemble(
            session_id,
            asm,
            address=address,
            arch_name=arch_name,
        )

    def _tool_transform_inspect(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._optional_str(arguments, "session_id")
        path = self._optional_str(arguments, "path")
        if session_id is None and path is None:
            raise BinjaBackendError("'session_id' or 'path' is required")
        mode = arguments.get("mode", "full")
        if not isinstance(mode, str):
            raise BinjaBackendError("'mode' must be a string")
        process = arguments.get("process", False)
        if not isinstance(process, bool):
            raise BinjaBackendError("'process' must be a boolean")
        return self._backend.transform_inspect(
            session_id=session_id,
            path=path,
            mode=mode,
            process=process,
        )

    def _tool_project_create(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._require_str(arguments, "path")
        name = self._require_str(arguments, "name")
        return self._backend.project_create(path, name)

    def _tool_project_open(self, arguments: dict[str, Any]) -> dict[str, Any]:
        path = self._require_str(arguments, "path")
        return self._backend.project_open(path)

    def _tool_project_close(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        return self._backend.project_close(project_id)

    def _tool_project_list(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        return self._backend.project_list(project_id)

    def _tool_project_create_folder(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        name = self._require_str(arguments, "name")
        parent_folder_id = self._optional_str(arguments, "parent_folder_id")
        description = arguments.get("description", "")
        if not isinstance(description, str):
            raise BinjaBackendError("'description' must be a string")
        return self._backend.project_create_folder(
            project_id,
            name,
            parent_folder_id=parent_folder_id,
            description=description,
        )

    def _tool_project_create_file(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        name = self._require_str(arguments, "name")
        data_base64 = self._require_str(arguments, "data_base64")
        folder_id = self._optional_str(arguments, "folder_id")
        description = arguments.get("description", "")
        if not isinstance(description, str):
            raise BinjaBackendError("'description' must be a string")
        return self._backend.project_create_file(
            project_id,
            name,
            data_base64,
            folder_id=folder_id,
            description=description,
        )

    def _tool_project_metadata_store(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        key = self._require_str(arguments, "key")
        if "value" not in arguments:
            raise BinjaBackendError("'value' is required")
        value = arguments["value"]
        return self._backend.project_metadata_store(project_id, key, value)

    def _tool_project_metadata_query(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        key = self._require_str(arguments, "key")
        return self._backend.project_metadata_query(project_id, key)

    def _tool_project_metadata_remove(self, arguments: dict[str, Any]) -> dict[str, Any]:
        project_id = self._require_str(arguments, "project_id")
        key = self._require_str(arguments, "key")
        return self._backend.project_metadata_remove(project_id, key)

    def _tool_database_info(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.database_info(session_id)

    def _tool_database_snapshots(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        offset = arguments.get("offset", 0)
        limit = arguments.get("limit", 100)
        if not isinstance(offset, int) or not isinstance(limit, int):
            raise BinjaBackendError("'offset' and 'limit' must be integers")
        return self._backend.database_list_snapshots(session_id, offset=offset, limit=limit)

    def _tool_database_read_global(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        key = self._require_str(arguments, "key")
        return self._backend.database_read_global(session_id, key)

    def _tool_database_write_global(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        key = self._require_str(arguments, "key")
        value = self._require_str(arguments, "value")
        return self._backend.database_write_global(session_id, key, value)

    def _tool_plugin_valid_commands(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        address = self._optional_int_or_str(arguments, "address")
        length = arguments.get("length", 0)
        if not isinstance(length, int):
            raise BinjaBackendError("'length' must be an integer")
        return self._backend.plugin_list_valid(
            session_id,
            address=address,
            length=length,
        )

    def _tool_plugin_execute(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        name = self._require_str(arguments, "name")
        address = self._optional_int_or_str(arguments, "address")
        length = arguments.get("length", 0)
        if not isinstance(length, int):
            raise BinjaBackendError("'length' must be an integer")
        perform = arguments.get("perform", False)
        if not isinstance(perform, bool):
            raise BinjaBackendError("'perform' must be a boolean")
        return self._backend.plugin_execute(
            session_id,
            name,
            address=address,
            length=length,
            perform=perform,
        )

    def _tool_plugin_repo_status(self, _: dict[str, Any]) -> dict[str, Any]:
        return self._backend.plugin_repo_status()

    def _tool_plugin_repo_check_updates(self, arguments: dict[str, Any]) -> dict[str, Any]:
        perform = arguments.get("perform", False)
        if not isinstance(perform, bool):
            raise BinjaBackendError("'perform' must be a boolean")
        return self._backend.plugin_repo_check_updates(perform=perform)

    def _tool_plugin_repo_plugin_action(self, arguments: dict[str, Any]) -> dict[str, Any]:
        repository_path = self._require_str(arguments, "repository_path")
        plugin_path = self._require_str(arguments, "plugin_path")
        action = self._require_str(arguments, "action")
        return self._backend.plugin_repo_plugin_action(repository_path, plugin_path, action)

    def _tool_baseaddr_detect(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        arch_name = self._optional_str(arguments, "arch_name")
        analysis = arguments.get("analysis", "full")
        if not isinstance(analysis, str):
            raise BinjaBackendError("'analysis' must be a string")
        min_strlen = arguments.get("min_strlen", 10)
        alignment = arguments.get("alignment", 1024)
        low_boundary = arguments.get("low_boundary", 0)
        high_boundary = arguments.get("high_boundary", 0xFFFFFFFFFFFFFFFF)
        max_pointers = arguments.get("max_pointers", 128)
        int_fields = [min_strlen, alignment, low_boundary, high_boundary, max_pointers]
        if not all(isinstance(field, int) for field in int_fields):
            raise BinjaBackendError(
                "'min_strlen', 'alignment', 'low_boundary', 'high_boundary', and "
                "'max_pointers' must be integers"
            )
        return self._backend.base_address_detect(
            session_id,
            arch_name=arch_name,
            analysis=analysis,
            min_strlen=min_strlen,
            alignment=alignment,
            low_boundary=low_boundary,
            high_boundary=high_boundary,
            max_pointers=max_pointers,
        )

    def _tool_baseaddr_reasons(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        base_address = self._optional_int_or_str(arguments, "base_address")
        if base_address is None:
            raise BinjaBackendError("'base_address' is required")
        return self._backend.base_address_reasons(session_id, base_address)

    def _tool_baseaddr_abort(self, arguments: dict[str, Any]) -> dict[str, Any]:
        session_id = self._require_str(arguments, "session_id")
        return self._backend.base_address_abort(session_id)
