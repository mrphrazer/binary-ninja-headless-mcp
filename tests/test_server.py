from __future__ import annotations

import json
import time
from io import StringIO
from pathlib import Path
from typing import Any

from binary_ninja_headless_mcp.server import SimpleMcpServer


def _call_tool(
    server: SimpleMcpServer,
    name: str,
    arguments: dict[str, Any] | None = None,
    request_id: int = 1,
) -> dict[str, Any]:
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}},
        }
    )
    assert response is not None
    assert "error" not in response
    return response["result"]


def _find_function_start(items: list[dict[str, Any]], name: str) -> str:
    for item in items:
        if item.get("name") == name:
            start = item.get("start")
            assert isinstance(start, str)
            return start
    raise AssertionError(f"function not found: {name}")


def _wait_task(server: SimpleMcpServer, task_id: str, timeout: float = 10.0) -> dict[str, Any]:
    deadline = time.time() + timeout
    request_id = 1000

    while time.time() < deadline:
        request_id += 1
        status = _call_tool(server, "task.status", {"task_id": task_id}, request_id=request_id)
        structured = status["structuredContent"]
        if structured["status"] in {"completed", "failed", "cancelled"}:
            return structured
        time.sleep(0.05)

    raise AssertionError(f"task did not complete: {task_id}")


def _open_session(
    server: SimpleMcpServer,
    sample_binary_path: str,
    *,
    read_only: bool,
    request_id: int,
) -> str:
    opened = _call_tool(
        server,
        "session.open",
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": read_only,
            "deterministic": True,
        },
        request_id=request_id,
    )
    session_id = opened["structuredContent"]["session_id"]
    assert isinstance(session_id, str)
    return session_id


def test_initialize_and_tools_list(real_server: SimpleMcpServer) -> None:
    init_response = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        }
    )
    assert init_response is not None
    assert init_response["result"]["serverInfo"]["name"] == "binary_ninja_headless_mcp"

    listed = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 500},
        }
    )
    assert listed is not None
    assert listed["result"]["total"] >= len(listed["result"]["tools"])
    names = {tool["name"] for tool in listed["result"]["tools"]}
    expected = {
        "health.ping",
        "binja.info",
        "session.open",
        "session.close",
        "session.list",
        "session.mode",
        "session.set_mode",
        "analysis.status",
        "analysis.progress",
        "analysis.update",
        "analysis.update_and_wait",
        "analysis.abort",
        "analysis.set_hold",
        "binary.summary",
        "binary.save",
        "binary.functions",
        "binary.strings",
        "binary.search_text",
        "binary.sections",
        "binary.segments",
        "binary.symbols",
        "binary.data_vars",
        "binary.get_function_at",
        "binary.get_function_disassembly_at",
        "binary.get_function_il_at",
        "xref.code_refs_to",
        "xref.code_refs_from",
        "xref.data_refs_to",
        "xref.data_refs_from",
        "function.callers",
        "function.callees",
        "disasm.function",
        "disasm.range",
        "il.function",
        "il.instruction_by_addr",
        "il.address_to_index",
        "il.index_to_address",
        "binja.call",
        "binja.eval",
        "task.analysis_update",
        "task.search_text",
        "task.status",
        "task.result",
        "task.cancel",
        "database.create_bndb",
        "database.save_auto_snapshot",
    }
    assert expected.issubset(names)


def test_tools_list_supports_filtering_and_pagination(real_server: SimpleMcpServer) -> None:
    first_page = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 10},
        }
    )
    assert first_page is not None
    assert len(first_page["result"]["tools"]) == 10
    assert first_page["result"]["total"] >= 10
    assert first_page["result"]["has_more"] is True
    assert first_page["result"]["next_offset"] == 10
    assert "truncated" in first_page["result"]["notice"]

    filtered = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {"prefix": "binary.", "offset": 0, "limit": 100},
        }
    )
    assert filtered is not None
    filtered_tools = filtered["result"]["tools"]
    assert filtered_tools
    assert all(tool["name"].startswith("binary.") for tool in filtered_tools)


def test_tools_list_without_explicit_pagination_returns_full_catalog(
    real_server: SimpleMcpServer,
) -> None:
    listed = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/list",
            "params": {},
        }
    )
    assert listed is not None
    assert len(listed["result"]["tools"]) == listed["result"]["total"]
    assert listed["result"]["has_more"] is False

    names = {tool["name"] for tool in listed["result"]["tools"]}
    assert "analysis.status" in names
    assert "analysis.update_and_wait" in names
    assert "binja.call" in names
    assert "binja.eval" in names


def test_tool_result_text_is_compact_summary(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    opened = _call_tool(
        real_server,
        "session.open",
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": True,
            "deterministic": True,
        },
        request_id=6,
    )
    open_text = opened["content"][0]["text"]
    assert isinstance(open_text, str)
    assert open_text.startswith("ok")
    assert not open_text.startswith("{")

    session_id = opened["structuredContent"]["session_id"]
    eval_result = _call_tool(
        real_server,
        "binja.eval",
        {"session_id": session_id, "code": "bv.entry_point"},
        request_id=7,
    )
    assert eval_result["isError"] is False
    assert eval_result["structuredContent"]["mode_transitioned"] is True
    assert eval_result["structuredContent"]["transitioned_session_ids"] == [session_id]
    eval_text = eval_result["content"][0]["text"]
    assert isinstance(eval_text, str)
    assert eval_text.startswith("ok")


def test_session_analysis_and_binary_tools(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_session(real_server, sample_binary_path, read_only=False, request_id=10)

    mode = _call_tool(real_server, "session.mode", {"session_id": session_id}, request_id=11)
    assert mode["structuredContent"]["read_only"] is False

    listed = _call_tool(real_server, "session.list", request_id=12)
    assert listed["structuredContent"]["count"] >= 1

    summary = _call_tool(
        real_server,
        "binary.summary",
        {"session_id": session_id},
        request_id=13,
    )
    assert summary["structuredContent"]["filename"] == sample_binary_path

    _call_tool(real_server, "analysis.status", {"session_id": session_id}, request_id=14)
    _call_tool(real_server, "analysis.update", {"session_id": session_id}, request_id=15)
    _call_tool(real_server, "analysis.update_and_wait", {"session_id": session_id}, request_id=16)
    _call_tool(real_server, "analysis.progress", {"session_id": session_id}, request_id=17)

    hold = _call_tool(
        real_server,
        "analysis.set_hold",
        {"session_id": session_id, "hold": True},
        request_id=18,
    )
    assert hold["structuredContent"]["hold"] is True
    _call_tool(
        real_server,
        "analysis.set_hold",
        {"session_id": session_id, "hold": False},
        request_id=19,
    )

    functions = _call_tool(
        real_server,
        "binary.functions",
        {"session_id": session_id, "offset": 0, "limit": 200},
        request_id=20,
    )
    assert functions["structuredContent"]["total"] >= 1

    _call_tool(
        real_server,
        "binary.strings",
        {"session_id": session_id, "offset": 0, "limit": 20},
        request_id=21,
    )
    _call_tool(
        real_server,
        "binary.sections",
        {"session_id": session_id, "offset": 0, "limit": 20},
        request_id=22,
    )
    _call_tool(
        real_server,
        "binary.segments",
        {"session_id": session_id, "offset": 0, "limit": 20},
        request_id=23,
    )
    _call_tool(
        real_server,
        "binary.symbols",
        {"session_id": session_id, "offset": 0, "limit": 20},
        request_id=24,
    )
    _call_tool(
        real_server,
        "binary.data_vars",
        {"session_id": session_id, "offset": 0, "limit": 20},
        request_id=25,
    )

    entry = summary["structuredContent"]["entry_point"]
    function_at = _call_tool(
        real_server,
        "binary.get_function_at",
        {"session_id": session_id, "address": entry},
        request_id=26,
    )
    assert function_at["structuredContent"]["function"]["start"].startswith("0x")

    search = _call_tool(
        real_server,
        "binary.search_text",
        {"session_id": session_id, "query": "Hello", "limit": 10},
        request_id=27,
    )
    assert search["structuredContent"]["count"] >= 1

    saved_path = tmp_path / "hello.saved"
    saved = _call_tool(
        real_server,
        "binary.save",
        {"session_id": session_id, "path": str(saved_path)},
        request_id=270,
    )
    assert saved["structuredContent"]["saved"] is True
    assert saved_path.exists()

    closed = _call_tool(real_server, "session.close", {"session_id": session_id}, request_id=28)
    assert closed["structuredContent"]["closed"] is True


def test_xref_disasm_il_and_eval_tools(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    session_id = _open_session(real_server, sample_binary_path, read_only=False, request_id=30)
    _call_tool(real_server, "analysis.update_and_wait", {"session_id": session_id}, request_id=31)

    functions = _call_tool(
        real_server,
        "binary.functions",
        {"session_id": session_id, "offset": 0, "limit": 200},
        request_id=32,
    )
    function_items = functions["structuredContent"]["items"]
    main_start = _find_function_start(function_items, "main")
    add_start = _find_function_start(function_items, "add_numbers")

    callers = _call_tool(
        real_server,
        "function.callers",
        {"session_id": session_id, "function_start": add_start},
        request_id=33,
    )
    assert callers["structuredContent"]["count"] >= 1

    callees = _call_tool(
        real_server,
        "function.callees",
        {"session_id": session_id, "function_start": main_start},
        request_id=34,
    )
    assert callees["structuredContent"]["count"] >= 1

    refs_to = _call_tool(
        real_server,
        "xref.code_refs_to",
        {"session_id": session_id, "address": add_start, "offset": 0, "limit": 20},
        request_id=35,
    )
    assert refs_to["structuredContent"]["total"] >= 1

    ref_from = refs_to["structuredContent"]["items"][0]["from"]
    refs_from = _call_tool(
        real_server,
        "xref.code_refs_from",
        {"session_id": session_id, "address": ref_from, "length": 4},
        request_id=36,
    )
    assert refs_from["structuredContent"]["count"] >= 1

    _call_tool(
        real_server,
        "xref.data_refs_to",
        {"session_id": session_id, "address": "0x400860"},
        request_id=37,
    )
    _call_tool(
        real_server,
        "xref.data_refs_from",
        {"session_id": session_id, "address": main_start, "length": 4},
        request_id=38,
    )

    disasm_function = _call_tool(
        real_server,
        "disasm.function",
        {"session_id": session_id, "address": int(main_start, 0) + 1},
        request_id=39,
    )
    assert disasm_function["structuredContent"]["total"] >= 1
    assert disasm_function["structuredContent"]["function"]["start"] == main_start
    assert disasm_function["structuredContent"]["total"] == len(
        disasm_function["structuredContent"]["items"]
    )

    disasm_at = _call_tool(
        real_server,
        "binary.get_function_disassembly_at",
        {"session_id": session_id, "address": int(main_start, 0) + 2},
        request_id=390,
    )
    assert disasm_at["structuredContent"]["function"]["start"] == main_start

    il_at = _call_tool(
        real_server,
        "binary.get_function_il_at",
        {
            "session_id": session_id,
            "address": int(main_start, 0) + 3,
            "level": "hlil",
        },
        request_id=391,
    )
    assert il_at["structuredContent"]["function"]["start"] == main_start
    assert il_at["structuredContent"]["level"] == "hlil"
    assert il_at["structuredContent"]["total"] == len(il_at["structuredContent"]["items"])

    disasm_range = _call_tool(
        real_server,
        "disasm.range",
        {"session_id": session_id, "start": main_start, "length": 16, "limit": 10},
        request_id=40,
    )
    assert disasm_range["structuredContent"]["count"] >= 1

    il_function = _call_tool(
        real_server,
        "il.function",
        {
            "session_id": session_id,
            "function_start": main_start,
            "level": "mlil",
            "ssa": False,
            "offset": 0,
            "limit": 20,
        },
        request_id=41,
    )
    first_il = il_function["structuredContent"]["items"][0]

    il_by_addr = _call_tool(
        real_server,
        "il.instruction_by_addr",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": first_il["address"],
            "level": "mlil",
            "ssa": False,
        },
        request_id=42,
    )
    assert il_by_addr["structuredContent"]["instruction"]["address"] == first_il["address"]

    addr_to_index = _call_tool(
        real_server,
        "il.address_to_index",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": first_il["address"],
            "level": "mlil",
            "ssa": False,
        },
        request_id=43,
    )
    assert first_il["index"] in addr_to_index["structuredContent"]["indices"]

    index_to_addr = _call_tool(
        real_server,
        "il.index_to_address",
        {
            "session_id": session_id,
            "function_start": main_start,
            "index": first_il["index"],
            "level": "mlil",
            "ssa": False,
        },
        request_id=44,
    )
    assert index_to_addr["structuredContent"]["address"] == first_il["address"]

    call_api = _call_tool(real_server, "binja.call", {"target": "bn.core_version"}, request_id=45)
    assert isinstance(call_api["structuredContent"]["result"], str)

    evaluated = _call_tool(
        real_server,
        "binja.eval",
        {"session_id": session_id, "code": "bv.entry_point"},
        request_id=46,
    )
    assert isinstance(evaluated["structuredContent"]["result"], int)

    _call_tool(real_server, "session.close", {"session_id": session_id}, request_id=47)


def test_task_and_database_tools(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_session(real_server, sample_binary_path, read_only=False, request_id=60)

    task_search = _call_tool(
        real_server,
        "task.search_text",
        {"session_id": session_id, "query": "Hello", "limit": 10},
        request_id=61,
    )
    task_search_id = task_search["structuredContent"]["task_id"]
    search_status = _wait_task(real_server, task_search_id)
    assert search_status["status"] == "completed"

    task_search_result = _call_tool(
        real_server,
        "task.result",
        {"task_id": task_search_id},
        request_id=62,
    )
    assert task_search_result["structuredContent"]["result"]["count"] >= 1

    task_analysis = _call_tool(
        real_server,
        "task.analysis_update",
        {"session_id": session_id},
        request_id=63,
    )
    task_analysis_id = task_analysis["structuredContent"]["task_id"]
    analysis_status = _wait_task(real_server, task_analysis_id)
    assert analysis_status["status"] == "completed"

    cancel_result = _call_tool(
        real_server,
        "task.cancel",
        {"task_id": task_search_id},
        request_id=64,
    )
    assert cancel_result["structuredContent"]["cancel_requested"] is False
    assert cancel_result["structuredContent"]["status"] == "completed"

    bndb_path = tmp_path / "hello-server.bndb"
    created = _call_tool(
        real_server,
        "database.create_bndb",
        {"session_id": session_id, "path": str(bndb_path)},
        request_id=65,
    )
    assert created["structuredContent"]["created"] is True

    snapshot = _call_tool(
        real_server,
        "database.save_auto_snapshot",
        {"session_id": session_id},
        request_id=66,
    )
    assert snapshot["structuredContent"]["saved"] is True

    reopened_session_id = _open_session(
        real_server,
        str(bndb_path),
        read_only=True,
        request_id=67,
    )
    _call_tool(real_server, "session.close", {"session_id": reopened_session_id}, request_id=68)
    _call_tool(real_server, "session.close", {"session_id": session_id}, request_id=69)


def test_binja_eval_transitions_read_only_session_mode(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    session_id = _open_session(real_server, sample_binary_path, read_only=True, request_id=80)

    result = _call_tool(
        real_server,
        "binja.eval",
        {"session_id": session_id, "code": "bv.entry_point"},
        request_id=81,
    )
    assert result["isError"] is False
    assert result["structuredContent"]["mode_transitioned"] is True
    assert result["structuredContent"]["transitioned_session_ids"] == [session_id]

    mode = _call_tool(real_server, "session.mode", {"session_id": session_id}, request_id=82)
    assert mode["structuredContent"]["read_only"] is False


def test_request_errors_and_notification(real_server: SimpleMcpServer) -> None:
    not_found = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "does.not.exist",
            "params": {},
        }
    )
    assert not_found is not None
    assert not_found["error"]["code"] == -32601

    unknown_tool = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        }
    )
    assert unknown_tool is not None
    assert unknown_tool["error"]["code"] == -32601

    assert (
        real_server.handle_request(
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}
        )
        is None
    )


def test_json_line_parser_and_stdio_loop(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    malformed = real_server.handle_json_line("not json")
    malformed_payload = json.loads(malformed or "{}")
    assert malformed_payload["error"]["code"] == -32700

    request_lines = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "session.open",
                        "arguments": {
                            "path": sample_binary_path,
                            "update_analysis": False,
                            "read_only": True,
                            "deterministic": True,
                        },
                    },
                }
            ),
        ]
    )
    input_stream = StringIO(request_lines)
    output_stream = StringIO()

    real_server.serve_stdio(input_stream=input_stream, output_stream=output_stream)

    out_lines = [line for line in output_stream.getvalue().splitlines() if line.strip()]
    assert len(out_lines) == 2
    first = json.loads(out_lines[0])
    second = json.loads(out_lines[1])
    assert first["result"]["serverInfo"]["name"] == "binary_ninja_headless_mcp"
    assert second["result"]["structuredContent"]["filename"] == sample_binary_path
