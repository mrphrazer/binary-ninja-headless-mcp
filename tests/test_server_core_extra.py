from __future__ import annotations

import base64
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


def _open_rw(server: SimpleMcpServer, sample_binary_path: str, request_id: int) -> str:
    opened = _call_tool(
        server,
        "session.open",
        {
            "path": sample_binary_path,
            "update_analysis": False,
            "read_only": False,
            "deterministic": True,
        },
        request_id=request_id,
    )
    session_id = opened["structuredContent"]["session_id"]
    assert isinstance(session_id, str)
    return session_id


def _find_function_start(items: list[dict[str, Any]], name: str) -> str:
    for item in items:
        if item.get("name") == name:
            start = item.get("start")
            if isinstance(start, str):
                return start
    raise AssertionError(f"function not found: {name}")


def test_tools_list_includes_new_core_tooling(real_server: SimpleMcpServer) -> None:
    listed = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 500},
        }
    )
    assert listed is not None

    names = {tool["name"] for tool in listed["result"]["tools"]}
    expected = {
        "session.open_bytes",
        "session.open_existing",
        "binary.functions_at",
        "binary.basic_blocks_at",
        "function.basic_blocks",
        "disasm.linear",
        "search.data",
        "search.next_text",
        "search.all_text",
        "search.next_data",
        "search.all_data",
        "search.next_constant",
        "search.all_constant",
        "function.variables",
        "function.var_refs",
        "value.reg",
        "value.stack",
        "value.possible",
        "memory.read",
        "memory.write",
        "memory.insert",
        "memory.remove",
        "data.typed_at",
        "annotation.rename_function",
        "annotation.rename_symbol",
        "annotation.undefine_symbol",
        "annotation.define_symbol",
        "annotation.rename_data_var",
        "annotation.define_data_var",
        "annotation.undefine_data_var",
        "annotation.set_comment",
        "annotation.get_comment",
        "annotation.add_tag",
        "annotation.get_tags",
        "metadata.store",
        "metadata.query",
        "metadata.remove",
        "patch.assemble",
        "patch.status",
        "patch.convert_to_nop",
        "patch.always_branch",
        "patch.never_branch",
        "patch.invert_branch",
        "patch.skip_and_return_value",
        "undo.begin",
        "undo.commit",
        "undo.revert",
        "undo.undo",
        "undo.redo",
    }
    assert expected.issubset(names)


def test_transform_inspect_schema_and_validation(real_server: SimpleMcpServer) -> None:
    listed = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {"offset": 0, "limit": 500},
        }
    )
    assert listed is not None

    tool = next(
        item for item in listed["result"]["tools"] if item.get("name") == "transform.inspect"
    )
    schema = tool["inputSchema"]
    # oneOf removed from top-level schema for Claude API compatibility;
    # the server-side handler still validates that session_id or path is provided.
    assert "oneOf" not in schema
    assert "session_id" in schema["properties"]
    assert "path" in schema["properties"]

    response = real_server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "transform.inspect", "arguments": {}},
        }
    )
    assert response is not None
    assert "error" not in response
    assert response["result"]["isError"] is True
    assert response["result"]["structuredContent"]["error"] == "'session_id' or 'path' is required"


def test_session_bytes_existing_navigation_and_search(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    with open(sample_binary_path, "rb") as handle:
        data_base64 = base64.b64encode(handle.read()).decode("ascii")

    session_from_bytes = _call_tool(
        real_server,
        "session.open_bytes",
        {
            "data_base64": data_base64,
            "filename": "hello-bytes",
            "update_analysis": False,
            "read_only": True,
        },
        request_id=10,
    )
    assert session_from_bytes["structuredContent"]["function_count"] >= 1

    source_session_id = _open_rw(real_server, sample_binary_path, request_id=11)
    session_existing = _call_tool(
        real_server,
        "session.open_existing",
        {
            "source_session_id": source_session_id,
            "read_only": True,
            "update_analysis": False,
        },
        request_id=12,
    )
    assert session_existing["structuredContent"]["function_count"] >= 1

    _call_tool(
        real_server,
        "analysis.update_and_wait",
        {"session_id": source_session_id},
        request_id=13,
    )

    summary = _call_tool(
        real_server,
        "binary.summary",
        {"session_id": source_session_id},
        request_id=14,
    )
    start = summary["structuredContent"]["start"]
    end = summary["structuredContent"]["end"]

    functions = _call_tool(
        real_server,
        "binary.functions",
        {"session_id": source_session_id, "offset": 0, "limit": 200},
        request_id=15,
    )
    main_start = _find_function_start(functions["structuredContent"]["items"], "main")

    functions_at = _call_tool(
        real_server,
        "binary.functions_at",
        {"session_id": source_session_id, "address": main_start},
        request_id=16,
    )
    assert functions_at["structuredContent"]["count"] >= 1

    blocks_at = _call_tool(
        real_server,
        "binary.basic_blocks_at",
        {"session_id": source_session_id, "address": main_start, "offset": 0, "limit": 1},
        request_id=17,
    )
    assert blocks_at["structuredContent"]["count"] == 1
    assert blocks_at["structuredContent"]["total"] >= 1

    function_blocks = _call_tool(
        real_server,
        "function.basic_blocks",
        {"session_id": source_session_id, "function_start": main_start, "offset": 0, "limit": 1},
        request_id=18,
    )
    assert function_blocks["structuredContent"]["count"] == 1
    assert function_blocks["structuredContent"]["total"] >= 1

    linear = _call_tool(
        real_server,
        "disasm.linear",
        {"session_id": source_session_id, "offset": 0, "limit": 20},
        request_id=19,
    )
    assert linear["structuredContent"]["total"] >= 1

    search_data = _call_tool(
        real_server,
        "search.data",
        {
            "session_id": source_session_id,
            "data_hex": "48656c6c6f",
            "start": start,
            "end": end,
            "limit": 10,
        },
        request_id=20,
    )
    assert search_data["structuredContent"]["count"] >= 1

    _call_tool(
        real_server,
        "search.next_text",
        {"session_id": source_session_id, "start": start, "query": "Hello"},
        request_id=21,
    )
    _call_tool(
        real_server,
        "search.all_text",
        {
            "session_id": source_session_id,
            "start": start,
            "end": end,
            "query": "Hello",
            "limit": 10,
        },
        request_id=22,
    )
    _call_tool(
        real_server,
        "search.next_data",
        {"session_id": source_session_id, "start": start, "data_hex": "48656c6c6f"},
        request_id=23,
    )
    _call_tool(
        real_server,
        "search.all_data",
        {
            "session_id": source_session_id,
            "start": start,
            "end": end,
            "data_hex": "48656c6c6f",
            "limit": 10,
        },
        request_id=24,
    )
    _call_tool(
        real_server,
        "search.next_constant",
        {"session_id": source_session_id, "start": start, "constant": 1},
        request_id=25,
    )
    _call_tool(
        real_server,
        "search.all_constant",
        {
            "session_id": source_session_id,
            "start": start,
            "end": end,
            "constant": 1,
            "limit": 10,
        },
        request_id=26,
    )


def test_values_memory_annotations_patch_and_undo_tools(  # noqa: PLR0915
    real_server: SimpleMcpServer,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_rw(real_server, sample_binary_path, request_id=30)
    _call_tool(
        real_server,
        "analysis.update_and_wait",
        {"session_id": session_id},
        request_id=31,
    )

    functions = _call_tool(
        real_server,
        "binary.functions",
        {"session_id": session_id, "offset": 0, "limit": 200},
        request_id=32,
    )
    main_start = _find_function_start(functions["structuredContent"]["items"], "main")

    variables = _call_tool(
        real_server,
        "function.variables",
        {"session_id": session_id, "function_start": main_start},
        request_id=33,
    )
    assert variables["structuredContent"]["count"] >= 1

    first_var_name = variables["structuredContent"]["items"][0]["name"]
    _call_tool(
        real_server,
        "function.var_refs",
        {
            "session_id": session_id,
            "function_start": main_start,
            "variable_name": first_var_name,
            "level": "mlil",
        },
        request_id=34,
    )

    _call_tool(
        real_server,
        "value.reg",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": main_start,
            "register": "x0",
        },
        request_id=35,
    )
    _call_tool(
        real_server,
        "value.stack",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": main_start,
            "stack_offset": 0,
            "size": 8,
        },
        request_id=36,
    )
    _call_tool(
        real_server,
        "value.possible",
        {
            "session_id": session_id,
            "function_start": main_start,
            "address": main_start,
            "level": "mlil",
        },
        request_id=37,
    )

    read = _call_tool(
        real_server,
        "memory.read",
        {"session_id": session_id, "address": main_start, "length": 4},
        request_id=38,
    )
    data_hex = read["structuredContent"]["data_hex"]

    too_large_read = _call_tool(
        real_server,
        "memory.read",
        {"session_id": session_id, "address": main_start, "length": 65537},
        request_id=381,
    )
    assert too_large_read["isError"] is True
    assert "length must be <= 65536" in too_large_read["structuredContent"]["error"]

    _call_tool(
        real_server,
        "memory.write",
        {"session_id": session_id, "address": main_start, "data_hex": data_hex},
        request_id=39,
    )
    _call_tool(
        real_server,
        "memory.insert",
        {"session_id": session_id, "address": int(main_start, 16) + 4, "data_hex": "00"},
        request_id=40,
    )
    _call_tool(
        real_server,
        "memory.remove",
        {"session_id": session_id, "address": int(main_start, 16) + 4, "length": 1},
        request_id=41,
    )

    search = _call_tool(
        real_server,
        "binary.search_text",
        {"session_id": session_id, "query": "Hello", "limit": 5},
        request_id=42,
    )
    hello_addr = search["structuredContent"]["items"][0]["address"]

    _call_tool(
        real_server,
        "data.typed_at",
        {"session_id": session_id, "address": hello_addr},
        request_id=43,
    )

    _call_tool(
        real_server,
        "annotation.rename_function",
        {"session_id": session_id, "function_start": main_start, "new_name": "main_mcp_srv"},
        request_id=44,
    )
    _call_tool(
        real_server,
        "annotation.rename_symbol",
        {"session_id": session_id, "address": main_start, "new_name": "main_symbol_srv"},
        request_id=45,
    )
    _call_tool(
        real_server,
        "annotation.define_symbol",
        {
            "session_id": session_id,
            "address": main_start,
            "name": "main_defined_srv",
            "symbol_type": "FunctionSymbol",
        },
        request_id=46,
    )
    _call_tool(
        real_server,
        "annotation.undefine_symbol",
        {"session_id": session_id, "address": main_start},
        request_id=47,
    )

    _call_tool(
        real_server,
        "annotation.rename_data_var",
        {"session_id": session_id, "address": hello_addr, "new_name": "hello_data_srv"},
        request_id=48,
    )
    _call_tool(
        real_server,
        "annotation.define_data_var",
        {
            "session_id": session_id,
            "address": hello_addr,
            "type_name": "char",
            "width": 1,
            "name": "hello_data_srv_2",
        },
        request_id=49,
    )
    _call_tool(
        real_server,
        "annotation.undefine_data_var",
        {"session_id": session_id, "address": hello_addr},
        request_id=50,
    )

    _call_tool(
        real_server,
        "annotation.set_comment",
        {"session_id": session_id, "address": main_start, "comment": "server comment"},
        request_id=51,
    )
    _call_tool(
        real_server,
        "annotation.get_comment",
        {"session_id": session_id, "address": main_start},
        request_id=52,
    )
    _call_tool(
        real_server,
        "annotation.add_tag",
        {
            "session_id": session_id,
            "address": main_start,
            "tag_type": "mcp-tag",
            "data": "tag-value",
            "icon": "M",
        },
        request_id=53,
    )
    _call_tool(
        real_server,
        "annotation.get_tags",
        {"session_id": session_id, "address": main_start},
        request_id=54,
    )

    _call_tool(
        real_server,
        "metadata.store",
        {"session_id": session_id, "key": "mcp.key", "value": {"a": 1}},
        request_id=55,
    )
    _call_tool(
        real_server,
        "metadata.query",
        {"session_id": session_id, "key": "mcp.key"},
        request_id=56,
    )
    _call_tool(
        real_server,
        "metadata.remove",
        {"session_id": session_id, "key": "mcp.key"},
        request_id=57,
    )

    _call_tool(
        real_server,
        "patch.assemble",
        {"session_id": session_id, "address": main_start, "asm": "nop"},
        request_id=58,
    )
    _call_tool(
        real_server,
        "patch.status",
        {"session_id": session_id, "address": main_start},
        request_id=59,
    )
    _call_tool(
        real_server,
        "patch.convert_to_nop",
        {"session_id": session_id, "address": main_start},
        request_id=60,
    )
    _call_tool(
        real_server,
        "patch.always_branch",
        {"session_id": session_id, "address": int(main_start, 16) + 0x10},
        request_id=61,
    )
    _call_tool(
        real_server,
        "patch.never_branch",
        {"session_id": session_id, "address": int(main_start, 16) + 0x10},
        request_id=62,
    )
    _call_tool(
        real_server,
        "patch.invert_branch",
        {"session_id": session_id, "address": int(main_start, 16) + 0x10},
        request_id=63,
    )
    _call_tool(
        real_server,
        "patch.skip_and_return_value",
        {"session_id": session_id, "address": int(main_start, 16) + 0x10, "value": 7},
        request_id=64,
    )

    tx = _call_tool(
        real_server,
        "undo.begin",
        {"session_id": session_id},
        request_id=65,
    )["structuredContent"]["transaction_id"]
    _call_tool(
        real_server,
        "annotation.set_comment",
        {"session_id": session_id, "address": main_start, "comment": "undo path"},
        request_id=66,
    )
    _call_tool(
        real_server,
        "undo.revert",
        {"session_id": session_id, "transaction_id": tx},
        request_id=67,
    )

    tx2 = _call_tool(
        real_server,
        "undo.begin",
        {"session_id": session_id},
        request_id=68,
    )["structuredContent"]["transaction_id"]
    _call_tool(
        real_server,
        "annotation.set_comment",
        {"session_id": session_id, "address": main_start, "comment": "undo commit"},
        request_id=69,
    )
    _call_tool(
        real_server,
        "undo.commit",
        {"session_id": session_id, "transaction_id": tx2},
        request_id=70,
    )
    _call_tool(real_server, "undo.undo", {"session_id": session_id}, request_id=71)
    _call_tool(real_server, "undo.redo", {"session_id": session_id}, request_id=72)

    bndb_path = tmp_path / "hello-core-extra.bndb"
    created = _call_tool(
        real_server,
        "database.create_bndb",
        {"session_id": session_id, "path": str(bndb_path)},
        request_id=73,
    )
    assert created["structuredContent"]["created"] is True


def test_rebase_is_rejected_after_byte_edits_and_transport_survives(
    real_server: SimpleMcpServer,
    sample_binary_path: str,
) -> None:
    session_id = _open_rw(real_server, sample_binary_path, request_id=200)
    summary = _call_tool(
        real_server,
        "binary.summary",
        {"session_id": session_id},
        request_id=201,
    )["structuredContent"]
    start = summary["start"]

    read_back = _call_tool(
        real_server,
        "memory.read",
        {"session_id": session_id, "address": start, "length": 4},
        request_id=202,
    )["structuredContent"]["data_hex"]
    _call_tool(
        real_server,
        "memory.write",
        {"session_id": session_id, "address": start, "data_hex": read_back},
        request_id=203,
    )

    rebased = _call_tool(
        real_server,
        "loader.rebase",
        {"session_id": session_id, "address": start},
        request_id=204,
    )
    assert rebased["isError"] is True
    assert "rebase is not allowed after byte edits" in rebased["structuredContent"]["error"]

    # Regression check: server remains responsive after the rejected rebase.
    ping = _call_tool(real_server, "health.ping", request_id=205)
    assert ping["isError"] is False
    assert ping["structuredContent"]["status"] == "ok"
