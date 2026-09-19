"""All-catalog argument/envelope parity; native semantics have a separate live gate.

Recording handlers isolate transport and coercion from native state. These tests
must never be counted as successful native tool coverage.
"""

from __future__ import annotations

import json

import pytest
from binary_ninja_headless_mcp import binja_cli
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.catalog import TOOL_DEFINITIONS
from binary_ninja_headless_mcp.fake_binja import make_fake_module
from binary_ninja_headless_mcp.server import SimpleMcpServer


def _value(schema):
    if schema.get("enum"):
        return schema["enum"][0]
    if schema.get("oneOf"):
        return "0x401000"
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = kind[0]
    if kind == "array":
        return [_value(schema.get("items", {})), _value(schema.get("items", {}))]
    if kind == "integer":
        return max(2, schema.get("minimum", 0))
    return {
        "string": "fixture λ\nvalue",
        "boolean": False,
        "number": 1.25,
        "object": {"nested": [1, False, None, {"key": "value"}]},
    }.get(kind, {"untyped": [1, True, None]})


@pytest.mark.parametrize("spec", TOOL_DEFINITIONS, ids=lambda spec: spec["name"])
@pytest.mark.parametrize("style", ["json", "typed_flags"])
def test_every_tool_preserves_arguments_and_mcp_envelope(spec, style, capsys):
    backend = BinjaBackend(make_fake_module())
    try:
        sid = backend.open_session("fixture", update_analysis=False, read_only=False)["session_id"]
        server = SimpleMcpServer(backend)
        arguments = {
            key: _value(schema) for key, schema in spec["inputSchema"]["properties"].items()
        }
        for key in ("session_id", "source_session_id"):
            if key in arguments:
                arguments[key] = sid
        observed = []

        def record(actual):
            observed.append(actual)
            return {"arguments": actual, "tool": spec["name"], "nested": [False, None, 42]}

        server._tool_handlers[spec["name"]] = record
        direct = server.handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": spec["name"], "arguments": arguments},
            }
        )["result"]
        assert not direct["isError"]
        rest = ["--json", json.dumps(arguments)]
        if style == "typed_flags":
            rest = []
            for key, value in arguments.items():
                rest.extend(["--" + key.replace("_", "-") + ":json", json.dumps(value)])
        assert binja_cli.main(["--raw", "call", spec["name"], *rest], server=server) == 0
        output = capsys.readouterr()
        assert not output.err
        assert json.loads(output.out) == direct
        assert observed == [arguments, arguments]
    finally:
        backend.shutdown()
