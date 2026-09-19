"""The offline catalog must preserve MCP schemas and effective handler defaults."""

from __future__ import annotations

import copy
import json
import subprocess
import sys

import pytest
from binary_ninja_headless_mcp.catalog import TOOL_DEFAULTS, TOOL_DEFINITIONS
from binary_ninja_headless_mcp.server import SimpleMcpServer


class RecordingBackend:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        def record(*args, **kwargs):
            self.calls.append((name, args, kwargs))
            return {}

        return record


def _example(schema):
    if "enum" in schema:
        return schema["enum"][0]
    if "oneOf" in schema:
        return _example(schema["oneOf"][0])
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = kind[0]
    if kind == "integer":
        return max(schema.get("minimum", 0), 1)
    if kind == "array":
        return [_example(schema.get("items", {}))]
    return {"boolean": True, "object": {}}.get(kind, "fixture")


@pytest.mark.parametrize("spec", TOOL_DEFINITIONS, ids=lambda spec: spec["name"])
def test_catalog_defaults_match_effective_handler_arguments(spec):
    backend = RecordingBackend()
    server = SimpleMcpServer(backend)
    schema = spec["inputSchema"]
    required = {key: _example(schema["properties"][key]) for key in schema.get("required", [])}
    if spec["name"] == "transform.inspect":
        required["path"] = "fixture"
    handler = server._tool_handlers[spec["name"]]
    handler(copy.deepcopy(required))
    omitted_calls = copy.deepcopy(backend.calls)
    backend.calls.clear()
    handler({**copy.deepcopy(TOOL_DEFAULTS[spec["name"]]), **required})
    assert backend.calls == omitted_calls
    assert set(TOOL_DEFAULTS[spec["name"]]) == (
        set(schema["properties"]) - set(schema.get("required", []))
    )


def test_mcp_catalog_is_independent_copy():
    server = SimpleMcpServer(RecordingBackend())
    definitions = server._tool_definitions()
    assert definitions == TOOL_DEFINITIONS
    definitions[0]["name"] = "changed"
    assert server._tool_definitions() == TOOL_DEFINITIONS


def test_catalog_import_does_not_import_native_runtime():
    script = """
import json
import sys
from binary_ninja_headless_mcp.catalog import TOOL_DEFINITIONS
assert 'binaryninja' not in sys.modules
print(json.dumps([spec['name'] for spec in TOOL_DEFINITIONS]))
"""
    proc = subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, check=True
    )
    assert json.loads(proc.stdout) == [spec["name"] for spec in TOOL_DEFINITIONS]
