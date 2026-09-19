"""Independent offline checks of native-verification acceptance accounting."""

from __future__ import annotations

import json
import subprocess

import pytest
from binary_ninja_headless_mcp import cli_verify as verify


class SuccessfulServer:
    """Protocol-only fixture: these tests never claim native capability coverage."""

    def handle_request(self, request):
        return {
            "jsonrpc": "2.0",
            "id": request["id"],
            "result": {"isError": False, "structuredContent": {"fixture": True}},
        }


def runner_for(tmp_path, monkeypatch, tool):
    monkeypatch.setattr(verify, "CATALOG", {tool: verify.CATALOG[tool]})
    fixture = tmp_path / "input"
    fixture.write_bytes(b"accounting-only")
    return verify.Runner(
        fixture,
        tmp_path / "evidence",
        mode="inprocess",
        argument_style="json",
        server=SuccessfulServer(),
    )


@pytest.mark.parametrize("tool", ["value.reg", "value.stack"])
def test_before_only_does_not_cover_after_variant(tmp_path, monkeypatch, tool):
    runner = runner_for(tmp_path, monkeypatch, tool)
    runner.tool(
        tool,
        session_id="fixture",
        function_start=4096,
        address=4096,
        register="sp",
        stack_offset=0,
        size=4,
        after=False,
    )
    runner.record(tool, "before", True, "Only the before variant was observed")
    assert runner.summary()["ledger"][tool]["status"] != "verified"


@pytest.mark.parametrize(
    "tool",
    [
        "binary.get_function_il_at",
        "il.instruction_by_addr",
        "il.address_to_index",
        "il.index_to_address",
        "value.possible",
    ],
)
def test_il_manifest_requires_every_level_and_ssa_form(tool):
    required = {level + suffix for level in ("llil", "mlil", "hlil") for suffix in ("", "_ssa")}
    assert required <= verify.REQUIRED_VARIANTS.get(tool, set())


@pytest.mark.parametrize(
    "tool, required",
    [
        (
            "plugin.execute",
            {
                "native-" + context
                for context in (
                    "default",
                    "address",
                    "range",
                    "function",
                    "global",
                    "project",
                    "llil_function",
                    "llil_instruction",
                    "mlil_function",
                    "mlil_instruction",
                    "hlil_function",
                    "hlil_instruction",
                )
            },
        ),
        (
            "debug.parse_and_apply",
            {"native-registered", "native-dwarf", "native-separate-debug"},
        ),
    ],
)
def test_manifest_requires_special_semantic_variants(tool, required):
    assert required <= verify.REQUIRED_VARIANTS.get(tool, set())


def test_readback_sequence_links_original_tool_invocation(tmp_path, monkeypatch):
    tool = "session.set_mode"
    catalog = {name: verify.CATALOG[name] for name in (tool, "session.mode")}
    runner = runner_for(tmp_path, monkeypatch, tool)
    monkeypatch.setattr(verify, "CATALOG", catalog)
    runner.tool(tool, session_id="fixture", read_only=False)
    original_sequence = runner._sequence
    runner.tool("session.mode", session_id="fixture")
    runner.record(tool, "False", True, "Readback occurs through another tool")
    assertion = runner.assertions[-1]
    assert assertion["invocation_sequence"] == original_sequence
    assert assertion["sequence"] > original_sequence


def test_precondition_without_invocation_is_not_success(tmp_path, monkeypatch):
    tool = "memory.insert"
    runner = runner_for(tmp_path, monkeypatch, tool)
    runner.record(tool, "raw-fixture-database", True, "Fixture setup is only a precondition")
    entry = runner.summary()["ledger"][tool]
    assert entry["attempts"] == 0
    assert entry["status"] != "verified"


def test_matrix_rejects_cells_from_different_source_versions(tmp_path, monkeypatch):
    """No native runtime starts: only the final acceptance combiner is exercised."""
    from binary_ninja_headless_mcp import backend, cli

    class Backend:
        def shutdown(self):
            pass

    class CellRunner:
        def __init__(self, fixture, _directory, *, mode, argument_style, **_kwargs):
            self.fixture = fixture
            self.mode = mode
            self.style = argument_style

        def tool(self, *_args, **_kwargs):
            return {}

        def close(self):
            pass

        def summary(self):
            # Each individual cell is internally consistent but the two cells
            # were run against different source revisions.
            source = {"backend.py": "revision-" + self.style}
            return {
                "mode": self.mode,
                "argument_style": self.style,
                "complete": True,
                "input_sha256": verify.sha256(self.fixture),
                "source_unchanged": True,
                "input_unchanged": True,
                "source_hashes_start": source,
                "source_hashes": source,
            }

    monkeypatch.setattr(verify, "Runner", CellRunner)
    monkeypatch.setattr(backend, "BinjaBackend", lambda _module: Backend())
    monkeypatch.setattr(cli, "load_binja_module", lambda _fake: object())
    fixture = tmp_path / "fixture"
    fixture.write_bytes(b"accounting-only")
    result = verify.run_matrix(fixture, tmp_path, ["inprocess"], ["json", "flags"], [])
    assert result["complete"] is False


def test_parent_timeout_records_cleanup_and_removes_private_license(tmp_path, monkeypatch):
    """Use fake process outcomes, never start a native core or managed worker."""
    fixture = tmp_path / "fixture"
    fixture.write_bytes(b"accounting-only")
    output = tmp_path / "output"
    stop_calls = []

    def run(command, **kwargs):
        if "server" in command:
            stop_calls.append((command, kwargs["env"]["BINJA_CLI_HOME"]))
            return subprocess.CompletedProcess(command, 0, '{"stopped":true}', "")
        cell = output / ("cell-" + command[command.index("--mode") + 1] + "-json")
        user = cell / "special" / "user"
        user.mkdir(parents=True)
        (user / "license.dat").write_text("nonsecret test marker")
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(verify.subprocess, "run", run)
    result = verify.main(
        [
            "--output",
            str(output),
            "--binary",
            str(fixture),
            "--mode",
            "both",
            "--argument-style",
            "json",
        ]
    )
    assert result == 1
    assert len(stop_calls) == 1
    assert stop_calls[0][1] == str(output / "cell-tcp-json" / "tcp-json" / "managed-state")
    assert not list(output.glob("cell-*/special/user/license.dat"))
    summary = json.loads((output / "summary.json").read_text())
    tcp_failure = next(item for item in summary["errors"] if item.get("mode") == "tcp")
    assert tcp_failure["cleanup"]["attempted"] is True
    assert tcp_failure["cleanup"]["exit_code"] == 0
    assert summary["complete"] is False
