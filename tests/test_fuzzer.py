from __future__ import annotations

import json
from pathlib import Path

from binary_ninja_headless_mcp.fuzzer import main


def test_feature_fuzzer_runs_with_fake_backend(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    sample_binary = root / "samples" / "ls"
    assert sample_binary.exists()

    report_path = tmp_path / "fuzzer-report.json"
    exit_code = main(
        [
            "--binary",
            str(sample_binary),
            "--fake-backend",
            "--allow-tool-errors",
            "--iterations",
            "5",
            "--seed",
            "1234",
            "--report-json",
            str(report_path),
            "--min-success-tools",
            "1",
        ]
    )
    assert exit_code == 0
    assert report_path.exists()

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["total_tools"] >= 150
    assert report["attempted_tools"] >= 150
    assert report["successful_tools"] >= 1

    unattempted = set(report["unattempted_tools"])
    assert "binary.save" not in unattempted
    assert "binary.get_function_disassembly_at" not in unattempted
    assert "binary.get_function_il_at" not in unattempted
    assert "disasm.function" not in unattempted


def test_old_task_metadata_does_not_resurrect_closed_session(tmp_path):
    from binary_ninja_headless_mcp.backend import BinjaBackend
    from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule
    from binary_ninja_headless_mcp.fuzzer import McpFeatureFuzzer
    from binary_ninja_headless_mcp.server import SimpleMcpServer

    sample = tmp_path / "binary"
    sample.write_bytes(b"ELF")
    backend = BinjaBackend(FakeBinaryNinjaModule())
    fuzzer = McpFeatureFuzzer(
        SimpleMcpServer(backend), sample, iterations=0, seed=0, update_analysis=False, verbose=False
    )
    try:
        fuzzer._invoke("session.open", {"path": str(sample), "update_analysis": False})
        sid = fuzzer._state.active_session_id
        task = backend.analysis_update(sid)
        backend._get_task(task["task_id"]).worker_future.result(timeout=5)
        fuzzer._invoke("session.close", {"session_id": sid})
        fuzzer._invoke("task.status", {"task_id": task["task_id"]})
        assert sid not in fuzzer._state.session_ids
    finally:
        backend.shutdown()
        fuzzer.close()


def test_register_argument_respects_schema(tmp_path):
    from binary_ninja_headless_mcp.backend import BinjaBackend
    from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule
    from binary_ninja_headless_mcp.fuzzer import McpFeatureFuzzer
    from binary_ninja_headless_mcp.server import SimpleMcpServer

    sample = tmp_path / "binary"
    sample.write_bytes(b"ELF")
    backend = BinjaBackend(FakeBinaryNinjaModule())
    fuzzer = McpFeatureFuzzer(
        SimpleMcpServer(backend), sample, iterations=0, seed=0, update_analysis=False, verbose=False
    )
    try:
        fuzzer._state.register_names.add("x0")
        assert (
            fuzzer._value_for_field(
                "workflow.clone", "register", {"type": "boolean"}, required=True
            )
            is False
        )
        assert (
            fuzzer._value_for_field(
                "value.register_at", "register", {"type": "string"}, required=True
            )
            == "x0"
        )
    finally:
        backend.shutdown()
        fuzzer.close()


def test_ssa_variable_probe_uses_same_function_with_available_il(tmp_path, monkeypatch):
    from binary_ninja_headless_mcp.backend import BinjaBackend
    from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule
    from binary_ninja_headless_mcp.fuzzer import McpFeatureFuzzer
    from binary_ninja_headless_mcp.server import SimpleMcpServer

    sample = tmp_path / "binary"
    sample.write_bytes(b"ELF")
    backend = BinjaBackend(FakeBinaryNinjaModule())
    fuzzer = McpFeatureFuzzer(
        SimpleMcpServer(backend), sample, iterations=0, seed=0, update_analysis=False, verbose=False
    )
    try:
        fuzzer._state.active_session_id = "active"
        fuzzer._state.function_starts.update({0x1000, 0x2000})
        fuzzer._state.variable_names.add("stale_other_function_var")

        def query(name, arguments):
            assert arguments["session_id"] == "active"
            if name == "il.function":
                assert arguments["ssa"] is True
                if arguments["function_start"] == 0x1000:
                    return True, {"error": "mlil is not available for this function"}, ""
                return False, {"items": [{"address": "0x2000"}]}, ""
            assert name == "function.variables"
            assert arguments["function_start"] == 0x2000
            return False, {"items": [{"name": "arg2"}]}, ""

        monkeypatch.setattr(fuzzer._client, "call_tool", query)
        monkeypatch.setattr(fuzzer, "_invoke", lambda *_args, **_kwargs: None)
        definition = {
            "inputSchema": {
                "required": ["session_id", "function_start", "variable_name", "version"],
                "properties": {"version": {"type": "integer"}},
            }
        }
        arguments = fuzzer._build_arguments("function.ssa_var_def_use", definition, fuzz=False)
        assert arguments["function_start"] == 0x2000
        assert arguments["variable_name"] == "arg2"
        assert "def_addr" not in arguments
    finally:
        backend.shutdown()
        fuzzer.close()


def test_instruction_probe_uses_actual_il_address_after_optimization(tmp_path, monkeypatch):
    from binary_ninja_headless_mcp.backend import BinjaBackend
    from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule
    from binary_ninja_headless_mcp.fuzzer import McpFeatureFuzzer
    from binary_ninja_headless_mcp.server import SimpleMcpServer

    sample = tmp_path / "binary"
    sample.write_bytes(b"ELF")
    backend = BinjaBackend(FakeBinaryNinjaModule())
    fuzzer = McpFeatureFuzzer(
        SimpleMcpServer(backend), sample, iterations=0, seed=0, update_analysis=False, verbose=False
    )
    try:
        fuzzer._state.active_session_id = "active"
        fuzzer._state.function_starts.add(0x1000)

        def query(name, arguments):
            assert name == "il.function"
            assert arguments["function_start"] == 0x1000
            return False, {"items": [{"address": "0x1008"}]}, ""

        monkeypatch.setattr(fuzzer._client, "call_tool", query)
        monkeypatch.setattr(fuzzer, "_invoke", lambda *_args, **_kwargs: None)
        arguments = fuzzer._build_arguments(
            "il.instruction_by_addr",
            {
                "inputSchema": {
                    "required": ["session_id", "function_start", "address"],
                    "properties": {},
                }
            },
            fuzz=False,
        )
        assert arguments["function_start"] == 0x1000
        assert arguments["address"] == "0x1008"
    finally:
        backend.shutdown()
        fuzzer.close()
