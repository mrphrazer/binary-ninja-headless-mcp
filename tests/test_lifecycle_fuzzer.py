from __future__ import annotations

import json
from pathlib import Path

from binary_ninja_headless_mcp.lifecycle_fuzzer import LifecycleFuzzer, main


def test_wire_fuzzer_checks_all_lifecycle_actions(tmp_path):
    binary = Path(__file__).resolve().parents[1] / "samples" / "ls"
    assert (
        main(
            [
                "--binary",
                str(binary),
                "--output-dir",
                str(tmp_path),
                "--transitions",
                "30",
                "--fake-backend",
                "--timeout",
                "20",
            ]
        )
        == 0
    )
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["passed"] is True
    assert report["transitions"] == 30
    assert set(report["actions"]) == set(LifecycleFuzzer.ACTIONS)
    assert report["terminal_tasks"] > 0


def test_wire_fuzzer_fails_on_unexpected_tool_error(tmp_path):
    missing = tmp_path / "missing"
    missing.write_bytes(b"ELF")
    # A deliberately wrong action demonstrates that the oracle's failures reach
    # the process exit/report instead of being counted as exploratory successes.
    original = LifecycleFuzzer.ACTIONS
    try:
        LifecycleFuzzer.ACTIONS = ("invalid-driver-action",)
        assert (
            main(
                [
                    "--binary",
                    str(missing),
                    "--output-dir",
                    str(tmp_path),
                    "--transitions",
                    "1",
                    "--fake-backend",
                ]
            )
            == 1
        )
    finally:
        LifecycleFuzzer.ACTIONS = original
    report = json.loads((tmp_path / "report.json").read_text())
    assert report["passed"] is False
    assert "invalid-driver-action" in report["error"]
