"""Fail-closed ledger unit tests and opt-in full licensed CLI verification.

Set BINJA_CLI_RUN_NATIVE=1 to run the complete four-cell native matrix. The
ordinary tests validate evidence accounting without pretending to be native
feature coverage.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest
from binary_ninja_headless_mcp.cli_verify import (
    CATALOG,
    Runner,
    VerificationFailure,
    flags_for,
)


def test_registry_ledger_requires_semantic_assertions(tmp_path, monkeypatch):
    fixture = tmp_path / "sample"
    fixture.write_bytes(b"fixture")
    runner = Runner(fixture, tmp_path / "evidence", mode="inprocess", argument_style="json")
    runner.events.append({"tool": "health.ping"})
    summary = runner.summary()
    assert summary["catalog_count"] == len(CATALOG)
    assert summary["verified_count"] == 0
    assert summary["ledger"]["health.ping"]["status"] == "missing"
    runner.record(
        "health.ping", "known-result", True, "Observed expected native result", {"status": "ok"}
    )
    summary = runner.summary()
    assert summary["verified_count"] == 0  # An invented assertion is not tool coverage.

    def main(_argv, *, server):  # noqa: ARG001
        print(json.dumps({"isError": False, "structuredContent": {"status": "ok"}}))
        return 0

    monkeypatch.setattr("binary_ninja_headless_mcp.binja_cli.main", main)
    runner.verify("health.ping", "real-command", {}, lambda p: p["status"] == "ok", "Healthy")
    assert runner.summary()["verified_count"] == 1
    assert not summary["complete"]


def test_failure_cannot_be_hidden_by_prior_success(tmp_path):
    fixture = tmp_path / "sample"
    fixture.write_bytes(b"fixture")
    runner = Runner(fixture, tmp_path / "evidence", mode="inprocess", argument_style="json")
    runner.record("health.ping", "earlier", True, "known healthy result")
    with pytest.raises(VerificationFailure):
        runner.record("health.ping", "later", False, "unexpected result", {"status": "broken"})
    assert runner.summary()["ledger"]["health.ping"]["status"] == "failed"
    assertions = [
        json.loads(line) for line in (runner.output / "assertions.jsonl").read_text().splitlines()
    ]
    assert [item["passed"] for item in assertions] == [True, False]


def test_flags_preserve_untyped_values_and_literal_source_prefixes():
    result = flags_for(
        {
            "count": 42,
            "ratio": 0.5,
            "enabled": False,
            "value": None,
            "nested": {"x": [1]},
            "literal": "@not-a-file",
            "negative": -7,
        }
    )
    assert result == [
        "--count:int",
        "42",
        "--ratio:float",
        "0.5",
        "--enabled:bool",
        "false",
        "--value:json",
        "null",
        "--nested:json",
        '{"x": [1]}',
        "--literal:json",
        '"@not-a-file"',
        "--negative:int",
        "-7",
    ]


def test_input_mutation_invalidates_ledger(tmp_path):
    fixture = tmp_path / "sample"
    fixture.write_bytes(b"fixture")
    runner = Runner(fixture, tmp_path / "evidence", mode="inprocess", argument_style="json")
    fixture.write_bytes(b"changed")
    assert not runner.summary()["input_unchanged"]


@pytest.mark.skipif(
    os.environ.get("BINJA_CLI_RUN_NATIVE") != "1",
    reason="Explicit opt-in required for complete licensed native matrix",
)
def test_complete_native_cli_matrix(tmp_path):
    output = tmp_path / "native-matrix"
    command = [
        sys.executable,
        "-m",
        "binary_ninja_headless_mcp.cli_verify",
        "--output",
        str(output),
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=7200, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    summary = json.loads((output / "summary.json").read_text())
    assert summary["complete"]
    assert len(summary["matrix"]) == 4
    assert all(item["verified_count"] == len(CATALOG) for item in summary["matrix"])
    assert {(item["mode"], item["argument_style"]) for item in summary["matrix"]} == {
        ("inprocess", "json"),
        ("inprocess", "flags"),
        ("tcp", "json"),
        ("tcp", "flags"),
    }
