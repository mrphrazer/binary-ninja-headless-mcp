"""Real child-process tests for the native CLI verification accelerator."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys

import pytest
from binary_ninja_headless_mcp.cli_verify_worker import CliWorker


def test_real_offline_calls_reuse_child_and_capture_argparse():
    with CliWorker() as worker:
        result = worker.invoke(["list", "--prefix", "session.", "--names-only"])
        assert result["exit_code"] == 0, result
        assert "session.open" in result["stdout"].splitlines()
        assert result["pid"] == worker.pid != os.getpid()
        described = worker.invoke(["describe", "workflow.insert"])
        assert described["exit_code"] == 0, described
        assert json.loads(described["stdout"])["name"] == "workflow.insert"
        bad = worker.invoke(["--does-not-exist"])
        assert bad["exit_code"] == 2
        assert "usage:" in bad["stderr"]
        assert not bad["stdout"]
        # A parser SystemExit must not terminate the worker.
        assert worker.invoke(["--version"])["exit_code"] == 0
    assert worker.process.returncode == 0
    worker.close()


def test_protocol_errors_are_isolated():
    requests = [
        "not-json",
        "[]",
        '{"argv": [1]}',
        '{"argv": [], "stdin": 1}',
        '{"argv": [], "surprise": true}',
        '{"argv": ["--version"]}',
    ]
    result = subprocess.run(
        [sys.executable, "-m", "binary_ninja_headless_mcp.cli_verify_worker"],
        input="\n".join(requests) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    responses = [json.loads(line) for line in result.stdout.splitlines()]
    assert len(responses) == len(requests)
    assert [item["exit_code"] for item in responses] == [2, 2, 2, 2, 2, 0]
    assert len({item["pid"] for item in responses}) == 1
    assert all(item["stderr"] for item in responses[:-1])


def test_timeout_kills_worker_even_when_request_cannot_fit_pipe():
    with CliWorker() as worker:
        assert worker.invoke(["--version"])["exit_code"] == 0
        os.kill(worker.pid, signal.SIGSTOP)
        try:
            with pytest.raises(TimeoutError, match="timed out"):
                worker.invoke(["list"], stdin="x" * 1_000_000, timeout=0.1)
        finally:
            if worker.process.poll() is None:
                os.kill(worker.pid, signal.SIGCONT)
        assert worker.process.poll() is not None
        with pytest.raises(RuntimeError, match="closed"):
            worker.invoke(["--version"])


def test_invalid_timeout_leaves_worker_usable():
    with CliWorker() as worker:
        with pytest.raises(ValueError, match="positive"):
            worker.invoke(["--version"], timeout=0)
        assert worker.invoke(["--version"])["exit_code"] == 0
