"""Public module entrypoint tests, including persistent state across CLI processes."""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path


def run_cli(*arguments, env=None, stdin=None):
    return subprocess.run(
        [sys.executable, "-m", "binary_ninja_headless_mcp.binja_cli", *arguments],
        input=stdin,
        text=True,
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )


def test_offline_catalog_and_module_version():
    result = run_cli("list", "--prefix", "session.", "--names-only")
    assert result.returncode == 0, result.stderr
    assert "session.open" in result.stdout.splitlines()
    result = run_cli("describe", "workflow.insert")
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["inputSchema"]["properties"]["activities"]["type"] == [
        "array",
        "string",
    ]
    result = run_cli("--version")
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("binja_cli ")


def test_fake_inprocess_batch_and_ephemeral_hint():
    payload = "\n".join(
        json.dumps(item)
        for item in [
            {"tool": "session.open", "arguments": {"path": __file__}},
            {"tool": "binary.summary"},
        ]
    )
    result = run_cli("--fake-backend", "batch", "--close-after", stdin=payload)
    assert result.returncode == 0, result.stderr
    items = [json.loads(line) for line in result.stdout.splitlines()]
    assert (
        items[0]["structuredContent"]["session_id"] == items[1]["structuredContent"]["session_id"]
    )
    result = run_cli("--fake-backend", "call", "session.open", "--path", __file__)
    assert result.returncode == 0, result.stderr
    assert "ephemeral" in result.stderr


def test_managed_cli_public_flow(tmp_path):
    env = os.environ.copy()
    env["BINJA_CLI_HOME"] = str(tmp_path / "managed")
    env.pop("BINJA_CLI_CONNECT", None)
    env.pop("BINJA_CLI_SESSION", None)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = str(listener.getsockname()[1])
    try:
        result = run_cli("server", "start", "--fake-backend", "--port", port, env=env)
        assert result.returncode == 0, result.stderr
        original_pid = json.loads(result.stdout)["pid"]
        # No --fake-backend here: this must select the existing managed worker.
        result = run_cli("call", "session.open", "--path", str(Path(__file__).resolve()), env=env)
        assert result.returncode == 0, result.stderr
        session = json.loads(result.stdout)["session_id"]
        result = run_cli(
            "--session-id", session, "--field", "session_id", "call", "binary.summary", env=env
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == session
        result = run_cli(
            "--connect",
            f"127.0.0.1:{port}",
            "call",
            "session.close",
            "--session-id",
            session,
            env=env,
        )
        assert result.returncode == 0, result.stderr
        result = run_cli("server", "restart", "--fake-backend", "--port", port, env=env)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["pid"] != original_pid
        result = run_cli("server", "status", env=env)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["running"] is True
    finally:
        stopped = run_cli("server", "stop", env=env)
        assert stopped.returncode == 0, stopped.stderr
    result = run_cli("server", "status", env=env)
    assert json.loads(result.stdout)["running"] is False
