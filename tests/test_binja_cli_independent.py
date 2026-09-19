"""Independent adversarial client checks; native success coverage lives elsewhere."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import threading
import time

import pytest
from binary_ninja_headless_mcp import binja_cli as cli
from binary_ninja_headless_mcp import managed_cli as managed


@pytest.mark.parametrize("value", ["1e999", "-1e999", '{"limit":1e999}', "[1e999]"])
def test_json_exponent_overflow_is_usage_error(value):
    with pytest.raises(cli.CliUsageError):
        cli._parse_json(value)


@contextlib.contextmanager
def peer(response):
    """Independent TCP peer returning one deliberately chosen response."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(3)
        port = listener.getsockname()[1]
        errors = []

        def serve():
            try:
                connection, _ = listener.accept()
                with connection, connection.makefile("rb") as stream:
                    request = json.loads(stream.readline())
                    payload = response(request) if callable(response) else response
                    connection.sendall(json.dumps(payload).encode() + b"\n")
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=serve)
        thread.start()
        try:
            yield port
        finally:
            thread.join(timeout=4)
            assert not thread.is_alive()
            assert not errors, errors


@pytest.mark.parametrize("request_id", [1.0, "1", None])
def test_remote_rejects_invalid_correlation_id(request_id):
    with peer({"jsonrpc": "2.0", "id": request_id, "result": {}}) as port:
        transport = cli.RemoteTransport("127.0.0.1", port, read_timeout=1)
        try:
            with pytest.raises(ConnectionError):
                transport.dispatch("ping", {})
        finally:
            transport.close()


@pytest.mark.parametrize("request_id", [True, 1.0])
def test_managed_control_rejects_non_integer_correlation_id(request_id):
    with (
        peer({"jsonrpc": "2.0", "id": request_id, "result": {}}) as port,
        pytest.raises(RuntimeError, match="invalid control response"),
    ):
        managed._rpc({"host": "127.0.0.1", "port": port, "token": "fixture"}, "ping")


@pytest.mark.parametrize("protocol", [None, "1999-01-01", 42])
def test_initialization_requires_supported_protocol(protocol):
    result = {
        "serverInfo": {"name": "binary_ninja_headless_mcp", "version": "0.2.0"},
        "capabilities": {"tools": {}},
    }
    if protocol is not None:
        result["protocolVersion"] = protocol
    with peer({"jsonrpc": "2.0", "id": 1, "result": result}) as port:
        transport = None
        try:
            with pytest.raises(cli.CliUsageError):
                transport = cli._connect_remote("127.0.0.1", port, version_check=True)
        finally:
            if transport is not None:
                transport.close()


@pytest.mark.parametrize("capabilities", [None, [], {}, {"tools": "yes"}])
def test_initialization_requires_tools_capability(capabilities):
    result = {
        "serverInfo": {"name": "binary_ninja_headless_mcp", "version": "0.2.0"},
        "protocolVersion": "2024-11-05",
        "capabilities": capabilities,
    }
    with peer({"jsonrpc": "2.0", "id": 1, "result": result}) as port:
        transport = None
        try:
            with pytest.raises(cli.CliUsageError):
                transport = cli._connect_remote("127.0.0.1", port, version_check=True)
        finally:
            if transport is not None:
                transport.close()


def test_batch_interrupt_closes_only_sessions_it_created():
    calls = []

    class Transport:
        def dispatch(self, method, params):
            calls.append((method, params))
            if params["name"] == "session.open":
                return {"structuredContent": {"session_id": "owned"}}
            if params["name"] == "health.ping":
                raise KeyboardInterrupt
            return {"structuredContent": {"closed": True}}

    args = argparse.Namespace(
        session_id="borrowed", no_autosession=True, continue_on_error=False, close_after=True
    )
    stream = io.StringIO(
        '{"tool":"session.open","args":{"path":"fixture"}}\n{"tool":"health.ping"}\n'
    )
    with pytest.raises(KeyboardInterrupt):
        cli._run_batch_lines(stream, args, Transport())
    assert calls[-1] == (
        "tools/call",
        {"name": "session.close", "arguments": {"session_id": "owned"}},
    )
    assert len(calls) == 3


def test_managed_failed_shutdown_remains_visible_and_retryable(tmp_path, monkeypatch):
    """A real child process injects only backend.shutdown failure, never native success."""
    monkeypatch.setenv("BINJA_CLI_HOME", str(tmp_path))
    monkeypatch.setattr(managed, "STOP_TIMEOUT", 1.0)
    token = "independent-ownership-token-" * 3
    marker = tmp_path / "fail-shutdown"
    marker.touch()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    script = """
import argparse
from pathlib import Path
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.managed_cli import _worker
original_shutdown = BinjaBackend.shutdown
def shutdown(self):
    if Path(MARKER).exists():
        raise RuntimeError('independent injected shutdown failure')
    return original_shutdown(self)
BinjaBackend.shutdown = shutdown
raise SystemExit(_worker(argparse.Namespace(host='127.0.0.1', port=PORT, fake_backend=True)))
""".replace("MARKER", repr(str(marker))).replace("PORT", str(port))
    env = dict(os.environ, BINJA_CLI_WORKER_TOKEN=token)
    with (tmp_path / "worker.log").open("w") as log:
        process = subprocess.Popen([sys.executable, "-c", script], env=env, stdout=log, stderr=log)
    state = {
        "pid": process.pid,
        "process_identity": managed._identity(process.pid),
        "host": "127.0.0.1",
        "port": port,
        "fake_backend": True,
        "token": token,
    }
    try:
        deadline = time.monotonic() + 5
        while True:
            try:
                managed._verify(state)
                break
            except (OSError, RuntimeError):
                assert time.monotonic() < deadline, (tmp_path / "worker.log").read_text()
                time.sleep(0.02)
        managed._write_state(tmp_path, state)
        with pytest.raises(RuntimeError):
            managed._stop(tmp_path)
        assert (tmp_path / "server.json").exists()
        assert process.poll() is None, "failed cleanup must leave the worker retryable"
        marker.unlink()
        assert managed._stop(tmp_path)["stopped"]
        process.wait(timeout=3)
        assert process.returncode == 0
    finally:
        marker.unlink(missing_ok=True)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
