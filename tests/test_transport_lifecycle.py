"""Real socket transport and CLI cleanup checks; native test is opt-in."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path

import pytest
from binary_ninja_headless_mcp import cli
from binary_ninja_headless_mcp import server as server_module
from binary_ninja_headless_mcp.backend import BinjaBackend
from binary_ninja_headless_mcp.server import SimpleMcpServer

from test_analysis_lifecycle import ControlledModule


class TcpClient:
    def __init__(self, address):
        self.socket = socket.create_connection(address, timeout=120)
        self.stream = self.socket.makefile("rw", encoding="utf-8")
        self.sequence = 0

    def call(self, name, **arguments):
        self.sequence += 1
        self.stream.write(
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": self.sequence,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
            )
            + "\n"
        )
        self.stream.flush()
        response = json.loads(self.stream.readline())
        assert response["id"] == self.sequence
        assert "error" not in response, response
        return response["result"]

    def tool(self, name, **arguments):
        result = self.call(name, **arguments)
        assert result["isError"] is False, result
        return result["structuredContent"]

    def close(self):
        self.stream.close()
        self.socket.close()


@contextmanager
def tcp_server(backend, monkeypatch):
    ready = threading.Event()
    servers = []
    original = server_module._ThreadingTcpServer

    def capture(*args, **kwargs):
        server = original(*args, **kwargs)
        servers.append(server)
        ready.set()
        return server

    monkeypatch.setattr(server_module, "_ThreadingTcpServer", capture)
    thread = threading.Thread(
        target=SimpleMcpServer(backend).serve_tcp, args=("127.0.0.1", 0), daemon=True
    )
    thread.start()
    assert ready.wait(5)
    clients = [TcpClient(servers[0].server_address) for _ in range(2)]
    try:
        yield clients
    finally:
        for client in clients:
            client.close()
        servers[0].shutdown()
        thread.join(timeout=5)
        assert not thread.is_alive()
        backend.shutdown()


def test_tcp_other_client_can_see_and_cancel_synchronous_open(monkeypatch):
    module = ControlledModule()
    module.block_on_load = True
    backend = BinjaBackend(module)
    with tcp_server(backend, monkeypatch) as (first, second), ThreadPoolExecutor() as pool:
        opening = pool.submit(first.call, "session.open", path="fixture")
        with backend._condition:
            assert backend._condition.wait_for(lambda: bool(backend._sessions), timeout=5)
        assert module.views[0].started.wait(5)
        sid = second.tool("session.list")["sessions"][0]["session_id"]
        assert second.tool("analysis.status", session_id=sid)["status"] == "running"
        assert not opening.done()
        rejected = second.call("analysis.update", session_id=sid)
        assert rejected["isError"] is True
        second.tool("analysis.abort", session_id=sid)
        error = opening.result(timeout=5)
        assert error["isError"] is True
        assert error["structuredContent"]["session_id"] == sid
        assert error["structuredContent"]["status"] == "cancelled"
        assert second.tool("analysis.update_and_wait", session_id=sid)["status"] == "completed"
        second.tool("session.close", session_id=sid)
        assert module.views[0].file.closed
        assert not module.views[0].closed_while_active


@pytest.mark.parametrize("failure", [None, RuntimeError("transport failed")])
@pytest.mark.parametrize("transport", ["stdio", "tcp"])
def test_cli_finally_drains_tasks(monkeypatch, failure, transport):
    module = ControlledModule()
    backends = []

    def serve(server, *_args):
        backend = server._backend
        backends.append(backend)
        sid = backend.open_session("fixture", update_analysis=False)["session_id"]
        view = module.views[0]
        view.release.clear()
        backend.analysis_update(sid)
        assert view.started.wait(5)
        if failure:
            raise failure

    monkeypatch.setattr(cli, "load_binja_module", lambda _fake: module)
    monkeypatch.setattr(SimpleMcpServer, "serve_stdio", serve)
    monkeypatch.setattr(SimpleMcpServer, "serve_tcp", serve)
    if failure:
        with pytest.raises(RuntimeError, match="transport failed"):
            cli.main(["--transport", transport])
    else:
        assert cli.main(["--transport", transport]) == 0
    assert backends[0]._shutdown_complete
    assert module.views[0].file.closed
    assert not module.views[0].closed_while_active


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"),
    reason="set BINJA_NATIVE_TEST_BINARY for the native TCP check",
)
def test_native_tcp_cancel_reanalyze_and_close(monkeypatch, tmp_path):
    import binaryninja

    path = Path(os.environ["BINJA_NATIVE_TEST_BINARY"]).resolve()
    backend = BinjaBackend(binaryninja)
    evidence = []
    with tcp_server(backend, monkeypatch) as (first, second), ThreadPoolExecutor() as pool:
        sid = first.tool("session.open", path=str(path), update_analysis=False)["session_id"]
        running = pool.submit(first.call, "analysis.update_and_wait", session_id=sid)
        deadline = time.monotonic() + 30
        while True:
            state = second.tool("analysis.status", session_id=sid)
            if state["status"] == "running":
                break
            assert time.monotonic() < deadline, state
            assert not running.done(), "use a binary large enough to observe native analysis"
            time.sleep(0.001)
        evidence.append(state)
        overlap = second.call("analysis.update", session_id=sid)
        assert overlap["isError"] and "already running" in overlap["structuredContent"]["error"]
        second.tool("analysis.abort", session_id=sid)
        result = running.result(timeout=120)
        evidence.append(result)
        assert result["isError"] and result["structuredContent"]["status"] == "cancelled"
        assert second.tool("analysis.update_and_wait", session_id=sid)["status"] == "completed"
        status = second.tool("analysis.status", session_id=sid)
        assert status["is_aborted"] is False
        assert first.tool("binary.functions", session_id=sid, limit=5)["items"]
        fresh = second.tool("session.open", path=str(path))["session_id"]
        recovered_functions = first.tool("binary.functions", session_id=sid, limit=10000)
        fresh_functions = second.tool("binary.functions", session_id=fresh, limit=10000)
        assert len(recovered_functions["items"]) == recovered_functions["total"]
        assert len(fresh_functions["items"]) == fresh_functions["total"]
        assert {f["start"] for f in recovered_functions["items"]} == {
            f["start"] for f in fresh_functions["items"]
        }, "cancellation/retry lost initial function discovery"
        second.tool("session.close", session_id=fresh)
        task = first.tool("analysis.update", session_id=sid)
        second.tool("session.close", session_id=sid)
        terminal = first.tool("task.result", task_id=task["task_id"])
        assert terminal["status"] in {"completed", "cancelled"}
        evidence.extend([status, terminal])
    (tmp_path / "native-tcp.json").write_text(json.dumps(evidence, indent=2) + "\n")


def test_tcp_transport_failure_cleans_up_with_idle_client(monkeypatch):
    module = ControlledModule()
    backend = BinjaBackend(module)
    backend.open_session("fixture")
    ready, connected = threading.Event(), threading.Event()
    servers = []
    original = server_module._ThreadingTcpServer

    class BrokenServer(original):
        def serve_forever(self, poll_interval=0.5):
            _ = poll_interval
            servers.append(self)
            ready.set()
            assert connected.wait(5)
            self._handle_request_noblock()  # Start a handler blocked in client readline.
            raise RuntimeError("listener failed")

    monkeypatch.setattr(server_module, "_ThreadingTcpServer", BrokenServer)
    monkeypatch.setattr(cli, "load_binja_module", lambda _fake: module)
    monkeypatch.setattr(cli, "BinjaBackend", lambda _module: backend)
    with ThreadPoolExecutor() as pool:
        serving = pool.submit(cli.main, ["--transport", "tcp", "--port", "0"])
        assert ready.wait(5)
        connection = socket.create_connection(servers[0].server_address, timeout=5)
        connected.set()
        try:
            with pytest.raises(RuntimeError, match="listener failed"):
                serving.result(timeout=5)
            assert backend._shutdown_complete
            assert module.views[0].file.closed
        finally:
            connection.close()


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"),
    reason="set BINJA_NATIVE_TEST_BINARY for native parallel session checks",
)
def test_native_tcp_independent_sessions_can_analyze(monkeypatch):
    import binaryninja

    backend = BinjaBackend(binaryninja)
    with tcp_server(backend, monkeypatch) as (first, second):
        path = os.environ["BINJA_NATIVE_TEST_BINARY"]
        ids = [
            client.tool("session.open", path=path, update_analysis=False)["session_id"]
            for client in (first, second)
        ]
        tasks = [
            client.tool("analysis.update", session_id=sid)["task_id"]
            for client, sid in zip((first, second), ids, strict=True)
        ]
        deadline = time.monotonic() + 120
        for client, tid in zip((first, second), tasks, strict=True):
            while not client.tool("task.status", task_id=tid)["result_ready"]:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            assert client.tool("task.result", task_id=tid)["status"] == "completed"
        for client, sid in zip((first, second), ids, strict=True):
            assert client.tool("analysis.status", session_id=sid)["status"] == "completed"
            client.tool("session.close", session_id=sid)


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"),
    reason="set BINJA_NATIVE_TEST_BINARY for native uploaded-file ownership checks",
)
def test_native_reopened_upload_survives_source_close(monkeypatch):
    import base64

    import binaryninja

    backend = BinjaBackend(binaryninja)
    with tcp_server(backend, monkeypatch) as (first, second):
        data = Path(os.environ["BINJA_NATIVE_TEST_BINARY"]).read_bytes()
        parent = first.tool(
            "session.open_bytes", data_base64=base64.b64encode(data).decode(), update_analysis=False
        )["session_id"]
        child = second.tool("session.open_existing", source_session_id=parent)["session_id"]
        first.tool("session.close", session_id=parent)
        grandchild = first.tool("session.open_existing", source_session_id=child)["session_id"]
        second.tool("session.close", session_id=child)
        first.tool("analysis.update_and_wait", session_id=grandchild)
        assert first.tool("binary.functions", session_id=grandchild, limit=5)["items"]
        first.tool("session.close", session_id=grandchild)


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"), reason="requires licensed native Binary Ninja"
)
@pytest.mark.parametrize("control", ["hold", "disable"])
def test_native_suspended_analysis_errors_then_recovers(monkeypatch, control):
    import binaryninja

    backend = BinjaBackend(binaryninja)
    with tcp_server(backend, monkeypatch) as (first, second):
        sid = first.tool(
            "session.open", path=os.environ["BINJA_NATIVE_TEST_BINARY"], update_analysis=False
        )["session_id"]
        if control == "hold":
            second.tool("analysis.set_hold", session_id=sid, hold=True)
        else:
            second.tool("workflow.machine.control", session_id=sid, action="disable")
        result = first.call("analysis.update_and_wait", session_id=sid)
        assert result["isError"]
        assert result["structuredContent"]["status"] == "failed"
        if control == "hold":
            assert second.tool("analysis.status", session_id=sid)["state"] == "HoldState"
            second.tool("analysis.set_hold", session_id=sid, hold=False)
        else:
            assert second.tool("analysis.status", session_id=sid)["is_aborted"]
            second.tool("workflow.machine.control", session_id=sid, action="enable")
        completed = first.tool("analysis.update_and_wait", session_id=sid)
        assert completed["status"] == "completed"
        assert completed["state"] == "IdleState" and not completed["is_aborted"]
        assert first.tool("binary.summary", session_id=sid)["string_count"] > 0


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"), reason="requires licensed native Binary Ninja"
)
def test_native_rebase_changes_address_and_keeps_analysis_usable(monkeypatch):
    import binaryninja

    backend = BinjaBackend(binaryninja)
    with tcp_server(backend, monkeypatch) as (first, second):
        opened = first.tool(
            "session.open",
            path=os.environ["BINJA_NATIVE_TEST_BINARY"],
            update_analysis=False,
            read_only=False,
        )
        sid = opened["session_id"]
        target = int(opened["start"], 16) + 0x100000
        rebased = second.tool("loader.rebase", session_id=sid, address=hex(target))
        assert rebased["rebased"] and int(rebased["start"], 16) == target
        completed = first.tool("analysis.update_and_wait", session_id=sid)
        assert completed["status"] == "completed"
        assert completed["state"] == "IdleState" and not completed["is_aborted"]
        summary = second.tool("binary.summary", session_id=sid)
        assert int(summary["start"], 16) == target
        assert summary["function_count"] > 7 and summary["string_count"] > 0


@pytest.mark.skipif(
    not os.environ.get("BINJA_NATIVE_TEST_BINARY"), reason="requires licensed native Binary Ninja"
)
@pytest.mark.parametrize("process", [False, True])
def test_native_transform_inspection_keeps_session_usable(monkeypatch, process):
    import gc

    import binaryninja

    backend = BinjaBackend(binaryninja)
    with tcp_server(backend, monkeypatch) as (first, second):
        sid = first.tool("session.open", path=os.environ["BINJA_NATIVE_TEST_BINARY"])["session_id"]
        before = first.tool("binary.functions", session_id=sid, limit=10000)
        first.tool("transform.inspect", session_id=sid, process=process)
        gc.collect()
        assert not second.tool("analysis.status", session_id=sid)["is_aborted"]
        completed = second.tool("analysis.update_and_wait", session_id=sid)
        assert completed["status"] == "completed" and completed["state"] == "IdleState"
        after = first.tool("binary.functions", session_id=sid, limit=10000)
        assert len(before["items"]) == before["total"]
        assert len(after["items"]) == after["total"]
        assert {item["start"] for item in before["items"]} == {
            item["start"] for item in after["items"]
        }
