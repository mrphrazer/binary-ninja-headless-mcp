"""Deterministic ownership/race tests, exercising production backend and wire code."""

from __future__ import annotations

import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from types import SimpleNamespace

import pytest
from binary_ninja_headless_mcp import lifecycle
from binary_ninja_headless_mcp.backend import BinjaBackend, BinjaBackendError
from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule, FakeBinaryView
from binary_ninja_headless_mcp.server import SimpleMcpServer


class ControlledView(FakeBinaryView):
    def __init__(self, filename: str):
        super().__init__(filename)
        self.started = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.abort_started = threading.Event()
        self.abort_release = threading.Event()
        self.abort_release.set()
        self.abort_unblocks = True
        self.fail = False
        self.abort_calls = 0
        self.enable_calls = 0
        self.active = 0
        self.closed_while_active = False
        self.workflow = SimpleNamespace(machine=SimpleNamespace(enable=self.enable))
        self.file.close = self.close

    def enable(self) -> None:
        self.enable_calls += 1
        self.analysis_is_aborted = False

    def update_analysis_and_wait(self) -> None:
        self.active += 1
        self.analysis_state = "AnalyzeState"
        self.started.set()
        try:
            assert self.release.wait(10), "test analysis watchdog"
            if self.fail:
                raise RuntimeError("native analysis failed")
        finally:
            self.active -= 1
            self.analysis_state = "IdleState"

    def abort_analysis(self) -> None:
        self.abort_started.set()
        assert self.abort_release.wait(10), "test abort watchdog"
        self.abort_calls += 1
        self.analysis_is_aborted = True
        if self.abort_unblocks:
            self.release.set()

    def close(self) -> None:
        self.closed_while_active = bool(self.active)
        self.file.closed = True


class ControlledModule(FakeBinaryNinjaModule):
    def __init__(self):
        self.views: list[ControlledView] = []
        self.update_flags: list[bool] = []
        self.fail_on_load = False
        self.block_on_load = False

    def load(self, path, update_analysis=True, options=None):
        _ = options
        self.update_flags.append(update_analysis)
        view = ControlledView(path)
        view.fail = self.fail_on_load
        if self.block_on_load:
            view.release.clear()
        self.views.append(view)
        if update_analysis:
            view.update_analysis_and_wait()
        return view


@pytest.fixture
def backend():
    module = ControlledModule()
    instance = BinjaBackend(module)
    yield instance
    for view in module.views:
        view.abort_release.set()
        view.release.set()
    instance.shutdown()


def open_view(backend):
    opened = backend.open_session("fixture", update_analysis=False, deterministic=False)
    return opened["session_id"], backend._bn.views[-1]


def tool(backend, tool_name, **arguments):
    response = SimpleMcpServer(backend).handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments},
        }
    )
    assert "error" not in response
    return response["result"]


def complete(backend, task):
    record = backend._get_task(task["task_id"])
    with suppress(BinjaBackendError):
        record.future.result(timeout=5)
    return backend.task_result(task["task_id"])


@pytest.mark.parametrize("mode", ["file", "bytes", "existing"])
@pytest.mark.parametrize("analyze", [False, True])
def test_open_modes_register_then_analyze(backend, mode, analyze):
    if mode == "file":
        opened = backend.open_session("fixture", update_analysis=analyze)
    elif mode == "bytes":
        opened = backend.open_session_from_bytes(
            base64.b64encode(b"ELF").decode(), update_analysis=analyze
        )
    else:
        sid, _ = open_view(backend)
        opened = backend.open_session_from_existing(sid, update_analysis=analyze)
    assert backend._bn.update_flags == [False] * len(backend._bn.update_flags)
    assert "task_id" not in opened
    assert "wait_completed" not in opened
    assert backend.analysis_status(opened["session_id"])["status"] == (
        "completed" if analyze else "idle"
    )


@pytest.mark.parametrize("mode", ["file", "bytes", "existing"])
def test_open_failure_returns_retained_session_id(backend, mode):
    sid, _ = open_view(backend)
    backend._bn.fail_on_load = True
    if mode == "file":
        result = tool(backend, "session.open", path="failure")
    elif mode == "bytes":
        result = tool(backend, "session.open_bytes", data_base64=base64.b64encode(b"ELF").decode())
    else:
        result = tool(backend, "session.open_existing", source_session_id=sid, update_analysis=True)
    assert result["isError"] is True
    payload = result["structuredContent"]
    assert payload["status"] == "failed"
    assert f"session_id={payload['session_id']}" in result["content"][0]["text"]
    assert "status=failed" in result["content"][0]["text"]
    assert backend.binary_summary(payload["session_id"])["session_id"] == payload["session_id"]
    assert backend.analysis_status(payload["session_id"])["last_analysis_error"]


def test_slow_open_is_registered_but_does_not_return_partial_result(backend):
    backend._bn.block_on_load = True
    with ThreadPoolExecutor() as callers:
        call = callers.submit(backend.open_session, "slow")
        # The caller publishes the view before entering the controlled native wait.
        with backend._condition:
            assert backend._condition.wait_for(lambda: bool(backend._sessions), timeout=5)
            sid = next(iter(backend._sessions))
        view = backend._bn.views[0]
        assert view.started.wait(5)
        assert not call.done()
        view.release.set()
        assert call.result(timeout=5)["session_id"] == sid


def test_async_alias_and_overlap_guard(backend):
    sid, view = open_view(backend)
    view.release.clear()
    started = tool(backend, "analysis.update", session_id=sid)
    assert started["isError"] is False
    task = started["structuredContent"]
    assert view.started.wait(5)
    for name in ("analysis.update", "analysis.update_and_wait", "task.analysis_update"):
        rejected = tool(backend, name, session_id=sid)
        assert rejected["isError"] is True
        assert "already running" in rejected["structuredContent"]["error"]
    status = backend.analysis_status(sid)
    assert status["status"] == "running"
    assert {"state", "progress", "info", "is_aborted"} <= status.keys()
    assert status["last_analysis_task_id"] == task["task_id"]
    view.release.set()
    assert complete(backend, task)["status"] == "completed"
    assert backend.analysis_update(sid, wait=True)["status"] == "completed"


def test_sessions_analyze_independently(backend):
    first_sid, first = open_view(backend)
    second_sid, second = open_view(backend)
    first.release.clear()
    second.release.clear()
    tasks = [backend.analysis_update(sid) for sid in (first_sid, second_sid)]
    assert first.started.wait(5) and second.started.wait(5)
    first.release.set()
    second.release.set()
    assert all(complete(backend, task)["status"] == "completed" for task in tasks)


def test_failed_task_result_is_terminal_envelope(backend):
    sid, view = open_view(backend)
    view.fail = True
    task = backend.analysis_update(sid)
    result = complete(backend, task)
    assert result["status"] == "failed"
    assert "native analysis failed" in result["error"]
    assert backend.task_status(task["task_id"])["result_ready"] is True
    assert tool(backend, "task.result", task_id=task["task_id"])["isError"] is False
    view.fail = False
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


def test_queued_cancel_releases_guard_without_native_abort(backend):
    release = threading.Event()
    started = threading.Barrier(5)

    def block():
        started.wait(timeout=5)
        assert release.wait(10)

    workers = [backend._executor.submit(block) for _ in range(4)]
    started.wait(timeout=5)
    sid, view = open_view(backend)
    try:
        task = backend.analysis_update(sid)
        assert task["status"] == "queued"
        assert backend.analysis_status(sid)["state"] == "IdleState"
        cancelled = backend.task_cancel(task["task_id"])
        assert cancelled["cancelled"] is True
        assert cancelled["status"] == "cancelled"
        assert view.abort_calls == 0
        assert backend.analysis_status(sid)["status"] == "cancelled"
        assert backend.task_result(task["task_id"])["status"] == "cancelled"
    finally:
        release.set()
        for worker in workers:
            worker.result(timeout=5)
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


def test_cancel_old_completed_task_cannot_abort_new_run(backend):
    sid, view = open_view(backend)
    old = backend.analysis_update(sid)
    complete(backend, old)
    view.started.clear()
    view.release.clear()
    current = backend.analysis_update(sid)
    assert view.started.wait(5)
    cancelled = backend.task_cancel(old["task_id"])
    assert cancelled["cancel_requested"] is False
    assert view.abort_calls == 0
    view.release.set()
    assert complete(backend, current)["status"] == "completed"


def test_running_cancel_waits_for_abort_and_supports_retry(backend):
    sid, view = open_view(backend)
    view.release.clear()
    view.abort_release.clear()
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    assert backend.task_cancel(task["task_id"])["status"] == "cancelling"
    assert view.abort_started.wait(5)
    view.release.set()  # Native wait returns before the delayed abort.
    with pytest.raises(BinjaBackendError, match="already running"):
        backend.analysis_update(sid)
    view.abort_release.set()
    assert complete(backend, task)["status"] == "cancelled"
    assert backend.task_cancel(task["task_id"])["status"] == "cancelled"
    assert view.abort_calls == 1
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"
    assert view.enable_calls == 1


def test_submission_failure_releases_guard(backend, monkeypatch):
    sid, _ = open_view(backend)
    original = backend._executor.submit

    def fail(*_args, **_kwargs):
        raise RuntimeError("executor unavailable")

    monkeypatch.setattr(backend._executor, "submit", fail)
    with pytest.raises(BinjaBackendError, match="failed to submit"):
        backend.analysis_update(sid)
    assert backend.analysis_status(sid)["status"] == "failed"
    assert backend.analysis_status(sid)["last_analysis_task_id"] is None
    assert not backend._tasks
    assert backend._get_record(sid).active_operations == 0
    monkeypatch.setattr(backend._executor, "submit", original)
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


def test_thread_start_failure_cannot_run_analysis_after_session_close(backend, monkeypatch):
    sid, view = open_view(backend)
    original = backend._executor._adjust_thread_count

    def fail():
        raise RuntimeError("cannot start new thread")

    # ThreadPoolExecutor queues the work before trying to start a worker.
    monkeypatch.setattr(backend._executor, "_adjust_thread_count", fail)
    with pytest.raises(BinjaBackendError, match="failed to submit"):
        backend.analysis_update(sid)
    assert backend.close_session(sid)["closed"] is True
    monkeypatch.setattr(backend._executor, "_adjust_thread_count", original)
    # A later successful submission drains the previously queued work first.
    backend._executor.submit(lambda: None).result(timeout=5)
    assert not view.started.is_set(), "rejected work accessed a closed native view"


@pytest.mark.parametrize("action", ["close", "shutdown"])
def test_cleanup_drains_native_analysis(backend, action):
    sid, view = open_view(backend)
    view.release.clear()
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    if action == "close":
        assert backend.close_session(sid)["closed"] is True
    else:
        backend.shutdown()
        backend.shutdown()
    assert view.file.closed
    assert not view.closed_while_active
    assert complete(backend, task)["status"] == "cancelled"


def test_close_timeout_retains_resources_and_allows_retry(backend, monkeypatch):
    monkeypatch.setattr(lifecycle, "CLOSE_DRAIN_TIMEOUT_S", 0.02)
    sid, view = open_view(backend)
    view.release.clear()
    view.abort_unblocks = False
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    error = tool(backend, "session.close", session_id=sid)
    assert error["isError"] is True
    assert error["structuredContent"]["status"] == "closing"
    assert not view.file.closed
    assert tool(backend, "analysis.status", session_id=sid)["isError"] is False
    assert tool(backend, "session.list")["isError"] is False
    assert tool(backend, "analysis.update", session_id=sid)["isError"] is True
    view.release.set()
    complete(backend, task)
    assert backend.close_session(sid)["closed"] is True
    assert not view.closed_while_active


def test_close_waits_for_inflight_mcp_call(backend):
    sid, view = open_view(backend)
    started = threading.Event()
    release = threading.Event()

    def read():
        with backend._operation_scope("binary.summary", {"session_id": sid}):
            started.set()
            assert release.wait(5)
            assert not view.file.closed

    with ThreadPoolExecutor() as callers:
        reader = callers.submit(read)
        assert started.wait(5)
        close = callers.submit(backend.close_session, sid)
        assert not close.done()
        release.set()
        reader.result(timeout=5)
        assert close.result(timeout=5)["closed"] is True


def test_pending_result_is_error(backend):
    sid, view = open_view(backend)
    view.release.clear()
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    response = tool(backend, "task.result", task_id=task["task_id"])
    assert response["isError"] is True
    assert "not in a terminal state" in response["structuredContent"]["error"]
    view.release.set()
    assert complete(backend, task)["status"] == "completed"


def test_idle_abort_cannot_stop_later_analysis(backend):
    sid, view = open_view(backend)
    view.abort_release.clear()
    with ThreadPoolExecutor() as callers:
        abort = callers.submit(backend.analysis_abort, sid)
        assert view.abort_started.wait(5)
        with pytest.raises(BinjaBackendError, match="already running"):
            backend.analysis_update(sid)
        view.abort_release.set()
        assert abort.result(timeout=5)["is_aborted"] is True
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"
    assert view.enable_calls == 1


def test_synchronous_analysis_can_be_cancelled(backend):
    sid, view = open_view(backend)
    view.release.clear()
    with ThreadPoolExecutor() as callers:
        run = callers.submit(backend.analysis_update_and_wait, sid)
        assert view.started.wait(5)
        backend.analysis_abort(sid)
        with pytest.raises(lifecycle.AnalysisCancelled) as error:
            run.result(timeout=5)
    assert error.value.details == {"session_id": sid, "status": "cancelled"}
    assert backend.analysis_status(sid)["status"] == "cancelled"
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


@pytest.mark.parametrize("action", ["close", "shutdown"])
def test_abort_failure_retains_view_and_retry_works(backend, monkeypatch, action):
    sid, view = open_view(backend)
    original = view.abort_analysis

    def fail():
        raise RuntimeError("abort failed")

    monkeypatch.setattr(view, "abort_analysis", fail)
    close = (lambda: backend.close_session(sid)) if action == "close" else backend.shutdown
    with pytest.raises(BinjaBackendError, match="abort failed"):
        close()
    assert sid in backend._sessions
    assert not view.file.closed
    monkeypatch.setattr(view, "abort_analysis", original)
    close()
    assert view.file.closed


def test_shutdown_timeout_rejects_new_work_and_can_retry(backend, monkeypatch):
    monkeypatch.setattr(lifecycle, "CLOSE_DRAIN_TIMEOUT_S", 0.02)
    sid, view = open_view(backend)
    view.release.clear()
    view.abort_unblocks = False
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    with pytest.raises(BinjaBackendError, match="shutdown incomplete"):
        backend.shutdown()
    assert not view.file.closed
    assert tool(backend, "session.open", path="new")["isError"] is True
    assert tool(backend, "task.status", task_id=task["task_id"])["isError"] is False
    view.release.set()
    complete(backend, task)
    backend.shutdown()
    assert view.file.closed


def test_close_retains_bytes_file_until_drain(backend, monkeypatch):
    from pathlib import Path

    monkeypatch.setattr(lifecycle, "CLOSE_DRAIN_TIMEOUT_S", 0.02)
    opened = backend.open_session_from_bytes(
        base64.b64encode(b"ELF").decode(), update_analysis=False
    )
    sid = opened["session_id"]
    record = backend._get_record(sid)
    path = Path(record.temp_path)
    record.view.abort_release.clear()
    with pytest.raises(BinjaBackendError, match="resources retained"):
        backend.close_session(sid)
    assert path.exists()
    assert not record.view.file.closed
    record.view.abort_release.set()
    backend.close_session(sid)
    assert not path.exists()


def test_list_native_read_does_not_hold_global_lock(backend, monkeypatch):
    sid, _ = open_view(backend)
    started, release = threading.Event(), threading.Event()
    original = backend._safe_attr_chain

    def slow(obj, chain):
        started.set()
        assert release.wait(5)
        return original(obj, chain)

    monkeypatch.setattr(backend, "_safe_attr_chain", slow)
    with ThreadPoolExecutor() as callers:
        listing = callers.submit(backend.list_sessions)
        assert started.wait(5)
        assert backend._lock.acquire(timeout=1), "native reads must not block global coordination"
        backend._lock.release()
        release.set()
        assert listing.result(timeout=5)["sessions"][0]["session_id"] == sid


def test_concurrent_shutdown_is_idempotent(backend):
    sid, view = open_view(backend)
    view.release.clear()
    view.abort_release.clear()
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    with ThreadPoolExecutor() as callers:
        first = callers.submit(backend.shutdown)
        assert view.abort_started.wait(5)
        second = callers.submit(backend.shutdown)
        view.abort_release.set()
        first.result(timeout=5)
        second.result(timeout=5)
    assert complete(backend, task)["status"] == "cancelled"
    assert view.file.closed
    assert backend._shutdown_complete


@pytest.mark.parametrize("level", ["llil", "mlil", "hlil"])
@pytest.mark.parametrize("ssa", [False, True])
def test_unavailable_il_returns_tool_error(backend, level, ssa):
    function = SimpleNamespace(llil=None, mlil=None, hlil=None)
    with pytest.raises(BinjaBackendError, match=f"{level} is not available"):
        backend._get_il_function(function, level, ssa)


@pytest.mark.parametrize("cancel", [False, True])
def test_terminal_task_does_not_retain_closed_view(backend, cancel):
    import gc
    import weakref

    sid, view = open_view(backend)
    ref = weakref.ref(view)
    if cancel:
        view.release.clear()
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    if cancel:
        backend.task_cancel(task["task_id"])
    worker = backend._get_task(task["task_id"]).worker_future
    worker.result(timeout=5)  # Worker stores cancellation; do not re-raise its traceback.
    assert backend.task_result(task["task_id"])["status"] == (
        "cancelled" if cancel else "completed"
    )
    backend.close_session(sid)
    backend._bn.views.clear()
    del view
    gc.collect()
    assert ref() is None, "completed task bookkeeping retained the closed native view"


def test_close_releases_session_detector(backend):
    sid, _ = open_view(backend)
    backend._base_detectors[sid] = object()
    backend.close_session(sid)
    assert sid not in backend._base_detectors


def test_running_abort_error_produces_failed_terminal_result(backend, monkeypatch):
    sid, view = open_view(backend)
    view.release.clear()

    def fail():
        view.abort_started.set()
        raise RuntimeError("abort failed")

    monkeypatch.setattr(view, "abort_analysis", fail)
    task = backend.analysis_update(sid)
    assert view.started.wait(5)
    backend.task_cancel(task["task_id"])
    assert view.abort_started.wait(5)
    view.release.set()
    result = complete(backend, task)
    assert result["status"] == "failed"
    assert "failed to abort analysis: abort failed" in result["error"]
    assert backend.analysis_status(sid)["status"] == "failed"
    monkeypatch.undo()


@pytest.mark.parametrize("fail_analysis", [False, True])
def test_reopened_upload_owns_backing_file_after_source_close(backend, fail_analysis):
    from pathlib import Path

    parent = backend.open_session_from_bytes(
        base64.b64encode(b"ELF").decode(), update_analysis=False
    )["session_id"]
    path = Path(backend._get_record(parent).temp_path)
    backend._bn.fail_on_load = fail_analysis
    result = tool(backend, "session.open_existing", source_session_id=parent, update_analysis=True)
    assert result["isError"] is fail_analysis
    child = result["structuredContent"]["session_id"]
    backend.close_session(parent)
    assert path.exists(), "source close removed a file still owned by the reopened session"
    assert backend._get_record(child).temp_path == str(path)
    backend._bn.fail_on_load = False
    grandchild = backend.open_session_from_existing(child)["session_id"]
    backend.close_session(child)
    assert path.exists()
    backend.close_session(grandchild)
    assert not path.exists()
