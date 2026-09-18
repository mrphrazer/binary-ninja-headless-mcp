"""Regressions reproduced by an independent adversarial lifecycle review."""

from __future__ import annotations

import base64
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend, BinjaBackendError

from test_analysis_lifecycle import ControlledModule, ControlledView, complete, open_view, tool


@pytest.fixture
def backend():
    instance = BinjaBackend(ControlledModule())
    yield instance
    for view in instance._bn.views:
        view.release.set()
        view.abort_release.set()
    instance.shutdown()


def test_grandchild_opened_during_child_analysis_owns_upload(backend):
    parent = backend.open_session_from_bytes(
        base64.b64encode(b"ELF").decode(), update_analysis=False
    )["session_id"]
    path = Path(backend._get_record(parent).temp_path)
    backend._bn.block_on_load = True
    with ThreadPoolExecutor() as callers:
        child_open = callers.submit(
            backend.open_session_from_existing, parent, update_analysis=True
        )
        with backend._condition:
            assert backend._condition.wait_for(lambda: len(backend._sessions) == 2, timeout=5)
            child = next(s for s in backend._sessions if s != parent)
        child_view = backend._get_record(child).view
        assert child_view.started.wait(5)
        try:
            grandchild = backend.open_session_from_existing(child)["session_id"]
        finally:
            child_view.release.set()
        assert child_open.result(timeout=5)["session_id"] == child
    backend.close_session(parent)
    backend.close_session(child)
    assert path.exists(), "closing ancestors deleted the published grandchild backing file"
    assert backend._get_record(grandchild).temp_path == str(path)
    backend.close_session(grandchild)
    assert not path.exists()


def test_rejected_reopen_during_shutdown_preserves_parent_upload(backend, monkeypatch):
    parent = backend.open_session_from_bytes(
        base64.b64encode(b"ELF").decode(), update_analysis=False
    )["session_id"]
    path = Path(backend._get_record(parent).temp_path)
    load = backend._load_view

    def shutting_down(*args, **kwargs):
        view = load(*args, **kwargs)
        backend._shutting_down = True
        return view

    monkeypatch.setattr(backend, "_load_view", shutting_down)
    with pytest.raises(BinjaBackendError, match="shutting down"):
        backend.open_session_from_existing(parent)
    assert path.exists(), "rejected child deleted the parent's shared backing file"
    assert not backend._get_record(parent).view.file.closed
    backend.close_session(parent)
    assert not path.exists()


def test_cancel_during_resume_keeps_new_abort_obligation(backend):
    sid, view = open_view(backend)
    resume_entered, resume_return = threading.Event(), threading.Event()
    original_enable = view.enable

    def delayed_enable():
        original_enable()
        resume_entered.set()
        assert resume_return.wait(5)

    backend.analysis_abort(sid)
    view.workflow.machine.enable = delayed_enable
    task = backend.analysis_update(sid)
    try:
        assert resume_entered.wait(5)
        backend.task_cancel(task["task_id"])
        backend._get_record(sid).active_analysis.abort_future.result(timeout=5)
        assert view.analysis_is_aborted
    finally:
        resume_return.set()
    assert complete(backend, task)["status"] == "cancelled"
    assert backend._get_record(sid).resume_after_abort
    view.workflow.machine.enable = original_enable
    assert backend.analysis_update_and_wait(sid)["is_aborted"] is False


def test_failed_resume_preserves_retry_obligation(backend, monkeypatch):
    sid, view = open_view(backend)
    backend.analysis_abort(sid)

    def fail():
        raise RuntimeError("enable failed")

    monkeypatch.setattr(view.workflow.machine, "enable", fail)
    with pytest.raises(BinjaBackendError, match="enable failed"):
        backend.analysis_update_and_wait(sid)
    assert backend._get_record(sid).resume_after_abort
    monkeypatch.setattr(view.workflow.machine, "enable", view.enable)
    assert backend.analysis_update_and_wait(sid)["is_aborted"] is False


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize(
    "state,aborted", [("HoldState", False), ("IdleState", True), ("InitialState", False)]
)
def test_native_noncompletion_cannot_report_success(
    backend, monkeypatch, asynchronous, state, aborted
):
    sid, view = open_view(backend)
    view.analysis_state = state
    view.analysis_is_aborted = aborted
    monkeypatch.setattr(view, "update_analysis_and_wait", lambda: None)
    if asynchronous:
        result = complete(backend, backend.analysis_update(sid))
        assert result["status"] == "failed"
    else:
        result = tool(backend, "analysis.update_and_wait", session_id=sid)
        assert result["isError"]
        assert result["structuredContent"]["status"] == "failed"
    assert backend.analysis_status(sid)["status"] == "failed"
    assert view.analysis_state == state
    assert view.analysis_is_aborted is aborted


def test_raw_context_leases_sessions_published_after_outer_admission(backend):
    outer_entered, build_context = threading.Event(), threading.Event()
    backend._bn.eval_entered = threading.Event()
    backend._bn.eval_release = threading.Event()
    backend.open_session("old", update_analysis=False)

    def evaluate():
        with backend._operation_scope("binja.eval", {}):
            outer_entered.set()
            assert build_context.wait(5)
            return backend.eval_code(
                "(bn.eval_entered.set(), bn.eval_release.wait(5), "
                "[v.file.closed for v in sessions.values()])[2]"
            )

    with ThreadPoolExecutor() as pool:
        evaluating = pool.submit(evaluate)
        try:
            assert outer_entered.wait(5)
            sid = backend.open_session("new", update_analysis=False)["session_id"]
            build_context.set()
            assert backend._bn.eval_entered.wait(5)
            closing = pool.submit(backend.close_session, sid)
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.1)
        finally:
            build_context.set()
            backend._bn.eval_release.set()
        assert evaluating.result(timeout=5)["result"] == [False, False]
        closing.result(timeout=5)


@pytest.mark.parametrize("operation", ["analysis.update_and_wait", "binary.summary"])
def test_rebase_rejects_active_analysis_and_readers(backend, operation):
    sid, view = open_view(backend)
    backend.set_session_mode(sid, read_only=False)
    view.release.clear()
    view.rebase = lambda *_args, **_kwargs: ControlledView("replacement")
    entered, release = threading.Event(), threading.Event()

    def admitted():
        with backend._operation_scope(operation, {"session_id": sid}):
            if operation == "analysis.update_and_wait":
                return backend.analysis_update_and_wait(sid)
            entered.set()
            assert release.wait(5)
            return backend.binary_summary(sid)

    with ThreadPoolExecutor() as pool:
        active = pool.submit(admitted)
        try:
            assert (view.started if operation == "analysis.update_and_wait" else entered).wait(5)
            rebased = tool(backend, "loader.rebase", session_id=sid, address="0x800000")
            assert rebased["isError"]
            assert not view.closed_while_active
            assert not view.file.closed
        finally:
            view.release.set()
            release.set()
        active.result(timeout=5)


def test_rebase_blocks_new_calls_and_close_drains_replacement(backend):
    sid, view = open_view(backend)
    backend.set_session_mode(sid, read_only=False)
    replacement = ControlledView("replacement")
    entered, release = threading.Event(), threading.Event()

    def rebase(*_args, **_kwargs):
        entered.set()
        assert release.wait(5)
        return replacement

    view.rebase = rebase
    with ThreadPoolExecutor() as pool:
        rebasing = pool.submit(tool, backend, "loader.rebase", session_id=sid, address="0x800000")
        try:
            assert entered.wait(5)
            for name in ("analysis.update", "analysis.update_and_wait", "binary.functions"):
                assert tool(backend, name, session_id=sid)["isError"]
            assert backend.analysis_status(sid)["replacing"]
            assert backend.list_sessions()["sessions"][0]["replacing"]
            closing = pool.submit(backend.close_session, sid)
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.1)
            assert not view.file.closed
            assert not replacement.file.closed
        finally:
            release.set()
        assert not rebasing.result(timeout=5)["isError"]
        assert closing.result(timeout=5)["closed"]
    assert view.file.closed and replacement.file.closed


def test_rebase_preserves_shared_file_and_resets_view_caches(backend):
    sid, view = open_view(backend)
    backend.set_session_mode(sid, read_only=False)
    replacement = ControlledView("fixture")
    replacement.file = view.file
    view.rebase = lambda *_args, **_kwargs: replacement
    backend._base_detectors[sid] = object()
    backend.analysis_update_and_wait(sid)
    assert backend.loader_rebase(sid, "0x800000")["rebased"]
    assert not replacement.file.closed
    assert sid not in backend._base_detectors
    assert backend.analysis_status(sid)["status"] == "idle"
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"
    backend.close_session(sid)
    assert replacement.file.closed


@pytest.mark.parametrize("control", ["hold", "disable"])
def test_transient_control_change_cannot_hide_interrupted_analysis(backend, monkeypatch, control):
    sid, view = open_view(backend)
    entered, returned, release = threading.Event(), threading.Event(), threading.Event()
    native_stopped = threading.Event()

    def wait():
        entered.set()
        assert native_stopped.wait(5)
        returned.set()
        assert release.wait(5)

    def hold(value):
        view.analysis_state = "HoldState" if value else "IdleState"
        if value:
            native_stopped.set()

    def disable():
        view.analysis_is_aborted = True
        native_stopped.set()

    monkeypatch.setattr(view, "update_analysis_and_wait", wait)
    monkeypatch.setattr(view, "set_analysis_hold", hold, raising=False)
    monkeypatch.setattr(view.workflow.machine, "disable", disable, raising=False)
    monkeypatch.setattr(view.workflow.machine, "status", lambda: {}, raising=False)
    task = backend.analysis_update(sid)
    try:
        assert entered.wait(5)
        if control == "hold":
            backend.analysis_set_hold(sid, True)
        else:
            backend.workflow_machine_control(sid, "disable")
        assert returned.wait(5)
        if control == "hold":
            backend.analysis_set_hold(sid, False)
        else:
            backend.workflow_machine_control(sid, "enable")
        assert view.analysis_state == "IdleState" and not view.analysis_is_aborted
    finally:
        native_stopped.set()
        release.set()
    result = complete(backend, task)
    assert result["status"] == "failed"
    assert "interrupted by a native control change" in result["error"]
    monkeypatch.undo()
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


def test_inflight_control_blocks_new_analysis_and_close_drains_it(backend, monkeypatch):
    sid, view = open_view(backend)
    entered, release = threading.Event(), threading.Event()

    def hold(_value):
        entered.set()
        assert release.wait(5)

    monkeypatch.setattr(view, "set_analysis_hold", hold, raising=False)
    with ThreadPoolExecutor() as pool:
        changing = pool.submit(backend.analysis_set_hold, sid, True)
        try:
            assert entered.wait(5)
            assert backend.analysis_status(sid)["control_in_progress"]
            for operation in (backend.analysis_update, backend.analysis_update_and_wait):
                with pytest.raises(BinjaBackendError, match="control is in progress"):
                    operation(sid)
            closing = pool.submit(backend.close_session, sid)
            with pytest.raises(TimeoutError):
                closing.result(timeout=0.1)
            assert not view.file.closed
        finally:
            release.set()
        changing.result(timeout=5)
        assert closing.result(timeout=5)["closed"]


def test_invalid_workflow_control_does_not_invalidate_active_analysis(backend):
    sid, view = open_view(backend)
    view.release.clear()
    task = backend.analysis_update(sid)
    try:
        assert view.started.wait(5)
        with pytest.raises(BinjaBackendError, match="action must be"):
            backend.workflow_machine_control(sid, "not-an-action")
    finally:
        view.release.set()
    assert complete(backend, task)["status"] == "completed"


@pytest.mark.parametrize("delayed_abort", [False, True])
def test_explicit_disable_supersedes_automatic_resume(backend, monkeypatch, delayed_abort):
    sid, view = open_view(backend)
    monkeypatch.setattr(view.workflow.machine, "status", lambda: {}, raising=False)
    monkeypatch.setattr(
        view.workflow.machine,
        "disable",
        lambda: setattr(view, "analysis_is_aborted", True),
        raising=False,
    )
    if delayed_abort:
        view.release.clear()
        view.abort_release.clear()
        task = backend.analysis_update(sid)
        assert view.started.wait(5)
        backend.task_cancel(task["task_id"])
        assert view.abort_started.wait(5)
    else:
        backend.analysis_abort(sid)
        assert backend._get_record(sid).resume_after_abort
    try:
        backend.workflow_machine_control(sid, "disable")
    finally:
        view.release.set()
        view.abort_release.set()
    if delayed_abort:
        assert complete(backend, task)["status"] == "cancelled"
    assert not backend._get_record(sid).resume_after_abort
    with pytest.raises(BinjaBackendError, match="aborted or disabled"):
        backend.analysis_update_and_wait(sid)
    assert view.enable_calls == 0
    backend.workflow_machine_control(sid, "enable")
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"


@pytest.mark.parametrize("mode", ["full", "intermediate", "basic", "controlFlow"])
@pytest.mark.parametrize("autorun", [False, True])
def test_initial_discovery_recovery_respects_native_settings(backend, monkeypatch, mode, autorun):
    sid, view = open_view(backend)
    initialized = False
    options = []
    abort = view.abort_analysis

    def interrupted():
        nonlocal initialized
        abort()
        initialized = True  # Native abort changes this flag even on partial analysis.

    class Settings:
        @staticmethod
        def get_string(key, resource):
            assert key == "analysis.mode" and resource is view
            return mode

        @staticmethod
        def get_bool(key, resource):
            assert key == "analysis.linearSweep.autorun" and resource is view
            return autorun

    monkeypatch.setattr(view, "has_initial_analysis", lambda: initialized, raising=False)
    monkeypatch.setattr(view, "abort_analysis", interrupted)
    monkeypatch.setattr(view, "add_analysis_option", options.append, raising=False)
    monkeypatch.setattr(backend._bn, "Settings", Settings, raising=False)
    backend.analysis_abort(sid)
    assert backend.analysis_status(sid)["discovery_recovery_pending"]
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"
    assert options == (["linearsweep"] if autorun else [])
    assert Settings.get_string("analysis.mode", view) == mode
    assert not backend.analysis_status(sid)["discovery_recovery_pending"]


def test_failed_old_resume_cannot_override_new_explicit_disable(backend, monkeypatch):
    sid, view = open_view(backend)
    backend.analysis_abort(sid)
    entered, release = threading.Event(), threading.Event()

    def failing_enable():
        entered.set()
        assert release.wait(5)
        raise RuntimeError("enable failed")

    monkeypatch.setattr(view.workflow.machine, "enable", failing_enable)
    monkeypatch.setattr(view.workflow.machine, "status", lambda: {}, raising=False)
    monkeypatch.setattr(
        view.workflow.machine,
        "disable",
        lambda: setattr(view, "analysis_is_aborted", True),
        raising=False,
    )
    task = backend.analysis_update(sid)
    try:
        assert entered.wait(5)
        backend.workflow_machine_control(sid, "disable")
    finally:
        release.set()
    assert complete(backend, task)["status"] == "failed"
    assert not backend._get_record(sid).resume_after_abort
    with pytest.raises(BinjaBackendError, match="aborted or disabled"):
        backend.analysis_update_and_wait(sid)


def test_discovery_bookkeeping_failure_cannot_prevent_abort(backend, monkeypatch):
    sid, view = open_view(backend)

    def fail():
        raise RuntimeError("initial analysis unavailable")

    monkeypatch.setattr(view, "has_initial_analysis", fail, raising=False)
    backend.analysis_abort(sid)
    assert view.abort_calls == 1 and view.analysis_is_aborted
    assert backend._get_record(sid).recover_initial_discovery


@pytest.mark.parametrize("process,fail", [(False, False), (True, False), (True, True)])
def test_transform_cleanup_preserves_borrowed_view(backend, monkeypatch, process, fail):
    import gc
    from types import SimpleNamespace

    sid, view = open_view(backend)
    released = []

    class TransformSession:
        def __init__(self, target, *, mode):
            _ = mode
            assert target is view
            self.root_context = SimpleNamespace(is_root=True)
            self.selected_contexts = []

        def set_selected_contexts(self, context):
            self.selected_contexts = [context]

        def process(self):
            assert self.root_context in self.selected_contexts
            if fail:
                raise RuntimeError("transform failed")

        def __del__(self):
            released.append(True)
            if self.root_context not in self.selected_contexts:
                view.analysis_is_aborted = True

    monkeypatch.setattr(backend._bn, "TransformSession", TransformSession, raising=False)
    monkeypatch.setattr(backend, "_resolve_transform_mode", lambda _mode: 0)
    if fail:
        with pytest.raises(BinjaBackendError, match="transform failed"):
            backend.transform_inspect(session_id=sid, process=process)
    else:
        result = backend.transform_inspect(session_id=sid, process=process)
        assert result["selected_context_count"] == 1
    gc.collect()
    assert released and not view.analysis_is_aborted
    assert backend.analysis_update_and_wait(sid)["status"] == "completed"
