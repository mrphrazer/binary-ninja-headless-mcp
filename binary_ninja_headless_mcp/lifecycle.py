"""Session ownership and task coordination, independent of the native engine."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import Future, ThreadPoolExecutor
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

CLOSE_DRAIN_TIMEOUT_S = 30.0
TERMINAL_STATES = frozenset({"completed", "failed", "cancelled"})


class BinjaBackendError(RuntimeError):
    """A tool error with optional machine-readable recovery information."""

    def __init__(self, message: str, **details: Any):
        super().__init__(message)
        self.details = details


class AnalysisCancelled(BinjaBackendError):
    """An analysis stopped before completion."""


@dataclass
class AnalysisRun:
    run_id: str = field(default_factory=lambda: uuid4().hex)
    task_id: str | None = None
    started: bool = False
    native_done: bool = False
    cancel_requested: bool = False
    abort_future: Future[Any] | None = None
    control_generation: int = 0
    initial_discovery_pending: bool = False


@dataclass
class SessionRecord:
    session_id: str
    view: Any
    read_only: bool = True
    deterministic: bool = True
    temp_path: str | None = None
    has_byte_edits: bool = False
    closing: bool = False
    replacing: bool = False
    active_operations: int = 0
    active_analysis: AnalysisRun | None = None
    control_generation: int = 0
    control_operations: int = 0
    last_analysis_status: str = "idle"
    last_analysis_started_at: float | None = None
    last_analysis_completed_at: float | None = None
    last_analysis_task_id: str | None = None
    last_analysis_error: str | None = None
    resume_after_abort: bool = False
    resume_generation: int = 0
    recover_initial_discovery: bool = False
    native_status: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    close_abort: Future[Any] | None = None
    close_lock: Any = field(default_factory=threading.Lock)


@dataclass
class TaskRecord:
    task_id: str
    kind: str
    future: Future[Any]
    session_id: str | None
    cancel_hook: Callable[[], None] | None = None
    cancel_requested: bool = False
    created_at: float = field(default_factory=time.time)
    worker_future: Future[Any] | None = None
    analysis_run: AnalysisRun | None = None


class LifecycleMixin:
    """Private helpers used by the backend and its MCP request boundary."""

    def _init_lifecycle(self) -> None:
        self._lock = threading.RLock()
        self._condition = threading.Condition(self._lock)
        self._local = threading.local()
        self._active_calls = 0
        self._shutting_down = False
        self._shutdown_complete = False
        self._shutdown_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="binary_ninja_headless_mcp"
        )

    def _ensure_running(self) -> None:
        if self._shutting_down:
            raise BinjaBackendError("backend is shutting down")

    def _lookup_record(self, session_id: str) -> SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise BinjaBackendError(f"unknown session_id: {session_id}")
        return record

    def _get_record(self, session_id: str) -> SessionRecord:
        with self._lock:
            record = self._lookup_record(session_id)
            allowed = getattr(self._local, "sessions", {})
            if record.closing and not allowed.get(session_id):
                raise BinjaBackendError(
                    f"session {session_id} is closing", session_id=session_id, status="closing"
                )
            if record.replacing and not self._owns_replacement(session_id):
                raise BinjaBackendError(
                    f"session {session_id} is being rebased", session_id=session_id
                )
            return record

    def _owns_replacement(self, session_id: str) -> bool:
        return session_id in getattr(self._local, "replacements", ())

    @contextmanager
    def _exclusive_session(self, session_id: str) -> Iterator[SessionRecord]:
        """Reserve view replacement; existing users finish or the caller retries."""
        with self._condition:
            self._ensure_running()
            record = self._get_record(session_id)
            own_leases = getattr(self._local, "sessions", {}).get(session_id, 0)
            if record.closing or record.replacing:
                raise BinjaBackendError(
                    "session is closing or being rebased", session_id=session_id
                )
            if record.active_analysis is not None or record.active_operations > own_leases:
                raise BinjaBackendError(
                    "rebase is not allowed while analysis or other operations are active; "
                    "wait for completion and retry",
                    session_id=session_id,
                )
            record.replacing = True
            record.active_operations += 1
            replacements = getattr(self._local, "replacements", None)
            if replacements is None:
                replacements = self._local.replacements = set()
            replacements.add(session_id)
        try:
            with self._allow_record(record):
                yield record
        finally:
            with self._condition:
                replacements.remove(session_id)
                record.replacing = False
                record.active_operations -= 1
                self._condition.notify_all()

    @contextmanager
    def _allow_record(self, record: SessionRecord) -> Iterator[None]:
        allowed = getattr(self._local, "sessions", None)
        if allowed is None:
            allowed = self._local.sessions = {}
        allowed[record.session_id] = allowed.get(record.session_id, 0) + 1
        try:
            yield
        finally:
            allowed[record.session_id] -= 1
            if not allowed[record.session_id]:
                del allowed[record.session_id]

    @contextmanager
    def _operation_scope(
        self, name: str, arguments: dict[str, Any]
    ) -> Iterator[list[SessionRecord]]:
        """Lease views for an entire MCP call, including native serialization."""
        records = []
        metadata_tools = {
            "health.ping",
            "mcp.response_format",
            "task.status",
            "task.result",
            "task.cancel",
            "session.close",
            "analysis.status",
            "session.list",
        }
        with self._condition:
            if name not in metadata_tools:
                self._ensure_running()
            ids = {
                value
                for key in ("session_id", "source_session_id")
                if isinstance(value := arguments.get(key), str)
            }
            if name in {"session.list", "binja.eval", "binja.call"}:
                ids.update(self._sessions)
            if name == "session.close":
                ids.clear()
            for sid in sorted(ids):
                record = self._lookup_record(sid)
                if (record.closing or record.replacing) and name in {
                    "analysis.status",
                    "session.list",
                }:
                    continue
                if record.closing:
                    raise BinjaBackendError(
                        f"session {sid} is closing", session_id=sid, status="closing"
                    )
                if record.replacing and not self._owns_replacement(sid):
                    raise BinjaBackendError(f"session {sid} is being rebased", session_id=sid)
                records.append(record)
            for record in records:
                record.active_operations += 1
            self._active_calls += 1
        try:
            # Nested raw API calls remain covered by these reservations.
            from contextlib import ExitStack

            with ExitStack() as stack:
                for record in records:
                    stack.enter_context(self._allow_record(record))
                yield records
        finally:
            with self._condition:
                for record in records:
                    record.active_operations -= 1
                self._active_calls -= 1
                self._condition.notify_all()

    def _begin_analysis(self, session_id: str) -> tuple[SessionRecord, AnalysisRun]:
        with self._condition:
            self._ensure_running()
            record = self._get_record(session_id)
            if record.closing:
                raise BinjaBackendError(f"session {session_id} is closing", session_id=session_id)
            if record.active_analysis is not None:
                raise BinjaBackendError(
                    f"analysis is already running for session {session_id}; "
                    "wait for it to complete before starting another",
                    session_id=session_id,
                    task_id=record.last_analysis_task_id,
                )
            if record.control_operations:
                raise BinjaBackendError(
                    "analysis control is in progress; wait for it to finish and retry",
                    session_id=session_id,
                )
            run = AnalysisRun(control_generation=record.control_generation)
            record.active_analysis = run
            record.last_analysis_status = "running"
            record.last_analysis_started_at = time.time()
            record.last_analysis_completed_at = None
            record.last_analysis_task_id = None
            record.last_analysis_error = None
            return record, run

    @contextmanager
    def _analysis_control(
        self, session_id: str, *, interrupts: bool = True
    ) -> Iterator[SessionRecord]:
        with self._condition:
            self._ensure_running()
            record = self._get_record(session_id)
            if record.closing:
                raise BinjaBackendError("session is closing", session_id=session_id)
            record.active_operations += 1
            record.control_operations += 1
            if interrupts:
                record.control_generation += 1
        try:
            with self._allow_record(record):
                yield record
        finally:
            with self._condition:
                record.control_operations -= 1
                record.active_operations -= 1
                self._condition.notify_all()

    @staticmethod
    def _managed_status(record: SessionRecord) -> dict[str, Any]:
        return {
            "session_id": record.session_id,
            "status": record.last_analysis_status,
            "last_analysis_started_at": record.last_analysis_started_at,
            "last_analysis_completed_at": record.last_analysis_completed_at,
            "last_analysis_task_id": record.last_analysis_task_id,
            "last_analysis_error": record.last_analysis_error,
            "has_log": False,
            "closing": record.closing,
            "replacing": record.replacing,
            "control_in_progress": bool(record.control_operations),
            "discovery_recovery_pending": record.recover_initial_discovery,
        }

    def _finish_analysis(
        self,
        record: SessionRecord,
        run: AnalysisRun,
        status: str,
        error: str | None = None,
    ) -> None:
        with self._condition:
            if record.active_analysis is not run:
                return
            record.last_analysis_status = status
            record.last_analysis_completed_at = time.time()
            record.last_analysis_error = error
            if status == "completed":
                record.recover_initial_discovery = False
            record.active_analysis = None
            self._condition.notify_all()

    def _resume_analysis(self, record: SessionRecord) -> None:
        with self._lock:
            if not record.resume_after_abort:
                return
            # Consume the old obligation before enabling: a concurrent newer
            # abort may publish another one while the native call returns.
            record.resume_after_abort = False
            resume_generation = record.resume_generation
        try:
            # Abort suspends the BN workflow. Only undo our own suspension.
            machine = getattr(getattr(record.view, "workflow", None), "machine", None)
            if machine is not None:
                machine.enable()
        except Exception:
            with self._lock:
                if record.resume_generation == resume_generation:
                    record.resume_after_abort = True
            raise

    def _execute_analysis(self, record: SessionRecord, run: AnalysisRun) -> None:
        initial = getattr(record.view, "has_initial_analysis", None)
        initial_pending = initial is not None and not initial()
        with self._lock:
            run.initial_discovery_pending = initial_pending
            cancelled = run.cancel_requested
            run.started = not cancelled
        if not cancelled:
            self._resume_analysis(record)
            before = self._native_analysis_status(record.view)
            with self._lock:
                cancelled = run.cancel_requested
                if not cancelled:
                    self._check_analysis_control(record, run)
                    self._check_analysis_suspension(before)
            if not cancelled:
                self._restore_initial_discovery(record)
                record.view.update_analysis_and_wait()

    def _run_analysis(self, record: SessionRecord, run: AnalysisRun) -> dict[str, Any]:
        error = None
        native = {}
        try:
            self._execute_analysis(record, run)
        except Exception as exc:
            error = exc
        finally:
            with self._lock:
                run.native_done = True
                abort = run.abort_future
            # Ownership lasts until an in-flight abort also finishes. Otherwise an
            # old abort can race a new run even after native analysis has stopped.
            if abort is not None:
                try:
                    abort.result()
                except Exception as exc:
                    error = BinjaBackendError(f"failed to abort analysis: {exc}")
                finally:
                    # Completed task metadata must not keep native abort frames/views alive.
                    run.abort_future = None
            try:
                native = self._native_analysis_status(record.view)
                record.native_status = native
            except Exception as exc:
                if error is None:
                    error = exc
            with self._condition:
                cancelled = run.cancel_requested
                if error is None and not cancelled:
                    try:
                        self._check_analysis_control(record, run)
                        self._check_analysis_suspension(native)
                    except BinjaBackendError as exc:
                        error = exc
                    if error is None and native.get("state") != "IdleState":
                        error = BinjaBackendError(
                            f"native analysis returned before reaching idle "
                            f"(state={native.get('state')}); retry after releasing holds "
                            "or resuming the workflow"
                        )
                status = (
                    "failed"
                    if isinstance(error, BinjaBackendError)
                    else "cancelled"
                    if cancelled
                    else "failed"
                    if error
                    else "completed"
                )
                self._finish_analysis(
                    record, run, status, str(error) if status == "failed" else None
                )
                result = {**native, **self._managed_status(record)}
        if status == "cancelled":
            raise AnalysisCancelled(
                "analysis cancelled", session_id=record.session_id, status="cancelled"
            )
        if error is not None:
            raise BinjaBackendError(
                f"analysis update failed: {error}", session_id=record.session_id, status="failed"
            ) from error
        return result

    @staticmethod
    def _check_analysis_control(record: SessionRecord, run: AnalysisRun) -> None:
        if record.control_generation != run.control_generation:
            raise BinjaBackendError(
                "analysis was interrupted by a native control change; "
                "wait for control operations to finish, release holds or enable the workflow, "
                "then retry analysis"
            )

    @staticmethod
    def _check_analysis_suspension(native: dict[str, Any]) -> None:
        if native.get("state") == "HoldState":
            raise BinjaBackendError("native analysis is held; release analysis.set_hold and retry")
        if native.get("is_aborted"):
            raise BinjaBackendError(
                "native analysis is aborted or disabled; enable the workflow and retry"
            )

    def _note_initial_interruption(self, record: SessionRecord) -> None:
        with self._lock:
            pending = (
                record.active_analysis is not None
                and record.active_analysis.initial_discovery_pending
            )
        initial = getattr(record.view, "has_initial_analysis", None)
        if not pending and initial is not None:
            try:
                pending = not initial()
            except Exception:
                # Optional bookkeeping must never prevent the native abort.
                pending = True
        if pending:
            with self._lock:
                # Native abort marks initial analysis done even if discovery was
                # interrupted. A normal subsequent update skips the missing sweep.
                record.recover_initial_discovery = True

    def _restore_initial_discovery(self, record: SessionRecord) -> None:
        if not record.recover_initial_discovery:
            return
        settings = self._bn.Settings()
        if settings.get_bool("analysis.linearSweep.autorun", record.view):
            record.view.add_analysis_option("linearsweep")

    @staticmethod
    def _background_call(func: Callable[[], Any]) -> Future[Any]:
        future = Future()

        def invoke() -> None:
            try:
                future.set_result(func())
            except BaseException as exc:
                future.set_exception(exc)

        # Separate from the saturated analysis pool. Cleanup retains ownership of
        # the view until this future finishes, including a blocked native abort.
        threading.Thread(target=invoke, name="binja-analysis-abort", daemon=True).start()
        return future

    def _request_analysis_cancel(self, record: SessionRecord, run: AnalysisRun) -> bool:
        with self._condition:
            if record.active_analysis is not run or run.native_done:
                return False
            run.cancel_requested = True
            if run.started and run.abort_future is None:
                resume_generation = record.resume_generation

                def abort() -> None:
                    self._note_initial_interruption(record)
                    record.view.abort_analysis()
                    with self._lock:
                        if record.resume_generation == resume_generation:
                            record.resume_after_abort = True

                run.abort_future = self._background_call(abort)
            return True

    def _submit_task(
        self,
        *,
        kind: str,
        session_id: str | None,
        func: Callable[[], Any],
        cancel_hook: Callable[[], None] | None = None,
        analysis_run: AnalysisRun | None = None,
    ) -> dict[str, Any]:
        with self._condition:
            self._ensure_running()
            session = self._get_record(session_id) if session_id is not None else None
            if session is not None and session.closing:
                raise BinjaBackendError(f"session {session_id} is closing")
            task = TaskRecord(
                uuid4().hex, kind, Future(), session_id, cancel_hook, analysis_run=analysis_run
            )
            self._tasks[task.task_id] = task
            if session is not None:
                session.active_operations += 1
            if analysis_run is not None:
                analysis_run.task_id = task.task_id
                session.last_analysis_task_id = task.task_id

            def execute() -> None:
                with self._lock:
                    if not task.future.set_running_or_notify_cancel():
                        return
                try:
                    if session is None:
                        result = func()
                    else:
                        with self._allow_record(session):
                            result = func()
                    task.future.set_result(result)
                except BaseException as exc:
                    # Futures retain exceptions indefinitely. Tracebacks/causes can
                    # retain this worker's closed view (and its whole analysis).
                    exc.__traceback__ = None
                    exc.__cause__ = None
                    exc.__context__ = None
                    task.future.set_exception(exc)

            def release(_worker: Future[Any]) -> None:
                nonlocal session
                with self._condition:
                    if session is not None:
                        session.active_operations -= 1
                        # Future keeps its callbacks after invocation. Release the
                        # callback's native-view reference when ownership ends.
                        session = None
                    self._condition.notify_all()

            try:
                task.worker_future = self._executor.submit(execute)
            except Exception:
                # submit can enqueue work before failing to start a thread. The
                # lock keeps that work from starting until this cancellation;
                # a later worker must never use a view whose lease we released.
                task.future.cancel()
                self._tasks.pop(task.task_id, None)
                if analysis_run is not None:
                    analysis_run.task_id = None
                    session.last_analysis_task_id = None
                if session is not None:
                    session.active_operations -= 1
                    session = None
                self._condition.notify_all()
                raise
            task.worker_future.add_done_callback(release)
            return self.task_status(task.task_id)

    def _get_task(self, task_id: str) -> TaskRecord:
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise BinjaBackendError(f"unknown task_id: {task_id}")
        return task

    @staticmethod
    def _task_status_value(record: TaskRecord) -> str:
        future = record.future
        if future.cancelled():
            return "cancelled"
        if future.done():
            error = future.exception()
            if isinstance(error, AnalysisCancelled):
                return "cancelled"
            return "failed" if error is not None else "completed"
        if future.running():
            return "cancelling" if record.cancel_requested else "running"
        return "queued"

    def _cancel_task(self, task_id: str) -> dict[str, Any]:
        with self._condition:
            task = self._get_task(task_id)
            cancelled = False
            hook_called = False
            if not task.future.done():
                cancelled = task.future.cancel()
                if cancelled:
                    task.cancel_requested = True
                    if task.analysis_run is not None:
                        session = self._lookup_record(task.session_id)
                        self._finish_analysis(session, task.analysis_run, "cancelled")
                    if task.worker_future is not None:
                        task.worker_future.cancel()
                elif task.analysis_run is not None:
                    session = self._lookup_record(task.session_id)
                    task.cancel_requested |= self._request_analysis_cancel(
                        session, task.analysis_run
                    )
                    hook_called = task.analysis_run.abort_future is not None
                else:
                    task.cancel_requested = True
                    if task.cancel_hook is not None:
                        task.cancel_hook()
                        hook_called = True
            return {
                "task_id": task_id,
                "kind": task.kind,
                "session_id": task.session_id,
                "cancel_requested": task.cancel_requested,
                "cancelled": cancelled,
                "future_cancelled": cancelled,
                "cancel_hook_called": hook_called,
                "status": self._task_status_value(task),
            }

    def _close_session(self, session_id: str, deadline: float) -> dict[str, Any]:
        with self._condition:
            record = self._lookup_record(session_id)
            record.closing = True
            tasks = [t.task_id for t in self._tasks.values() if t.session_id == session_id]
            if record.active_analysis is not None:
                self._request_analysis_cancel(record, record.active_analysis)
        for task_id in tasks:
            self._cancel_task(task_id)
        remaining = max(0.0, deadline - time.monotonic())
        if not record.close_lock.acquire(timeout=remaining):
            raise BinjaBackendError("session close is already in progress", session_id=session_id)
        try:
            with self._condition:
                if session_id not in self._sessions:
                    return {"session_id": session_id, "closed": True}
                while record.active_analysis is not None or record.active_operations:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise BinjaBackendError(
                            "timed out draining session; resources retained; retry session.close",
                            session_id=session_id,
                            status="closing",
                        )
                    self._condition.wait(remaining)
                # Also stop native auto-analysis triggered by earlier edits.
                if record.close_abort is None:
                    record.close_abort = self._background_call(record.view.abort_analysis)
            try:
                record.close_abort.result(timeout=max(0.0, deadline - time.monotonic()))
            except TimeoutError as exc:
                raise BinjaBackendError(
                    "timed out aborting native analysis; resources retained; retry session.close",
                    session_id=session_id,
                    status="closing",
                ) from exc
            except Exception as exc:
                # A failed abort did not establish that the native view is safe.
                # Retain the session, and let a later close retry the abort.
                record.close_abort = None
                raise BinjaBackendError(
                    f"failed to abort native analysis: {exc}; "
                    "resources retained; retry session.close",
                    session_id=session_id,
                    status="closing",
                ) from exc
            try:
                self._close_view(record.view)
            except Exception as exc:
                raise BinjaBackendError(
                    f"failed to close native view: {exc}; resources retained; retry session.close",
                    session_id=session_id,
                    status="closing",
                ) from exc
            with self._condition:
                self._sessions.pop(session_id, None)
                self._base_detectors.pop(session_id, None)
                delete_upload = record.temp_path and not any(
                    other.temp_path == record.temp_path for other in self._sessions.values()
                )
                self._condition.notify_all()
            if delete_upload:
                with suppress(OSError):
                    os.unlink(record.temp_path)
            return {"closed": True, "session_id": session_id}
        finally:
            record.close_lock.release()

    def _shutdown(self) -> None:
        deadline = time.monotonic() + CLOSE_DRAIN_TIMEOUT_S
        if not self._shutdown_lock.acquire(timeout=CLOSE_DRAIN_TIMEOUT_S):
            raise BinjaBackendError("shutdown is already in progress; retry shutdown")
        try:
            self._drain_shutdown(deadline)
        finally:
            self._shutdown_lock.release()

    def _drain_shutdown(self, deadline: float) -> None:
        with self._condition:
            if self._shutdown_complete:
                return
            self._shutting_down = True
            task_ids = list(self._tasks)
            sessions = list(self._sessions)
        for task_id in task_ids:
            self._cancel_task(task_id)
        errors = []
        for session_id in sessions:
            try:
                self._close_session(session_id, deadline)
            except BinjaBackendError as exc:
                with self._lock:
                    # Another admitted client may have completed session.close.
                    if session_id in self._sessions:
                        errors.append(str(exc))
        with self._condition:
            while self._active_calls:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    errors.append("timed out draining MCP calls")
                    break
                self._condition.wait(remaining)
        if errors:
            raise BinjaBackendError("shutdown incomplete: " + "; ".join(errors))
        self._executor.shutdown(wait=True, cancel_futures=True)
        for project in self._projects.values():
            project.close()
        self._projects.clear()
        self._base_detectors.clear()
        self._type_libraries.clear()
        self._type_archives.clear()
        self._shutdown_complete = True
