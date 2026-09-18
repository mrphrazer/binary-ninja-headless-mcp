from __future__ import annotations

import time
from pathlib import Path

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend, BinjaBackendError


def _open(
    real_backend: BinjaBackend,
    sample_binary_path: str,
    *,
    read_only: bool = True,
) -> str:
    summary = real_backend.open_session(
        sample_binary_path,
        update_analysis=False,
        read_only=read_only,
        deterministic=True,
    )
    return summary["session_id"]


def _find_function_start(functions: dict[str, object], name: str) -> str:
    for item in functions["items"]:  # type: ignore[index]
        assert isinstance(item, dict)
        if item.get("name") == name:
            start = item.get("start")
            assert isinstance(start, str)
            return start
    raise AssertionError(f"function not found: {name}")


def _wait_task_completed(
    real_backend: BinjaBackend,
    task_id: str,
    timeout: float = 10.0,
) -> dict[str, object]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        status = real_backend.task_status(task_id)
        if status["status"] in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(0.05)
    raise AssertionError(f"task did not complete: {task_id}")


def _assert_hex_match(match: object) -> None:
    assert isinstance(match, str)
    assert "databuffer" not in match.lower()
    int(match, 16)


def test_open_list_summary_mode_and_close(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    summary = real_backend.open_session(sample_binary_path, update_analysis=False)

    assert summary["filename"] == sample_binary_path
    assert isinstance(summary["arch"], str)
    assert summary["arch"]
    assert summary["read_only"] is True
    assert summary["deterministic"] is True

    mode = real_backend.session_mode(summary["session_id"])
    assert mode["read_only"] is True
    assert mode["deterministic"] is True

    listed = real_backend.list_sessions()
    assert listed["count"] == 1

    closed = real_backend.close_session(summary["session_id"])
    assert closed == {"closed": True, "session_id": summary["session_id"]}
    assert real_backend.list_sessions()["count"] == 0


def test_safety_mode_enforcement(real_backend: BinjaBackend, sample_binary_path: str) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=True)

    eval_result = real_backend.eval_code("bv.entry_point", session_id=session_id)
    assert isinstance(eval_result["result"], int)
    assert eval_result["result"] > 0
    assert eval_result["mode_transitioned"] is True
    assert eval_result["transitioned_session_ids"] == [session_id]

    mode_after_eval = real_backend.session_mode(session_id)
    assert mode_after_eval["read_only"] is False

    updated_mode = real_backend.set_session_mode(session_id, read_only=True, deterministic=False)
    assert updated_mode["read_only"] is True
    assert updated_mode["deterministic"] is False

    call_result = real_backend.call_api("bv.update_analysis", session_id=session_id)
    assert call_result["callable"] is True
    assert call_result["mode_transitioned"] is True
    assert call_result["transitioned_session_ids"] == [session_id]


def test_eval_code_captures_stdout_and_stderr(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)

    evaluated = real_backend.eval_code(
        "import sys\nprint('stdout from eval')\nprint('stderr from eval', file=sys.stderr)\n_ = 99",
        session_id=session_id,
    )
    assert evaluated["result"] == 99
    assert evaluated["stdout"] == "stdout from eval\n"
    assert evaluated["stderr"] == "stderr from eval\n"


def test_analysis_and_navigation_features(
    real_backend: BinjaBackend,
    sample_binary_path: str,
) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)

    status_before = real_backend.analysis_status(session_id)
    assert "state" in status_before

    set_hold = real_backend.analysis_set_hold(session_id, True)
    assert set_hold["hold"] is True
    real_backend.analysis_set_hold(session_id, False)

    status_after_update = real_backend.analysis_update(session_id, wait=False)
    assert status_after_update["session_id"] == session_id
    assert (
        _wait_task_completed(real_backend, status_after_update["task_id"])["status"] == "completed"
    )

    status_after_wait = real_backend.analysis_update(session_id, wait=True)
    assert status_after_wait["session_id"] == session_id

    progress = real_backend.analysis_progress(session_id)
    assert "progress" in progress

    sections = real_backend.list_sections(session_id, offset=0, limit=10)
    assert sections["total"] >= 1

    segments = real_backend.list_segments(session_id, offset=0, limit=10)
    assert segments["total"] >= 1

    symbols = real_backend.list_symbols(session_id, offset=0, limit=10)
    assert symbols["total"] >= 1

    data_vars = real_backend.list_data_vars(session_id, offset=0, limit=10)
    assert data_vars["total"] >= 1

    summary = real_backend.binary_summary(session_id)
    entry = int(summary["entry_point"], 16)
    function_at = real_backend.get_function_at(session_id, entry)
    assert function_at["function"]["start"].startswith("0x")


def test_xrefs_disasm_and_il_features(real_backend: BinjaBackend, sample_binary_path: str) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)
    real_backend.analysis_update(session_id, wait=True)

    functions = real_backend.list_functions(session_id, offset=0, limit=200)
    main_start = _find_function_start(functions, "main")
    add_start = _find_function_start(functions, "add_numbers")

    callers = real_backend.function_callers(session_id, add_start)
    assert callers["count"] >= 1

    callees = real_backend.function_callees(session_id, main_start)
    assert callees["count"] >= 1

    refs_to = real_backend.code_refs_to(session_id, add_start, offset=0, limit=20)
    assert refs_to["total"] >= 1

    ref_from = refs_to["items"][0]["from"]
    refs_from = real_backend.code_refs_from(session_id, ref_from, length=4)
    assert refs_from["count"] >= 1

    search = real_backend.search_text(session_id, "Hello", limit=10)
    assert search["count"] >= 1
    _assert_hex_match(search["items"][0]["match"])
    string_address = search["items"][0]["address"]

    data_to = real_backend.data_refs_to(session_id, string_address, limit=20)
    assert data_to["count"] >= 0

    data_from = real_backend.data_refs_from(session_id, main_start, length=4)
    assert data_from["count"] >= 0

    disasm_function = real_backend.disasm_function(session_id, int(main_start, 0) + 1)
    assert disasm_function["total"] >= 1
    assert disasm_function["items"][0]["text"]
    assert disasm_function["function"]["start"] == main_start
    assert disasm_function["total"] == len(disasm_function["items"])

    disasm_at = real_backend.get_function_disassembly_at(session_id, int(main_start, 0) + 2)
    assert disasm_at["function"]["start"] == main_start
    assert disasm_at["total"] == len(disasm_at["items"])

    il_at = real_backend.get_function_il_at(
        session_id,
        int(main_start, 0) + 3,
        level="hlil",
        ssa=False,
    )
    assert il_at["function"]["start"] == main_start
    assert il_at["level"] == "hlil"
    assert il_at["total"] == len(il_at["items"])

    disasm_range = real_backend.disasm_range(session_id, main_start, length=16, limit=10)
    assert disasm_range["count"] >= 1

    il_function = real_backend.il_function(
        session_id,
        main_start,
        level="mlil",
        ssa=False,
        offset=0,
        limit=20,
    )
    assert il_function["total"] >= 1

    first_il = il_function["items"][0]
    il_by_addr = real_backend.il_instruction_by_addr(
        session_id,
        main_start,
        first_il["address"],
        level="mlil",
        ssa=False,
    )
    assert il_by_addr["instruction"]["address"] == first_il["address"]

    addr_to_index = real_backend.il_address_to_index(
        session_id,
        main_start,
        first_il["address"],
        level="mlil",
        ssa=False,
    )
    assert first_il["index"] in addr_to_index["indices"]

    index_to_addr = real_backend.il_index_to_address(
        session_id,
        main_start,
        first_il["index"],
        level="mlil",
        ssa=False,
    )
    assert index_to_addr["address"] == first_il["address"]


def test_async_tasks_and_persistence(
    real_backend: BinjaBackend,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open(real_backend, sample_binary_path, read_only=False)

    task_search = real_backend.task_start_search_text(session_id, "Hello", limit=10)
    search_task_id = task_search["task_id"]
    completed_search = _wait_task_completed(real_backend, search_task_id)
    assert completed_search["status"] == "completed"

    search_result = real_backend.task_result(search_task_id)
    assert search_result["result"]["count"] >= 1
    _assert_hex_match(search_result["result"]["items"][0]["match"])

    task_analysis = real_backend.task_start_analysis_update(session_id)
    analysis_task_id = task_analysis["task_id"]
    completed_analysis = _wait_task_completed(real_backend, analysis_task_id)
    assert completed_analysis["status"] == "completed"

    cancel_result = real_backend.task_cancel(search_task_id)
    assert cancel_result["cancel_requested"] is False
    assert cancel_result["status"] == "completed"

    bndb_path = tmp_path / "hello.bndb"
    created = real_backend.create_database(session_id, str(bndb_path))
    assert created["created"] is True
    assert bndb_path.exists()

    snapshot = real_backend.save_auto_snapshot(session_id)
    assert snapshot["saved"] is True

    saved_binary_path = tmp_path / "hello.saved"
    saved_binary = real_backend.save_binary(session_id, str(saved_binary_path))
    assert saved_binary["saved"] is True
    assert saved_binary_path.exists()

    reopened = real_backend.open_session(str(bndb_path), update_analysis=False, read_only=True)
    assert reopened["filename"] == str(bndb_path)

    real_backend.close_session(reopened["session_id"])


def test_backend_errors(real_backend: BinjaBackend, sample_binary_path: str) -> None:
    with pytest.raises(BinjaBackendError, match="unknown session_id"):
        real_backend.close_session("nope")

    with pytest.raises(BinjaBackendError, match="path is required"):
        real_backend.open_session("")

    session_id = _open(real_backend, sample_binary_path)
    with pytest.raises(BinjaBackendError, match="offset must be >= 0"):
        real_backend.list_functions(session_id, offset=-1, limit=10)

    with pytest.raises(BinjaBackendError, match="session_id is required"):
        real_backend.call_api("bv.start")

    with pytest.raises(BinjaBackendError, match="read-only"):
        real_backend.save_binary(session_id, sample_binary_path)

    with pytest.raises(BinjaBackendError, match="unknown task_id"):
        real_backend.task_status("missing-task")
