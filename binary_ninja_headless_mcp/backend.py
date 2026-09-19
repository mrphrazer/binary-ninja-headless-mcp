"""Backend abstraction over Binary Ninja APIs for the MCP server."""

from __future__ import annotations

import base64
import binascii
import io
import os
import re
import tempfile
import time
from contextlib import redirect_stderr, redirect_stdout, suppress
from dataclasses import fields, is_dataclass
from itertools import islice
from types import ModuleType
from typing import Any
from uuid import uuid4

from . import lifecycle
from .lifecycle import BinjaBackendError, LifecycleMixin, SessionRecord, TaskRecord

__all__ = ["BinjaBackend", "BinjaBackendError", "TaskRecord"]

DETERMINISM_ENV_KEYS = (
    "BN_DISABLE_USER_SETTINGS",
    "BN_DISABLE_USER_PLUGINS",
    "BN_DISABLE_REPOSITORY_PLUGINS",
)

MAX_MEMORY_READ_BYTES = 64 * 1024


class BinjaBackend(LifecycleMixin):
    """High-level Binja operations exposed to MCP tools."""

    def __init__(self, bn_module: ModuleType):
        self._bn = bn_module
        self._sessions: dict[str, SessionRecord] = {}
        self._tasks: dict[str, TaskRecord] = {}
        self._type_libraries: dict[str, Any] = {}
        self._type_archives: dict[str, Any] = {}
        self._projects: dict[str, Any] = {}
        self._base_detectors: dict[str, Any] = {}
        self._workflow_clones: dict[tuple[str, str], Any] = {}
        self._init_lifecycle()

    def ping(self) -> dict[str, str]:
        return {"status": "ok", "message": "pong"}

    def open_session(
        self,
        path: str,
        *,
        update_analysis: bool = True,
        options: dict[str, Any] | None = None,
        read_only: bool = True,
        deterministic: bool = True,
    ) -> dict[str, Any]:
        return self._open_session_path(
            path,
            update_analysis=update_analysis,
            options=options,
            read_only=read_only,
            deterministic=deterministic,
        )

    def _open_session_path(
        self,
        path: str,
        *,
        update_analysis: bool,
        options: dict[str, Any] | None,
        read_only: bool,
        deterministic: bool,
        temp_path: str | None = None,
    ) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")

        if deterministic:
            self._apply_determinism_env(True)

        with self._lock:
            self._ensure_running()
        view = self._load_view(path, update_analysis=False, options=options or {})
        session_id = self._register_session(
            view,
            read_only=read_only,
            deterministic=deterministic,
            temp_path=temp_path,
        )
        return self._finalize_open(session_id, update_analysis)

    def open_session_from_bytes(
        self,
        data_base64: str,
        *,
        filename: str = "binary_ninja_headless_mcp_bytes.bin",
        update_analysis: bool = True,
        options: dict[str, Any] | None = None,
        read_only: bool = True,
        deterministic: bool = True,
    ) -> dict[str, Any]:
        if not data_base64:
            raise BinjaBackendError("data_base64 is required")

        try:
            raw_bytes = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BinjaBackendError(f"invalid base64 data: {exc}") from exc

        if deterministic:
            self._apply_determinism_env(True)

        suffix = f".{filename}" if filename else ".bin"
        with tempfile.NamedTemporaryFile(
            prefix="binary_ninja_headless_mcp-",
            suffix=suffix,
            delete=False,
        ) as tmp:
            temp_path = tmp.name
            tmp.write(raw_bytes)

        try:
            view = self._load_view(
                temp_path,
                update_analysis=False,
                options=options or {},
            )
        except Exception:
            with suppress(OSError):
                os.unlink(temp_path)
            raise

        session_id = self._register_session(
            view,
            read_only=read_only,
            deterministic=deterministic,
            temp_path=temp_path,
        )
        return self._finalize_open(session_id, update_analysis)

    def open_session_from_existing(
        self,
        source_session_id: str,
        *,
        update_analysis: bool = False,
        options: dict[str, Any] | None = None,
        read_only: bool = True,
        deterministic: bool = True,
    ) -> dict[str, Any]:
        with self._operation_scope(
            "session.open_existing", {"source_session_id": source_session_id}
        ):
            source = self._get_record(source_session_id)
            source_path = self._safe_attr_chain(source.view, "file.filename")
            if not source_path:
                raise BinjaBackendError("source session has no filename to reopen")

            # Publish upload ownership together with the new session. Another
            # client may reopen it before its synchronous analysis has finished.
            return self._open_session_path(
                source_path,
                update_analysis=update_analysis,
                options=options,
                read_only=read_only,
                deterministic=deterministic,
                temp_path=source.temp_path if source.temp_path == source_path else None,
            )

    def _finalize_open(self, session_id: str, update_analysis: bool) -> dict[str, Any]:
        if update_analysis:
            self.analysis_update_and_wait(session_id)
        return self.binary_summary(session_id)

    def set_session_mode(
        self,
        session_id: str,
        *,
        read_only: bool | None = None,
        deterministic: bool | None = None,
    ) -> dict[str, Any]:
        record = self._get_record(session_id)

        if read_only is not None:
            record.read_only = read_only

        if deterministic is not None:
            record.deterministic = deterministic
            self._apply_determinism_env(deterministic)

        return self.session_mode(session_id)

    def session_mode(self, session_id: str) -> dict[str, Any]:
        record = self._get_record(session_id)
        return {
            "session_id": session_id,
            "read_only": record.read_only,
            "deterministic": record.deterministic,
            "deterministic_env": self._determinism_env_snapshot(),
        }

    def close_session(self, session_id: str) -> dict[str, Any]:
        result = self._close_session(session_id, time.monotonic() + lifecycle.CLOSE_DRAIN_TIMEOUT_S)
        with self._lock:
            for key in list(self._workflow_clones):
                if key[0] == session_id:
                    del self._workflow_clones[key]
        return result

    def _load_view(
        self,
        path: str,
        *,
        update_analysis: bool,
        options: dict[str, Any],
    ) -> Any:
        try:
            source = path
            with self._lock:
                projects = tuple(self._projects.values())
            for project in projects:
                lookup = getattr(project, "get_file_by_path_on_disk", None)
                if not callable(lookup):
                    continue
                project_file = lookup(path)
                if project_file is not None and project_file.path_on_disk == path:
                    # Passing the actual managed ProjectFile lets the native loader
                    # establish project context; filename loading cannot do that.
                    source = project_file
                    break
            view = self._bn.load(source, update_analysis=update_analysis, options=options)
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"failed to load binary: {exc}") from exc

        if view is None:
            raise BinjaBackendError("failed to load binary: no BinaryView returned")
        return view

    def _register_session(
        self,
        view: Any,
        *,
        read_only: bool,
        deterministic: bool,
        temp_path: str | None = None,
    ) -> str:
        with self._condition:
            if not self._shutting_down:
                session_id = uuid4().hex
                self._sessions[session_id] = SessionRecord(
                    session_id=session_id,
                    view=view,
                    read_only=read_only,
                    deterministic=deterministic,
                    temp_path=temp_path,
                )
                self._condition.notify_all()
                return session_id
        # A load admitted before shutdown can finish after the session snapshot.
        # Cleanup outside the global lock so cancellation/status stay responsive.
        self._close_view(view)
        if temp_path:
            with self._lock:
                shared = any(record.temp_path == temp_path for record in self._sessions.values())
            if not shared:
                with suppress(OSError):
                    os.unlink(temp_path)
        raise BinjaBackendError("backend is shutting down")

    def list_sessions(self) -> dict[str, Any]:
        with self._operation_scope("session.list", {}) as records:
            with self._lock:
                ids = {record.session_id for record in records}
                summaries = [
                    {
                        **record.summary,
                        "session_id": sid,
                        "closing": record.closing,
                        "replacing": record.replacing,
                    }
                    for sid, record in sorted(self._sessions.items())
                    if (record.closing or record.replacing) and sid not in ids
                ]
            summaries.extend(self.binary_summary(sid) for sid in sorted(ids))
        return {"sessions": summaries, "count": len(summaries)}

    def binary_summary(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._lookup_record(session_id)
            if record.closing or (record.replacing and not self._owns_replacement(session_id)):
                return {
                    **record.summary,
                    "session_id": session_id,
                    "closing": record.closing,
                    "replacing": record.replacing,
                }
            record.active_operations += 1
        try:
            view = record.view

            filename = self._safe_attr_chain(view, "file.filename")
            arch = self._safe_attr_chain(view, "arch.name")

            summary = {
                "session_id": session_id,
                "filename": filename,
                "arch": arch,
                "view_type": self._safe_attr(view, "view_type"),
                "start": self._hex_or_none(self._safe_attr(view, "start")),
                "end": self._hex_or_none(self._safe_attr(view, "end")),
                "entry_point": self._hex_or_none(self._safe_attr(view, "entry_point")),
                "function_count": self._iter_count(self._safe_attr(view, "functions")),
                "string_count": self._iter_count(self._safe_attr(view, "strings")),
                "read_only": record.read_only,
                "deterministic": record.deterministic,
            }
            with self._lock:
                record.summary = summary
            return summary
        finally:
            with self._condition:
                record.active_operations -= 1
                self._condition.notify_all()

    def analysis_update(self, session_id: str, *, wait: bool = False) -> dict[str, Any]:
        if wait:
            return self.analysis_update_and_wait(session_id)
        return self.task_start_analysis_update(session_id)

    def analysis_update_and_wait(self, session_id: str) -> dict[str, Any]:
        record, run = self._begin_analysis(session_id)
        return self._run_analysis(record, run)

    def analysis_abort(self, session_id: str) -> dict[str, Any]:
        idle_abort = False
        with self._lock:
            record = self._get_record(session_id)
            run = record.active_analysis
            if run is None:
                record, run = self._begin_analysis(session_id)
                run.started = True
                idle_abort = True
            task_id = run.task_id
            if task_id is None:
                self._request_analysis_cancel(record, run)
        if task_id is not None:
            return {
                **self.task_cancel(task_id),
                "is_aborted": bool(self._safe_attr(record.view, "analysis_is_aborted")),
            }
        if idle_abort:
            # The reservation covers automatic updates initiated by edits/raw APIs.
            with suppress(lifecycle.AnalysisCancelled):
                self._run_analysis(record, run)
        return {
            "session_id": session_id,
            "is_aborted": bool(self._safe_attr(record.view, "analysis_is_aborted")),
            "cancel_requested": run.cancel_requested,
        }

    def analysis_set_hold(self, session_id: str, hold: bool) -> dict[str, Any]:
        with self._analysis_control(session_id, interrupts=hold) as record:
            try:
                record.view.set_analysis_hold(hold)
            except Exception as exc:  # pragma: no cover - depends on binaryninja internals
                raise BinjaBackendError(f"failed to set analysis hold: {exc}") from exc

        return {
            "session_id": session_id,
            "hold": hold,
        }

    def analysis_status(self, session_id: str) -> dict[str, Any]:
        with self._condition:
            record = self._lookup_record(session_id)
            if record.closing or (record.replacing and not self._owns_replacement(session_id)):
                return {**record.native_status, **self._managed_status(record)}
            record.active_operations += 1
        try:
            native = self._native_analysis_status(record.view)
            with self._lock:
                record.native_status = native
                return {**native, **self._managed_status(record)}
        finally:
            with self._condition:
                record.active_operations -= 1
                self._condition.notify_all()

    def _native_analysis_status(self, view: Any) -> dict[str, Any]:
        progress = self._safe_attr(view, "analysis_progress")
        info = self._safe_attr(view, "analysis_info")

        return {
            "state": self._enum_name_or_value(self._safe_attr(view, "analysis_state")),
            "is_aborted": bool(self._safe_attr(view, "analysis_is_aborted")),
            "progress": {
                "state": self._enum_name_or_value(self._safe_attr(progress, "state")),
                "count": self._safe_attr(progress, "count"),
                "total": self._safe_attr(progress, "total"),
            },
            "info": {
                "state": self._enum_name_or_value(self._safe_attr(info, "state")),
                "analysis_time": self._safe_attr(info, "analysis_time"),
                "active_info": self._to_jsonable(self._safe_attr(info, "active_info")),
            },
        }

    def analysis_progress(self, session_id: str) -> dict[str, Any]:
        status = self.analysis_status(session_id)
        return {
            "session_id": session_id,
            "state": status["state"],
            "is_aborted": status["is_aborted"],
            "progress": status["progress"],
        }

    def list_functions(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        all_functions = list(self._safe_iter(self._safe_attr(view, "functions")))
        all_functions.sort(key=lambda func: int(self._safe_attr(func, "start") or 0))

        items = [
            self._function_to_record(function)
            for function in all_functions[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(all_functions),
            "items": items,
        }

    def list_strings(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        all_strings = list(self._safe_iter(self._safe_attr(view, "strings")))
        all_strings.sort(key=lambda string_ref: int(self._safe_attr(string_ref, "start") or 0))

        items = []
        for string_ref in all_strings[offset : offset + limit]:
            items.append(
                {
                    "start": self._hex_or_none(self._safe_attr(string_ref, "start")),
                    "length": self._safe_attr(string_ref, "length"),
                    "value": self._safe_attr(string_ref, "value"),
                    "type": str(self._safe_attr(string_ref, "type")),
                }
            )

        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(all_strings),
            "items": items,
        }

    def list_sections(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        sections = list(self._safe_iter(self._safe_attr(view, "sections")).items())
        sections.sort(key=lambda item: int(self._safe_attr(item[1], "start") or 0))

        items = []
        for name, section in sections[offset : offset + limit]:
            items.append(
                {
                    "name": name,
                    "start": self._hex_or_none(self._safe_attr(section, "start")),
                    "end": self._hex_or_none(self._safe_attr(section, "end")),
                    "length": self._safe_attr(section, "length"),
                    "type": self._safe_attr(section, "type"),
                    "semantics": self._enum_name_or_value(self._safe_attr(section, "semantics")),
                    "align": self._safe_attr(section, "align"),
                    "entry_size": self._safe_attr(section, "entry_size"),
                    "auto_defined": bool(self._safe_attr(section, "auto_defined")),
                }
            )

        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(sections),
            "items": items,
        }

    def list_segments(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        segments = list(self._safe_iter(self._safe_attr(view, "segments")))
        segments.sort(key=lambda segment: int(self._safe_attr(segment, "start") or 0))

        items = []
        for segment in segments[offset : offset + limit]:
            items.append(
                {
                    "start": self._hex_or_none(self._safe_attr(segment, "start")),
                    "end": self._hex_or_none(self._safe_attr(segment, "end")),
                    "data_offset": self._safe_attr(segment, "data_offset"),
                    "data_length": self._safe_attr(segment, "data_length"),
                    "readable": bool(self._safe_attr(segment, "readable")),
                    "writable": bool(self._safe_attr(segment, "writable")),
                    "executable": bool(self._safe_attr(segment, "executable")),
                    "auto_defined": bool(self._safe_attr(segment, "auto_defined")),
                }
            )

        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(segments),
            "items": items,
        }

    def list_symbols(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        symbol_mapping = self._safe_iter(self._safe_attr(view, "symbols"))

        all_symbols = []
        for key in sorted(symbol_mapping):
            for symbol in symbol_mapping[key]:
                all_symbols.append(self._symbol_to_record(symbol))

        all_symbols.sort(key=lambda item: item["address_int"])
        sliced = all_symbols[offset : offset + limit]

        items = []
        for symbol in sliced:
            symbol_copy = dict(symbol)
            symbol_copy.pop("address_int")
            items.append(symbol_copy)

        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(all_symbols),
            "items": items,
        }

    def list_data_vars(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        view = self._get_view(session_id)
        data_vars = list(self._safe_iter(self._safe_attr(view, "data_vars")).items())
        data_vars.sort(key=lambda item: int(item[0]))

        items = []
        for _, data_var in data_vars[offset : offset + limit]:
            items.append(self._data_var_to_record(data_var))

        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(data_vars),
            "items": items,
        }

    def get_function_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)

        function = view.get_function_at(normalized)
        if function is None:
            functions_at = list(self._safe_iter(view.get_functions_at(normalized)))
            function = functions_at[0] if functions_at else None

        if function is None:
            raise BinjaBackendError(f"no function at address {hex(normalized)}")

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "function": self._function_to_record(function),
        }

    def get_function_disassembly_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        function = self._find_function_containing(view, normalized)
        if function is None:
            raise BinjaBackendError(f"no function containing address {hex(normalized)}")

        instructions = list(self._safe_iter(self._safe_attr(function, "instructions")))
        items = [self._disasm_instruction_to_record(instruction) for instruction in instructions]

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "function": self._function_to_record(function),
            "total": len(instructions),
            "items": items,
        }

    def get_function_il_at(
        self,
        session_id: str,
        address: int | str,
        *,
        level: str = "mlil",
        ssa: bool = False,
    ) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        function = self._find_function_containing(view, normalized)
        if function is None:
            raise BinjaBackendError(f"no function containing address {hex(normalized)}")

        il = self._get_il_function(function, level, ssa)
        instructions = list(il.instructions)
        items = [self._il_instruction_to_record(instruction) for instruction in instructions]

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "function": self._function_to_record(function),
            "level": level,
            "ssa": ssa,
            "total": len(instructions),
            "items": items,
        }

    def list_functions_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        functions = list(self._safe_iter(view.get_functions_at(normalized)))
        functions.sort(key=lambda function: int(self._safe_attr(function, "start") or 0))
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "count": len(functions),
            "items": [self._function_to_record(function) for function in functions],
        }

    def list_basic_blocks_at(
        self,
        session_id: str,
        address: int | str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        blocks = list(self._safe_iter(view.get_basic_blocks_at(normalized)))
        blocks.sort(key=lambda block: int(self._safe_attr(block, "start") or 0))
        sliced = blocks[offset : offset + limit]
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "offset": offset,
            "limit": limit,
            "total": len(blocks),
            "count": len(sliced),
            "items": [self._basic_block_to_record(block) for block in sliced],
        }

    def list_function_basic_blocks(
        self,
        session_id: str,
        function_start: int | str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        function = self._get_function_by_start(session_id, function_start)
        blocks = list(self._safe_iter(self._safe_attr(function, "basic_blocks")))
        blocks.sort(key=lambda block: int(self._safe_attr(block, "start") or 0))
        sliced = blocks[offset : offset + limit]
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "offset": offset,
            "limit": limit,
            "total": len(blocks),
            "count": len(sliced),
            "items": [self._basic_block_to_record(block) for block in sliced],
        }

    def disasm_linear(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        view = self._get_view(session_id)
        items = []
        total = 0
        # Preserve the exact total without retaining every native line/token.
        # Large binaries can have millions of lines even for a tiny page request.
        for total, line in enumerate(
            self._safe_iter(self._safe_attr(view, "linear_disassembly")), start=1
        ):
            if offset < total <= offset + limit:
                items.append(self._linear_disassembly_line_to_record(line))
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": total,
            "items": items,
        }

    def search_text(
        self,
        session_id: str,
        query: str,
        *,
        limit: int = 50,
    ) -> dict[str, Any]:
        if not query:
            raise BinjaBackendError("query is required")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

        view = self._get_view(session_id)
        search = self._safe_attr(view, "search")
        if search is None:
            raise BinjaBackendError("BinaryView.search is not available")

        try:
            matches = list(islice(search(query, raw=True, limit=limit), limit))
        except TypeError:
            matches = list(islice(search(query), limit))
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"search failed: {exc}") from exc

        items = []
        for match in matches:
            if isinstance(match, tuple) and len(match) >= 1:
                address = match[0]
                data = match[1] if len(match) > 1 else None
            else:
                address = match
                data = None

            items.append(
                {
                    "address": self._hex_or_none(address),
                    "match": self._search_match_to_jsonable(data),
                }
            )

        return {
            "session_id": session_id,
            "query": query,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def search_data(
        self,
        session_id: str,
        data_hex: str,
        *,
        start: int | str | None = None,
        end: int | str | None = None,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

        try:
            pattern = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc

        view = self._get_view(session_id)
        start_int = self._coerce_address(start, "start") if start is not None else int(view.start)
        end_int = self._coerce_address(end, "end") if end is not None else int(view.end)
        if end_int <= start_int:
            raise BinjaBackendError("end must be greater than start")

        results: list[dict[str, Any]] = []
        for match in view.find_all_data(start_int, end_int, pattern):
            address = match[0] if isinstance(match, tuple) else match
            data = match[1] if isinstance(match, tuple) and len(match) > 1 else None
            results.append(
                {
                    "address": self._hex_or_none(address),
                    "match": self._search_match_to_jsonable(data),
                }
            )
            if len(results) >= limit:
                break

        return {
            "session_id": session_id,
            "data_hex": data_hex,
            "start": hex(start_int),
            "end": hex(end_int),
            "limit": limit,
            "count": len(results),
            "items": results,
        }

    def find_next_text(
        self,
        session_id: str,
        start: int | str,
        query: str,
    ) -> dict[str, Any]:
        if not query:
            raise BinjaBackendError("query is required")
        start_int = self._coerce_address(start, "start")
        view = self._get_view(session_id)
        address = view.find_next_text(start_int, query)
        return {
            "session_id": session_id,
            "start": hex(start_int),
            "query": query,
            "address": self._hex_or_none(address),
            "found": address is not None,
        }

    def find_all_text(
        self,
        session_id: str,
        start: int | str,
        end: int | str,
        query: str,
        *,
        regex: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not query:
            raise BinjaBackendError("query is required")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

        start_int = self._coerce_address(start, "start")
        end_int = self._coerce_address(end, "end")
        if end_int <= start_int:
            raise BinjaBackendError("end must be greater than start")

        view = self._get_view(session_id)
        matches = self._find_all_text_matches(view, start_int, end_int, query, regex)

        items = []
        for match in matches:
            if isinstance(match, tuple):
                address = match[0] if len(match) > 0 else None
                data = match[1] if len(match) > 1 else None
            else:
                address = match
                data = None

            items.append(
                {
                    "address": self._hex_or_none(address),
                    "match": self._search_match_to_jsonable(data),
                }
            )
            if len(items) >= limit:
                break

        return {
            "session_id": session_id,
            "start": hex(start_int),
            "end": hex(end_int),
            "query": query,
            "regex": regex,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def _find_all_text_matches(
        self,
        view: Any,
        start: int,
        end: int,
        query: str,
        regex: bool,
    ) -> Any:
        find_flag_enum = getattr(self._bn, "FindFlag", None)
        if regex:
            regex_flag = (
                getattr(find_flag_enum, "FindRegularExpression", None)
                if find_flag_enum is not None
                else None
            )
            if find_flag_enum is not None and regex_flag is not None:
                flags = find_flag_enum.FindCaseSensitive | regex_flag
                return view.find_all_text(start, end, query, flags=flags)
            return self._find_all_text_regex_fallback(view, start, end, query)

        if find_flag_enum is not None:
            flags = find_flag_enum.FindCaseSensitive
            return view.find_all_text(start, end, query, flags=flags)
        return view.find_all_text(start, end, query)

    def _find_all_text_regex_fallback(
        self,
        view: Any,
        start: int,
        end: int,
        query: str,
    ) -> list[tuple[int, str]]:
        try:
            pattern = re.compile(query)
        except re.error as exc:
            raise BinjaBackendError(f"invalid regex query: {exc}") from exc

        lines = self._safe_attr(view, "linear_disassembly")
        if lines is None:
            raise BinjaBackendError("regex search is not supported by this Binary Ninja build")

        matches: list[tuple[int, str]] = []
        for line in self._safe_iter(lines):
            contents = self._safe_attr(line, "contents")
            address = self._safe_attr(contents, "address")
            if not isinstance(address, int):
                continue
            if address < start or address >= end:
                continue

            text = str(contents or "")
            if pattern.search(text) is None:
                continue

            matches.append((address, text))

        return matches

    def find_next_data(
        self,
        session_id: str,
        start: int | str,
        data_hex: str,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc

        start_int = self._coerce_address(start, "start")
        view = self._get_view(session_id)
        address = view.find_next_data(start_int, data)
        return {
            "session_id": session_id,
            "start": hex(start_int),
            "data_hex": data_hex,
            "address": self._hex_or_none(address),
            "found": address is not None,
        }

    def find_all_data(
        self,
        session_id: str,
        start: int | str,
        end: int | str,
        data_hex: str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc

        start_int = self._coerce_address(start, "start")
        end_int = self._coerce_address(end, "end")
        if end_int <= start_int:
            raise BinjaBackendError("end must be greater than start")

        view = self._get_view(session_id)
        items = []
        for match in view.find_all_data(start_int, end_int, data):
            if isinstance(match, tuple):
                address = match[0] if len(match) > 0 else None
                buf = match[1] if len(match) > 1 else None
            else:
                address = match
                buf = None
            items.append(
                {
                    "address": self._hex_or_none(address),
                    "match": self._search_match_to_jsonable(buf),
                }
            )
            if len(items) >= limit:
                break

        return {
            "session_id": session_id,
            "start": hex(start_int),
            "end": hex(end_int),
            "data_hex": data_hex,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def find_next_constant(
        self,
        session_id: str,
        start: int | str,
        constant: int,
    ) -> dict[str, Any]:
        start_int = self._coerce_address(start, "start")
        view = self._get_view(session_id)
        address = view.find_next_constant(start_int, constant)
        return {
            "session_id": session_id,
            "start": hex(start_int),
            "constant": constant,
            "address": self._hex_or_none(address),
            "found": address is not None,
        }

    def find_all_constant(
        self,
        session_id: str,
        start: int | str,
        end: int | str,
        constant: int,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")
        start_int = self._coerce_address(start, "start")
        end_int = self._coerce_address(end, "end")
        if end_int <= start_int:
            raise BinjaBackendError("end must be greater than start")

        view = self._get_view(session_id)
        items = []
        for match in view.find_all_constant(start_int, end_int, constant):
            if isinstance(match, tuple):
                address = match[0] if len(match) > 0 else None
                detail = match[1] if len(match) > 1 else None
            else:
                address = match
                detail = None
            items.append(
                {
                    "address": self._hex_or_none(address),
                    "match": self._to_jsonable(detail),
                }
            )
            if len(items) >= limit:
                break

        return {
            "session_id": session_id,
            "start": hex(start_int),
            "end": hex(end_int),
            "constant": constant,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def code_refs_to(
        self,
        session_id: str,
        address: int | str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        refs = [self._reference_source_to_record(ref) for ref in view.get_code_refs(normalized)]
        refs.sort(key=lambda item: item["from_int"])

        sliced = refs[offset : offset + limit]
        items = []
        for ref in sliced:
            ref_copy = dict(ref)
            ref_copy.pop("from_int")
            items.append(ref_copy)

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "offset": offset,
            "limit": limit,
            "total": len(refs),
            "items": items,
        }

    def code_refs_from(
        self,
        session_id: str,
        address: int | str,
        *,
        length: int | None = None,
    ) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        if length is not None and length <= 0:
            raise BinjaBackendError("length must be > 0 when provided")

        view = self._get_view(session_id)
        refs = list(view.get_code_refs_from(normalized, length=length))
        items = [{"to": self._hex_or_none(ref)} for ref in refs]

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "length": length,
            "count": len(items),
            "items": items,
        }

    def data_refs_to(
        self,
        session_id: str,
        address: int | str,
        *,
        limit: int = 100,
    ) -> dict[str, Any]:
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        refs = list(view.get_data_refs(normalized, max_items=limit))

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "limit": limit,
            "count": len(refs),
            "items": [{"from": self._hex_or_none(ref)} for ref in refs],
        }

    def data_refs_from(
        self,
        session_id: str,
        address: int | str,
        *,
        length: int | None = None,
    ) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        if length is not None and length <= 0:
            raise BinjaBackendError("length must be > 0 when provided")

        view = self._get_view(session_id)
        refs = list(view.get_data_refs_from(normalized, length=length))

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "length": length,
            "count": len(refs),
            "items": [{"to": self._hex_or_none(ref)} for ref in refs],
        }

    def function_callers(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        callers = list(self._safe_iter(self._safe_attr(function, "callers")))
        callers.sort(key=lambda func: int(self._safe_attr(func, "start") or 0))

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "count": len(callers),
            "items": [self._function_to_record(caller) for caller in callers],
        }

    def function_callees(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        callees = list(self._safe_iter(self._safe_attr(function, "callees")))
        callees.sort(key=lambda func: int(self._safe_attr(func, "start") or 0))

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "count": len(callees),
            "items": [self._function_to_record(callee) for callee in callees],
        }

    def disasm_function(
        self,
        session_id: str,
        address: int | str,
    ) -> dict[str, Any]:
        return self.get_function_disassembly_at(session_id, address)

    def disasm_range(
        self,
        session_id: str,
        start: int | str,
        *,
        length: int,
        limit: int = 200,
    ) -> dict[str, Any]:
        normalized_start = self._coerce_address(start, "start")
        if length <= 0:
            raise BinjaBackendError("length must be > 0")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

        view = self._get_view(session_id)
        end = normalized_start + length
        cursor = normalized_start
        items = []

        while cursor < end and len(items) < limit:
            text = view.get_disassembly(cursor)
            instruction_length = view.get_instruction_length(cursor)
            if not isinstance(instruction_length, int) or instruction_length <= 0:
                instruction_length = 1

            items.append({"address": hex(cursor), "text": text})
            cursor += instruction_length

        return {
            "session_id": session_id,
            "start": hex(normalized_start),
            "length": length,
            "limit": limit,
            "count": len(items),
            "items": items,
        }

    def il_function(
        self,
        session_id: str,
        function_start: int | str,
        *,
        level: str = "mlil",
        ssa: bool = False,
        offset: int = 0,
        limit: int = 200,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)

        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa)
        instructions = list(il.instructions)

        items = [
            self._il_instruction_to_record(instruction)
            for instruction in instructions[offset : offset + limit]
        ]

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "ssa": ssa,
            "offset": offset,
            "limit": limit,
            "total": len(instructions),
            "items": items,
        }

    def il_instruction_by_addr(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        *,
        level: str = "mlil",
        ssa: bool = False,
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        target_address = self._coerce_address(address, "address")
        il = self._get_il_function(function, level, ssa)

        instruction = None
        for candidate in il.instructions:
            if int(candidate.address) == target_address:
                instruction = candidate
                break

        if instruction is None and hasattr(il, "get_instruction_start"):
            try:
                index = il.get_instruction_start(target_address)
            except TypeError:
                index = il.get_instruction_start(
                    target_address,
                    arch=self._safe_attr(function, "arch"),
                )
            if index is not None:
                instruction = il[index]

        if instruction is None:
            raise BinjaBackendError(
                f"no {level}{'_ssa' if ssa else ''} instruction for address {hex(target_address)}"
            )

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "ssa": ssa,
            "address": hex(target_address),
            "instruction": self._il_instruction_to_record(instruction),
        }

    def il_address_to_index(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        *,
        level: str = "mlil",
        ssa: bool = False,
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        target_address = self._coerce_address(address, "address")
        il = self._get_il_function(function, level, ssa)

        indices = [
            int(instruction.instr_index)
            for instruction in il.instructions
            if int(instruction.address) == target_address
        ]

        if not indices and hasattr(il, "get_instruction_start"):
            try:
                index = il.get_instruction_start(target_address)
            except TypeError:
                index = il.get_instruction_start(
                    target_address,
                    arch=self._safe_attr(function, "arch"),
                )
            if index is not None:
                indices.append(int(index))

        indices = sorted(set(indices))

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "ssa": ssa,
            "address": hex(target_address),
            "indices": indices,
            "count": len(indices),
        }

    def il_index_to_address(
        self,
        session_id: str,
        function_start: int | str,
        index: int,
        *,
        level: str = "mlil",
        ssa: bool = False,
    ) -> dict[str, Any]:
        if index < 0:
            raise BinjaBackendError("index must be >= 0")

        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa)

        try:
            instruction = il[index]
        except Exception as exc:
            raise BinjaBackendError(f"invalid IL index {index}: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "ssa": ssa,
            "index": index,
            "address": self._hex_or_none(self._safe_attr(instruction, "address")),
        }

    def function_reg_value(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        register: str,
        *,
        after: bool = False,
    ) -> dict[str, Any]:
        if not register:
            raise BinjaBackendError("register is required")
        function = self._get_function_by_start(session_id, function_start)
        target = self._coerce_address(address, "address")

        getter = function.get_reg_value_after if after else function.get_reg_value_at
        value = getter(target, register)
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "address": hex(target),
            "register": register,
            "after": after,
            "value": self._register_value_to_record(value),
        }

    def function_stack_contents(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        stack_offset: int,
        size: int,
        *,
        after: bool = False,
    ) -> dict[str, Any]:
        if size <= 0:
            raise BinjaBackendError("size must be > 0")
        function = self._get_function_by_start(session_id, function_start)
        target = self._coerce_address(address, "address")
        getter = function.get_stack_contents_after if after else function.get_stack_contents_at
        value = getter(target, stack_offset, size)
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "address": hex(target),
            "stack_offset": stack_offset,
            "size": size,
            "after": after,
            "value": self._register_value_to_record(value),
        }

    def function_variables(self, session_id: str, function_start: int | str) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        variables = list(self._safe_iter(self._safe_attr(function, "vars")))
        items = [self._variable_to_record(variable) for variable in variables]
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "count": len(items),
            "items": items,
        }

    def function_variable_refs(
        self,
        session_id: str,
        function_start: int | str,
        variable_name: str,
        *,
        level: str = "mlil",
    ) -> dict[str, Any]:
        if not variable_name:
            raise BinjaBackendError("variable_name is required")
        function = self._get_function_by_start(session_id, function_start)
        variable = self._find_variable(function, variable_name)
        if variable is None:
            raise BinjaBackendError(f"variable not found: {variable_name}")

        normalized_level = level.lower()
        if normalized_level == "mlil":
            refs = function.get_mlil_var_refs(variable)
        elif normalized_level == "hlil":
            refs = function.get_hlil_var_refs(variable)
        else:
            raise BinjaBackendError("level must be one of: mlil, hlil")

        items = []
        for ref in refs:
            items.append(
                {
                    "address": self._hex_or_none(self._safe_attr(ref, "address")),
                    "function_start": self._hex_or_none(
                        self._safe_attr(self._safe_attr(ref, "func"), "start")
                    ),
                    "arch": self._safe_attr_chain(ref, "arch.name"),
                }
            )

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "variable_name": variable_name,
            "level": normalized_level,
            "count": len(items),
            "items": items,
        }

    def function_variable_refs_from(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        *,
        level: str = "mlil",
        length: int | None = None,
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        target_address = self._coerce_address(address, "address")
        if length is not None and length <= 0:
            raise BinjaBackendError("length must be > 0 when provided")

        normalized_level = level.lower()
        if normalized_level == "mlil":
            refs = function.get_mlil_var_refs_from(target_address, length=length)
        elif normalized_level == "hlil":
            refs = function.get_hlil_var_refs_from(target_address, length=length)
        else:
            raise BinjaBackendError("level must be one of: mlil, hlil")

        items = [self._variable_reference_source_to_record(ref) for ref in refs]
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "address": hex(target_address),
            "level": normalized_level,
            "length": length,
            "count": len(items),
            "items": items,
        }

    def function_ssa_var_def_use(
        self,
        session_id: str,
        function_start: int | str,
        variable_name: str,
        version: int,
        *,
        level: str = "mlil",
    ) -> dict[str, Any]:
        if not variable_name:
            raise BinjaBackendError("variable_name is required")
        if version < 0:
            raise BinjaBackendError("version must be >= 0")

        function = self._get_function_by_start(session_id, function_start)
        variable = self._find_variable(function, variable_name)
        if variable is None:
            raise BinjaBackendError(f"variable not found: {variable_name}")

        il = self._get_il_function(function, level, ssa=True)
        ssa_var = self._bn.SSAVariable(variable, version)

        try:
            definition = il.get_ssa_var_definition(ssa_var)
            uses = il.get_ssa_var_uses(ssa_var)
        except Exception as exc:
            raise BinjaBackendError(f"failed to query SSA var def/use: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "variable_name": variable_name,
            "version": version,
            "level": level,
            "definition": self._il_instruction_to_record(definition) if definition else None,
            "uses": [self._il_instruction_to_record(use) for use in uses],
            "use_count": len(uses),
        }

    def function_ssa_memory_def_use(
        self,
        session_id: str,
        function_start: int | str,
        version: int,
        *,
        level: str = "mlil",
    ) -> dict[str, Any]:
        if version < 0:
            raise BinjaBackendError("version must be >= 0")
        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa=True)

        try:
            definition = il.get_ssa_memory_definition(version)
            uses = il.get_ssa_memory_uses(version)
        except Exception as exc:
            raise BinjaBackendError(f"failed to query SSA memory def/use: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "version": version,
            "level": level,
            "definition": self._il_instruction_to_record(definition) if definition else None,
            "uses": [self._il_instruction_to_record(use) for use in uses],
            "use_count": len(uses),
        }

    def function_flags_at(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        target_address = self._coerce_address(address, "address")

        lifted_il = function.get_lifted_il_at(
            target_address,
            arch=self._safe_attr(function, "arch"),
        )
        if lifted_il is None:
            lifted_ils = function.get_lifted_ils_at(
                target_address,
                arch=self._safe_attr(function, "arch"),
            )
            lifted_il = lifted_ils[0] if lifted_ils else None
        if lifted_il is None:
            raise BinjaBackendError(f"no lifted IL at address {hex(target_address)}")

        index = int(self._safe_attr(lifted_il, "instr_index") or 0)
        flags_read = list(function.get_flags_read_by_lifted_il_instruction(index))
        flags_written = list(function.get_flags_written_by_lifted_il_instruction(index))

        read_definitions = {}
        for flag in flags_read:
            try:
                definitions = function.get_lifted_il_flag_definitions_for_use(index, flag)
            except Exception:
                definitions = []
            read_definitions[str(flag)] = [int(definition) for definition in definitions]

        write_uses = {}
        for flag in flags_written:
            try:
                uses = function.get_lifted_il_flag_uses_for_definition(index, flag)
            except Exception:
                uses = []
            write_uses[str(flag)] = [
                {
                    "index": int(self._safe_attr(use, "instr_index") or 0),
                    "address": self._hex_or_none(self._safe_attr(use, "address")),
                    "text": str(use),
                }
                for use in uses
            ]

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "address": hex(target_address),
            "lifted_il_index": index,
            "flags_read": [str(flag) for flag in flags_read],
            "flags_written": [str(flag) for flag in flags_written],
            "read_definitions": read_definitions,
            "write_uses": write_uses,
        }

    def il_possible_values(
        self,
        session_id: str,
        function_start: int | str,
        address: int | str,
        *,
        level: str = "mlil",
        ssa: bool = False,
    ) -> dict[str, Any]:
        instruction = self.il_instruction_by_addr(
            session_id,
            function_start,
            address,
            level=level,
            ssa=ssa,
        )["instruction"]

        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa)
        index = instruction["index"]
        il_instruction = il[index]
        possible_values = self._safe_attr(il_instruction, "possible_values")

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "address": instruction["address"],
            "level": level,
            "ssa": ssa,
            "index": index,
            "possible_values": self._to_jsonable(possible_values),
        }

    def read_bytes(self, session_id: str, address: int | str, length: int) -> dict[str, Any]:
        if length <= 0:
            raise BinjaBackendError("length must be > 0")
        if length > MAX_MEMORY_READ_BYTES:
            raise BinjaBackendError(
                f"length must be <= {MAX_MEMORY_READ_BYTES} to limit response size"
            )
        view = self._get_view(session_id)
        normalized = self._coerce_address(address, "address")
        data = view.read(normalized, length)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "length": length,
            "data_hex": data.hex(),
        }

    def reader_read(
        self,
        session_id: str,
        address: int | str,
        width: int,
        *,
        endian: str = "little",
    ) -> dict[str, Any]:
        if width not in {1, 2, 4, 8}:
            raise BinjaBackendError("width must be one of: 1, 2, 4, 8")
        view = self._get_view(session_id)
        target = self._coerce_address(address, "address")
        reader = self._make_binary_reader(view, target, endian)

        methods = {
            1: reader.read8,
            2: reader.read16,
            4: reader.read32,
            8: reader.read64,
        }
        value = methods[width]()
        if value is None:
            raise BinjaBackendError("reader failed to read value")
        return {
            "session_id": session_id,
            "address": hex(target),
            "width": width,
            "endian": endian,
            "value": int(value),
            "next_offset": int(reader.offset),
        }

    def writer_write(
        self,
        session_id: str,
        address: int | str,
        width: int,
        value: int,
        *,
        endian: str = "little",
    ) -> dict[str, Any]:
        if width not in {1, 2, 4, 8}:
            raise BinjaBackendError("width must be one of: 1, 2, 4, 8")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before writing via BinaryWriter",
        )
        view = self._get_view(session_id)
        target = self._coerce_address(address, "address")
        writer = self._make_binary_writer(view, target, endian)

        methods = {
            1: writer.write8,
            2: writer.write16,
            4: writer.write32,
            8: writer.write64,
        }
        ok = bool(methods[width](value))
        if not ok:
            raise BinjaBackendError("writer failed to write value")
        self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(target),
            "width": width,
            "endian": endian,
            "value": value,
            "written": True,
            "next_offset": int(writer.offset),
        }

    def write_bytes(
        self,
        session_id: str,
        address: int | str,
        data_hex: str,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before writing bytes",
        )

        normalized = self._coerce_address(address, "address")
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc

        view = self._get_view(session_id)
        written = int(view.write(normalized, data, except_on_relocation=False))
        if written > 0:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "written": written,
        }

    def insert_bytes(
        self,
        session_id: str,
        address: int | str,
        data_hex: str,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before inserting bytes",
        )
        normalized = self._coerce_address(address, "address")
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc

        view = self._get_view(session_id)
        inserted = int(view.insert(normalized, data))
        if inserted > 0:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "inserted": inserted,
        }

    def remove_bytes(self, session_id: str, address: int | str, length: int) -> dict[str, Any]:
        if length <= 0:
            raise BinjaBackendError("length must be > 0")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing bytes",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        removed = int(view.remove(normalized, length))
        if removed > 0:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "removed": removed,
        }

    def typed_data_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        data_var = view.get_data_var_at(normalized)
        if data_var is None:
            raise BinjaBackendError(f"no data variable at address {hex(normalized)}")
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "data_var": self._data_var_to_record(data_var),
        }

    def rename_function(
        self,
        session_id: str,
        function_start: int | str,
        new_name: str,
    ) -> dict[str, Any]:
        if not new_name:
            raise BinjaBackendError("new_name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before renaming functions",
        )
        function = self._get_function_by_start(session_id, function_start)
        function.name = new_name
        return {
            "session_id": session_id,
            "function": self._function_to_record(function),
        }

    def rename_symbol(self, session_id: str, address: int | str, new_name: str) -> dict[str, Any]:
        if not new_name:
            raise BinjaBackendError("new_name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before renaming symbols",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        symbol = view.get_symbol_at(normalized)
        if symbol is None:
            raise BinjaBackendError(f"no symbol at address {hex(normalized)}")

        replacement = self._bn.Symbol(symbol.type, symbol.address, new_name)
        view.define_user_symbol(replacement)
        updated = view.get_symbol_at(normalized)
        if updated is None:
            raise BinjaBackendError("failed to fetch renamed symbol")

        record = self._symbol_to_record(updated)
        record.pop("address_int", None)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "symbol": record,
        }

    def undefine_symbol(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before undefining symbols",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        symbol = view.get_symbol_at(normalized)
        if symbol is None:
            raise BinjaBackendError(f"no symbol at address {hex(normalized)}")
        view.undefine_user_symbol(symbol)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "undefined": True,
        }

    def define_symbol(
        self,
        session_id: str,
        address: int | str,
        name: str,
        *,
        symbol_type: str = "FunctionSymbol",
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before defining symbols",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)

        try:
            symbol_kind = self._bn.SymbolType[symbol_type]
        except Exception as exc:
            raise BinjaBackendError(f"unknown symbol_type: {symbol_type}") from exc

        symbol = self._bn.Symbol(symbol_kind, normalized, name)
        view.define_user_symbol(symbol)
        created = view.get_symbol_at(normalized)
        if created is None:
            raise BinjaBackendError("failed to fetch defined symbol")

        record = self._symbol_to_record(created)
        record.pop("address_int", None)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "symbol": record,
        }

    def rename_data_var(
        self,
        session_id: str,
        address: int | str,
        new_name: str,
    ) -> dict[str, Any]:
        if not new_name:
            raise BinjaBackendError("new_name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before renaming data variables",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        data_var = view.get_data_var_at(normalized)
        if data_var is None:
            raise BinjaBackendError(f"no data variable at address {hex(normalized)}")
        data_var.name = new_name
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "data_var": self._data_var_to_record(data_var),
        }

    def define_data_var(
        self,
        session_id: str,
        address: int | str,
        *,
        type_name: str = "char",
        width: int = 1,
        name: str | None = None,
    ) -> dict[str, Any]:
        if width <= 0:
            raise BinjaBackendError("width must be > 0")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before defining data variables",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)

        if type_name == "char":
            core_type = self._bn.Type.char()
        elif type_name == "int":
            core_type = self._bn.Type.int(width)
        elif type_name == "pointer":
            core_type = self._bn.Type.pointer(view.arch, self._bn.Type.char(), width=width)
        else:
            raise BinjaBackendError("type_name must be one of: char, int, pointer")

        data_var = view.define_user_data_var(normalized, core_type, name=name)
        if data_var is None:
            raise BinjaBackendError("failed to define data variable")

        return {
            "session_id": session_id,
            "address": hex(normalized),
            "data_var": self._data_var_to_record(data_var),
        }

    def undefine_data_var(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before undefining data variables",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        view.undefine_user_data_var(normalized)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "undefined": True,
        }

    def set_comment(self, session_id: str, address: int | str, comment: str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding comments",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        view.set_comment_at(normalized, comment)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "comment": view.get_comment_at(normalized),
        }

    def get_comment(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "comment": view.get_comment_at(normalized),
        }

    def add_tag(
        self,
        session_id: str,
        address: int | str,
        tag_type: str,
        data: str,
        *,
        icon: str = "M",
    ) -> dict[str, Any]:
        if not tag_type:
            raise BinjaBackendError("tag_type is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding tags",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)

        if view.get_tag_type(tag_type) is None:
            view.create_tag_type(tag_type, icon)

        view.add_tag(normalized, tag_type, data, user=True)
        tags = view.get_tags_at(normalized)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "count": len(tags),
            "items": [self._tag_to_record(tag) for tag in tags],
        }

    def get_tags_at(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        tags = view.get_tags_at(normalized)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "count": len(tags),
            "items": [self._tag_to_record(tag) for tag in tags],
        }

    def metadata_store(self, session_id: str, key: str, value: Any) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before storing metadata",
        )
        view = self._get_view(session_id)
        view.store_metadata(key, value)
        return {
            "session_id": session_id,
            "key": key,
            "value": self._to_jsonable(view.query_metadata(key)),
        }

    def metadata_query(self, session_id: str, key: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        view = self._get_view(session_id)
        try:
            value = view.query_metadata(key)
        except Exception:
            value = None
        return {
            "session_id": session_id,
            "key": key,
            "value": self._to_jsonable(value),
        }

    def metadata_remove(self, session_id: str, key: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing metadata",
        )
        view = self._get_view(session_id)
        view.remove_metadata(key)
        return {"session_id": session_id, "key": key, "removed": True}

    def function_metadata_store(
        self,
        session_id: str,
        function_start: int | str,
        key: str,
        value: Any,
    ) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before storing function metadata",
        )
        function = self._get_function_by_start(session_id, function_start)
        function.store_metadata(key, value)
        queried = function.query_metadata(key)
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "key": key,
            "value": self._to_jsonable(queried),
        }

    def function_metadata_query(
        self,
        session_id: str,
        function_start: int | str,
        key: str,
    ) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        function = self._get_function_by_start(session_id, function_start)
        try:
            value = function.query_metadata(key)
        except Exception:
            value = None
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "key": key,
            "value": self._to_jsonable(value),
        }

    def function_metadata_remove(
        self,
        session_id: str,
        function_start: int | str,
        key: str,
    ) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing function metadata",
        )
        function = self._get_function_by_start(session_id, function_start)
        function.remove_metadata(key)
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "key": key,
            "removed": True,
        }

    def patch_assemble(
        self,
        session_id: str,
        address: int | str,
        asm: str,
    ) -> dict[str, Any]:
        if not asm:
            raise BinjaBackendError("asm is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        if not view.can_assemble():
            raise BinjaBackendError("architecture does not support assembly for this view")
        data = view.arch.assemble(asm, normalized)
        written = int(view.write(normalized, data, except_on_relocation=False))
        if written > 0:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "asm": asm,
            "written": written,
            "data_hex": data.hex(),
        }

    def patch_status(self, session_id: str, address: int | str) -> dict[str, Any]:
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "can_convert_to_nop": bool(view.is_never_branch_patch_available(normalized))
            or bool(view.is_always_branch_patch_available(normalized))
            or bool(view.is_invert_branch_patch_available(normalized)),
            "is_never_branch_patch_available": bool(
                view.is_never_branch_patch_available(normalized)
            ),
            "is_always_branch_patch_available": bool(
                view.is_always_branch_patch_available(normalized)
            ),
            "is_invert_branch_patch_available": bool(
                view.is_invert_branch_patch_available(normalized)
            ),
            "is_skip_and_return_zero_patch_available": bool(
                view.is_skip_and_return_zero_patch_available(normalized)
            ),
            "is_skip_and_return_value_patch_available": bool(
                view.is_skip_and_return_value_patch_available(normalized)
            ),
        }

    def patch_convert_to_nop(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        patched = bool(view.convert_to_nop(normalized))
        if patched:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "patched": patched,
        }

    def patch_always_branch(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        patched = bool(view.always_branch(normalized))
        if patched:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "patched": patched,
        }

    def patch_never_branch(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        patched = bool(view.never_branch(normalized))
        if patched:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "patched": patched,
        }

    def patch_invert_branch(self, session_id: str, address: int | str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        patched = bool(view.invert_branch(normalized))
        if patched:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "patched": patched,
        }

    def patch_skip_and_return_value(
        self,
        session_id: str,
        address: int | str,
        value: int,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before patching",
        )
        normalized = self._coerce_address(address, "address")
        view = self._get_view(session_id)
        patched = bool(view.skip_and_return_value(normalized, value))
        if patched:
            self._mark_session_byte_edits(session_id)
        return {
            "session_id": session_id,
            "address": hex(normalized),
            "value": value,
            "patched": patched,
        }

    def undo_begin(self, session_id: str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before starting transactions",
        )
        view = self._get_view(session_id)
        transaction_id = view.begin_undo_actions()
        return {
            "session_id": session_id,
            "transaction_id": transaction_id,
        }

    def undo_commit(self, session_id: str, transaction_id: str | None = None) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before committing transactions",
        )
        view = self._get_view(session_id)
        view.commit_undo_actions(transaction_id)
        return {
            "session_id": session_id,
            "transaction_id": transaction_id,
            "committed": True,
        }

    def undo_revert(self, session_id: str, transaction_id: str | None = None) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before reverting transactions",
        )
        view = self._get_view(session_id)
        view.revert_undo_actions(transaction_id)
        return {
            "session_id": session_id,
            "transaction_id": transaction_id,
            "reverted": True,
        }

    def undo(self, session_id: str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before undo",
        )
        view = self._get_view(session_id)
        view.undo()
        return {"session_id": session_id, "undone": True}

    def redo(self, session_id: str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before redo",
        )
        view = self._get_view(session_id)
        view.redo()
        return {"session_id": session_id, "redone": True}

    def call_api(
        self,
        target: str,
        *,
        args: list[Any] | None = None,
        kwargs: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> dict[str, Any]:
        args = args or []
        kwargs = kwargs or {}
        if not target:
            raise BinjaBackendError("target is required")

        root, attr_path = self._resolve_call_target(target, session_id)
        obj = self._resolve_attr_path(root, attr_path)
        transitioned_session_ids: list[str] = []

        if target.startswith("bv.") and session_id is not None and callable(obj):
            transitioned_session_ids = self._transition_sessions_to_writable([session_id])

        try:
            result = obj(*args, **kwargs) if callable(obj) else obj
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"API call failed: {exc}") from exc

        return {
            "target": target,
            "callable": callable(obj),
            "result": self._to_jsonable(result),
            "mode_transitioned": bool(transitioned_session_ids),
            "transitioned_session_ids": transitioned_session_ids,
        }

    def eval_code(self, code: str, *, session_id: str | None = None) -> dict[str, Any]:
        with self._operation_scope("binja.eval", {"session_id": session_id}) as records:
            return self._eval_code(code, session_id=session_id, records=records)

    def _eval_code(
        self, code: str, *, session_id: str | None, records: list[SessionRecord]
    ) -> dict[str, Any]:
        if not code:
            raise BinjaBackendError("code is required")

        if session_id is not None:
            _ = self._get_view(session_id)
            transition_candidates = [session_id]
        else:
            transition_candidates = sorted(record.session_id for record in records)
        transitioned_session_ids = self._transition_sessions_to_writable(transition_candidates)

        context: dict[str, Any] = {
            "bn": self._bn,
            "sessions": {record.session_id: record.view for record in records},
        }
        if session_id is not None:
            context["bv"] = self._get_view(session_id)

        stdout_buffer = io.StringIO()
        stderr_buffer = io.StringIO()
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            try:
                compiled = compile(code, "<binary_ninja_headless_mcp>", "eval")
            except SyntaxError:
                compiled = compile(code, "<binary_ninja_headless_mcp>", "exec")
                exec(compiled, context, context)
                result = context.get("_")
            else:
                result = eval(compiled, context, context)

        payload: dict[str, Any] = {"result": self._to_jsonable(result)}
        stdout_text = stdout_buffer.getvalue()
        stderr_text = stderr_buffer.getvalue()
        if stdout_text:
            payload["stdout"] = stdout_text
        if stderr_text:
            payload["stderr"] = stderr_text
        payload["mode_transitioned"] = bool(transitioned_session_ids)
        payload["transitioned_session_ids"] = transitioned_session_ids
        return payload

    def task_start_analysis_update(self, session_id: str) -> dict[str, Any]:
        record, run = self._begin_analysis(session_id)
        try:
            return self._submit_task(
                kind="analysis.update_and_wait",
                session_id=session_id,
                func=lambda: self._run_analysis(record, run),
                analysis_run=run,
            )
        except Exception as exc:
            self._finish_analysis(record, run, "failed", str(exc))
            raise BinjaBackendError(
                f"failed to submit analysis task: {exc}", session_id=session_id, status="failed"
            ) from exc

    def task_start_search_text(
        self,
        session_id: str,
        query: str,
        *,
        limit: int = 50,
    ) -> dict[str, Any]:
        _ = self._get_view(session_id)

        def run() -> dict[str, Any]:
            return self.search_text(session_id, query, limit=limit)

        return self._submit_task(kind="binary.search_text", session_id=session_id, func=run)

    def task_status(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._get_task(task_id)
            status = self._task_status_value(record)
            error = record.future.exception() if status == "failed" else None
            return {
                "task_id": record.task_id,
                "kind": record.kind,
                "session_id": record.session_id,
                "status": status,
                "cancel_requested": record.cancel_requested,
                "cancel_supported": record.analysis_run is not None
                or record.cancel_hook is not None,
                "result_ready": status in lifecycle.TERMINAL_STATES,
                "error": str(error) if error is not None else None,
                "created_at": record.created_at,
            }

    def task_result(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._get_task(task_id)
            status = self._task_status_value(record)
            if status not in lifecycle.TERMINAL_STATES:
                raise BinjaBackendError(f"task is not in a terminal state (status={status})")
            payload = {
                "task_id": task_id,
                "kind": record.kind,
                "session_id": record.session_id,
                "status": status,
            }
            if status == "failed":
                payload["error"] = str(record.future.exception())
            elif status == "completed":
                payload["result"] = self._to_jsonable(record.future.result())
            return payload

    def task_cancel(self, task_id: str) -> dict[str, Any]:
        return self._cancel_task(task_id)

    def create_database(self, session_id: str, path: str) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")

        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before creating a database",
        )
        view = self._get_view(session_id)

        try:
            created = bool(view.create_database(path))
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"failed to create database: {exc}") from exc

        return {
            "session_id": session_id,
            "path": path,
            "created": created,
        }

    def save_auto_snapshot(self, session_id: str) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before saving snapshots",
        )
        view = self._get_view(session_id)

        try:
            saved = bool(view.save_auto_snapshot())
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"failed to save auto snapshot: {exc}") from exc

        return {
            "session_id": session_id,
            "saved": saved,
        }

    def save_binary(self, session_id: str, path: str) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")

        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before saving binaries",
        )
        view = self._get_view(session_id)

        try:
            saved = bool(view.save(path))
        except Exception as exc:  # pragma: no cover - depends on binaryninja internals
            raise BinjaBackendError(f"failed to save binary: {exc}") from exc

        return {
            "session_id": session_id,
            "path": path,
            "saved": saved,
        }

    def type_parse_string(
        self,
        session_id: str,
        type_source: str,
        *,
        import_dependencies: bool = True,
    ) -> dict[str, Any]:
        if not type_source:
            raise BinjaBackendError("type_source is required")

        view = self._get_view(session_id)
        try:
            parsed_type, parsed_name = view.parse_type_string(
                type_source,
                import_dependencies=import_dependencies,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse type string: {exc}") from exc

        return {
            "session_id": session_id,
            "type_source": type_source,
            "parsed_name": str(parsed_name) if parsed_name is not None else None,
            "parsed_type": repr(parsed_type),
        }

    def type_parse_declarations(
        self,
        session_id: str,
        declarations: str,
        *,
        options: list[str] | None = None,
        include_dirs: list[str] | None = None,
        import_dependencies: bool = True,
    ) -> dict[str, Any]:
        if not declarations:
            raise BinjaBackendError("declarations is required")

        view = self._get_view(session_id)
        try:
            parsed = view.parse_types_from_string(
                declarations,
                options=options,
                include_dirs=include_dirs,
                import_dependencies=import_dependencies,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse declarations: {exc}") from exc

        type_items = []
        for name, type_obj in dict(self._safe_attr(parsed, "types") or {}).items():
            type_items.append({"name": str(name), "type": repr(type_obj)})

        variable_items = []
        for name, type_obj in dict(self._safe_attr(parsed, "variables") or {}).items():
            variable_items.append({"name": str(name), "type": repr(type_obj)})

        function_items = []
        for name, type_obj in dict(self._safe_attr(parsed, "functions") or {}).items():
            function_items.append({"name": str(name), "type": repr(type_obj)})

        return {
            "session_id": session_id,
            "type_count": len(type_items),
            "variable_count": len(variable_items),
            "function_count": len(function_items),
            "types": type_items,
            "variables": variable_items,
            "functions": function_items,
        }

    def type_define_user(
        self,
        session_id: str,
        type_source: str,
        *,
        name: str | None = None,
        import_dependencies: bool = True,
    ) -> dict[str, Any]:
        if not type_source:
            raise BinjaBackendError("type_source is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before defining user types",
        )

        view = self._get_view(session_id)
        try:
            parsed_type, parsed_name = view.parse_type_string(
                type_source,
                import_dependencies=import_dependencies,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse type string: {exc}") from exc

        type_name = name or (str(parsed_name) if parsed_name is not None else None)
        if not type_name:
            raise BinjaBackendError(
                "name is required when parsed type string does not include a declarator name"
            )

        try:
            view.define_user_type(type_name, parsed_type)
        except Exception as exc:
            raise BinjaBackendError(f"failed to define user type: {exc}") from exc

        return {
            "session_id": session_id,
            "name": type_name,
            "type": repr(parsed_type),
            "defined": True,
        }

    def type_rename(self, session_id: str, old_name: str, new_name: str) -> dict[str, Any]:
        if not old_name:
            raise BinjaBackendError("old_name is required")
        if not new_name:
            raise BinjaBackendError("new_name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before renaming types",
        )

        view = self._get_view(session_id)
        try:
            view.rename_type(old_name, new_name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to rename type: {exc}") from exc

        return {
            "session_id": session_id,
            "old_name": old_name,
            "new_name": new_name,
            "renamed": True,
        }

    def type_undefine_user(self, session_id: str, name: str) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before undefining user types",
        )

        view = self._get_view(session_id)
        try:
            view.undefine_user_type(name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to undefine user type: {exc}") from exc

        return {"session_id": session_id, "name": name, "undefined": True}

    def type_import_library_type(
        self,
        session_id: str,
        name: str,
        *,
        type_library_id: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        view = self._get_view(session_id)
        library = self._get_type_library(type_library_id) if type_library_id else None

        try:
            imported = view.import_library_type(name, lib=library)
        except Exception as exc:
            raise BinjaBackendError(f"failed to import library type: {exc}") from exc

        return {
            "session_id": session_id,
            "name": name,
            "type_library_id": type_library_id,
            "imported": imported is not None,
            "type": repr(imported) if imported is not None else None,
        }

    def type_import_library_object(
        self,
        session_id: str,
        name: str,
        *,
        type_library_id: str | None = None,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        view = self._get_view(session_id)
        library = self._get_type_library(type_library_id) if type_library_id else None

        try:
            imported = view.import_library_object(name, lib=library)
        except Exception as exc:
            raise BinjaBackendError(f"failed to import library object: {exc}") from exc

        library_name = self._safe_attr(library, "name")
        imported_type = imported
        if isinstance(imported, tuple) and len(imported) == 2:
            library_name = self._safe_attr(imported[0], "name")
            imported_type = imported[1]

        return {
            "session_id": session_id,
            "name": name,
            "type_library_id": type_library_id,
            "imported": imported is not None,
            "library_name": library_name,
            "type": repr(imported_type) if imported_type is not None else None,
        }

    def type_export_to_library(
        self,
        session_id: str,
        type_library_id: str,
        type_source: str,
        *,
        name: str | None = None,
        import_dependencies: bool = True,
    ) -> dict[str, Any]:
        if not type_library_id:
            raise BinjaBackendError("type_library_id is required")
        if not type_source:
            raise BinjaBackendError("type_source is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before exporting types",
        )

        view = self._get_view(session_id)
        library = self._get_type_library(type_library_id)

        try:
            parsed_type, parsed_name = view.parse_type_string(
                type_source,
                import_dependencies=import_dependencies,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse type string: {exc}") from exc

        export_name = name or (str(parsed_name) if parsed_name is not None else None)
        if export_name is None:
            raise BinjaBackendError(
                "name is required when parsed type string does not include a declarator name"
            )

        try:
            view.export_type_to_library(library, export_name, parsed_type)
        except Exception as exc:
            raise BinjaBackendError(f"failed to export type to library: {exc}") from exc

        return {
            "session_id": session_id,
            "type_library_id": type_library_id,
            "name": export_name,
            "exported": True,
        }

    def type_library_create(
        self,
        session_id: str,
        name: str,
        *,
        path: str | None = None,
        add_to_view: bool = True,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before creating type libraries",
        )
        view = self._get_view(session_id)

        try:
            library = self._bn.TypeLibrary.new(view.arch, name)
            if add_to_view:
                view.add_type_library(library)
            if path:
                library.write_to_file(path)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create type library: {exc}") from exc

        type_library_id = self._register_type_library(library)
        return self.type_library_get(session_id, type_library_id)

    def type_library_load(
        self,
        session_id: str,
        path: str,
        *,
        add_to_view: bool = True,
    ) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before loading type libraries",
        )

        view = self._get_view(session_id)
        try:
            library = self._bn.TypeLibrary.load_from_file(path)
        except Exception as exc:
            raise BinjaBackendError(f"failed to load type library: {exc}") from exc
        if library is None:
            raise BinjaBackendError("failed to load type library: no TypeLibrary returned")

        try:
            if add_to_view:
                view.add_type_library(library)
        except Exception as exc:
            raise BinjaBackendError(f"failed to add type library to view: {exc}") from exc

        type_library_id = self._register_type_library(library)
        return self.type_library_get(session_id, type_library_id)

    def type_library_list(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)
        items = []
        for library in self._safe_iter(self._safe_attr(view, "type_libraries")):
            type_library_id = self._register_type_library(library)
            items.append(self._type_library_to_record(type_library_id, library))

        return {"session_id": session_id, "count": len(items), "items": items}

    def type_library_get(self, session_id: str, type_library_id: str) -> dict[str, Any]:
        if not type_library_id:
            raise BinjaBackendError("type_library_id is required")
        _ = self._get_view(session_id)
        library = self._get_type_library(type_library_id)
        return {
            "session_id": session_id,
            "type_library": self._type_library_to_record(type_library_id, library),
        }

    def type_archive_create(
        self,
        session_id: str,
        path: str,
        *,
        platform_name: str | None = None,
        attach: bool = True,
    ) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before creating type archives",
        )
        view = self._get_view(session_id)

        platform = view.platform
        if platform_name:
            try:
                platform = self._bn.Platform[platform_name]
            except Exception as exc:
                raise BinjaBackendError(f"unknown platform: {platform_name}") from exc
        if platform is None:
            raise BinjaBackendError("unable to determine platform for type archive creation")

        try:
            archive = self._bn.TypeArchive.create(path, platform)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create type archive: {exc}") from exc
        if archive is None:
            raise BinjaBackendError("failed to create type archive: no TypeArchive returned")

        archive_id = self._register_type_archive(archive)
        if attach:
            try:
                view.attach_type_archive(archive)
            except Exception as exc:
                raise BinjaBackendError(f"failed to attach type archive: {exc}") from exc

        return self.type_archive_get(session_id, archive_id)

    def type_archive_open(
        self,
        session_id: str,
        path: str,
        *,
        attach: bool = True,
    ) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before opening type archives",
        )
        view = self._get_view(session_id)

        try:
            archive = self._bn.TypeArchive.open(path)
        except Exception as exc:
            raise BinjaBackendError(f"failed to open type archive: {exc}") from exc
        if archive is None:
            raise BinjaBackendError("failed to open type archive: no TypeArchive returned")

        archive_id = self._register_type_archive(archive)
        if attach:
            try:
                view.attach_type_archive(archive)
            except Exception as exc:
                raise BinjaBackendError(f"failed to attach type archive: {exc}") from exc

        return self.type_archive_get(session_id, archive_id)

    def type_archive_list(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)
        attached = dict(self._safe_attr(view, "attached_type_archives") or {})
        type_names = self._name_list(self._safe_attr(view, "type_archive_type_names"))
        items = []

        for archive_id, path in attached.items():
            archive = None
            try:
                archive = view.get_type_archive(archive_id)
            except Exception:
                archive = None
            archive_record_id = str(archive_id)
            if archive is not None:
                archive_record_id = self._register_type_archive(archive)
            items.append(
                {
                    "type_archive_id": str(archive_record_id),
                    "path": str(path) if path is not None else None,
                    "attached": True,
                    "type_names": type_names,
                }
            )

        return {"session_id": session_id, "count": len(items), "items": items}

    def type_archive_get(self, session_id: str, type_archive_id: str) -> dict[str, Any]:
        if not type_archive_id:
            raise BinjaBackendError("type_archive_id is required")
        _ = self._get_view(session_id)
        archive = self._get_type_archive(type_archive_id)
        return {
            "session_id": session_id,
            "type_archive": self._type_archive_to_record(archive),
        }

    def type_archive_pull(
        self,
        session_id: str,
        type_archive_id: str,
        names: list[str],
    ) -> dict[str, Any]:
        if not type_archive_id:
            raise BinjaBackendError("type_archive_id is required")
        if not names:
            raise BinjaBackendError("names is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before pulling types from archives",
        )

        view = self._get_view(session_id)
        archive = self._get_type_archive(type_archive_id)
        try:
            pulled = view.pull_types_from_archive(archive, names)
        except Exception as exc:
            raise BinjaBackendError(f"failed to pull types from archive: {exc}") from exc

        if pulled is None:
            raise BinjaBackendError(
                "failed to pull types from archive: unknown type or native failure"
            )
        return {
            "session_id": session_id,
            "type_archive_id": type_archive_id,
            "names": names,
            "pulled": self._to_jsonable(pulled),
        }

    def type_archive_push(
        self,
        session_id: str,
        type_archive_id: str,
        names: list[str],
    ) -> dict[str, Any]:
        if not type_archive_id:
            raise BinjaBackendError("type_archive_id is required")
        if not names:
            raise BinjaBackendError("names is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before pushing types to archives",
        )

        view = self._get_view(session_id)
        archive = self._get_type_archive(type_archive_id)
        try:
            pushed = view.push_types_to_archive(archive, names)
        except Exception as exc:
            raise BinjaBackendError(f"failed to push types to archive: {exc}") from exc

        if pushed is None:
            raise BinjaBackendError(
                "failed to push types to archive: unknown type or native failure"
            )
        return {
            "session_id": session_id,
            "type_archive_id": type_archive_id,
            "names": names,
            "pushed": self._to_jsonable(pushed),
        }

    def type_archive_references(
        self,
        type_archive_id: str,
        name: str,
    ) -> dict[str, Any]:
        if not type_archive_id:
            raise BinjaBackendError("type_archive_id is required")
        if not name:
            raise BinjaBackendError("name is required")

        archive = self._get_type_archive(type_archive_id)
        try:
            type_id = archive.get_type_id(name)
            if type_id is None:
                raise BinjaBackendError(f"unknown archive type: {name}")
            outgoing_direct = archive.get_outgoing_direct_references(type_id)
            outgoing_recursive = archive.get_outgoing_recursive_references(type_id)
            incoming_direct = archive.get_incoming_direct_references(type_id)
            incoming_recursive = archive.get_incoming_recursive_references(type_id)
        except Exception as exc:
            raise BinjaBackendError(f"failed to query type archive references: {exc}") from exc

        return {
            "type_archive_id": type_archive_id,
            "name": name,
            "outgoing_direct": self._to_jsonable(outgoing_direct),
            "outgoing_recursive": self._to_jsonable(outgoing_recursive),
            "incoming_direct": self._to_jsonable(incoming_direct),
            "incoming_recursive": self._to_jsonable(incoming_recursive),
        }

    def debug_list_parsers(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)

        try:
            parsers = list(self._bn.DebugInfoParser.get_parsers_for_view(view))
        except Exception as exc:
            raise BinjaBackendError(f"failed to enumerate debug parsers: {exc}") from exc

        items = []
        for parser in parsers:
            items.append({"name": self._safe_attr(parser, "name")})

        return {"session_id": session_id, "count": len(items), "items": items}

    def debug_parse_and_apply(
        self,
        session_id: str,
        *,
        debug_path: str | None = None,
        parser_name: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before applying debug info",
        )
        view = self._get_view(session_id)

        parse_path = debug_path or self._safe_attr_chain(view, "file.filename")
        if not parse_path:
            raise BinjaBackendError("debug_path is required when session has no filename")

        debug_view = None
        try:
            debug_view = self._bn.load(parse_path, update_analysis=False)
            if debug_view is None:
                raise BinjaBackendError("failed to load debug information file")
            # External parsers identify the debug file, which may contain sections
            # deliberately removed from the target executable (for example DWARF).
            parser_view = debug_view if debug_path else view
            try:
                parsers = list(self._bn.DebugInfoParser.get_parsers_for_view(parser_view))
            except Exception as exc:
                raise BinjaBackendError(f"failed to enumerate debug parsers: {exc}") from exc
            if not parsers:
                raise BinjaBackendError("no debug info parser is available for this view")
            parser = next(
                (
                    candidate
                    for candidate in parsers
                    if parser_name is None or self._safe_attr(candidate, "name") == parser_name
                ),
                None,
            )
            if parser is None:
                raise BinjaBackendError(f"debug parser not found: {parser_name}")
            debug_info = parser.parse_debug_info(view, debug_view)
            if debug_info is None:
                raise BinjaBackendError("debug parser returned no debug info")
            view.apply_debug_info(debug_info)
        except BinjaBackendError:
            raise
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse/apply debug info: {exc}") from exc
        finally:
            if debug_view is not None:
                self._close_view(debug_view)

        type_count = self._iter_count(self._safe_attr(debug_info, "types"))
        function_count = self._iter_count(self._safe_attr(debug_info, "functions"))
        data_var_count = self._iter_count(self._safe_attr(debug_info, "data_variables"))

        return {
            "session_id": session_id,
            "parser_name": self._safe_attr(parser, "name"),
            "debug_path": parse_path,
            "type_count": type_count,
            "function_count": function_count,
            "data_var_count": data_var_count,
            "applied": True,
        }

    def workflow_list(self) -> dict[str, Any]:
        workflows = list(self._safe_iter(self._safe_attr(self._bn.Workflow, "list")))
        items = [str(workflow) for workflow in workflows]
        return {"count": len(items), "items": items}

    def workflow_describe(
        self,
        session_id: str,
        *,
        workflow_name: str | None = None,
        activity: str = "",
        immediate: bool = True,
    ) -> dict[str, Any]:
        workflow = self._resolve_workflow(session_id, workflow_name)

        try:
            subactivities = workflow.subactivities(activity, immediate=immediate)
        except Exception:
            subactivities = []

        try:
            roots = workflow.activity_roots(activity)
        except Exception:
            roots = []

        try:
            configuration = workflow.configuration(activity)
        except Exception:
            configuration = ""

        try:
            eligibility_settings = workflow.eligibility_settings()
        except Exception:
            eligibility_settings = []

        return {
            "session_id": session_id,
            "name": self._safe_attr(workflow, "name"),
            "registered": bool(self._safe_attr(workflow, "registered")),
            "activity": activity,
            "immediate": immediate,
            "roots": self._to_jsonable(roots),
            "subactivities": self._to_jsonable(subactivities),
            "configuration": configuration,
            "eligibility_settings": self._to_jsonable(eligibility_settings),
        }

    def workflow_clone(
        self,
        session_id: str,
        name: str,
        *,
        register: bool = False,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before cloning workflows",
        )
        workflow = self._resolve_workflow(session_id, None)

        try:
            cloned = workflow.clone(name)
            if register and not cloned.register():
                raise BinjaBackendError(f"failed to register workflow: {name}")
        except Exception as exc:
            raise BinjaBackendError(f"failed to clone workflow: {exc}") from exc

        with self._lock:
            self._workflow_clones[(session_id, name)] = cloned
        return {
            "session_id": session_id,
            "source_workflow": self._safe_attr(workflow, "name"),
            "workflow": self._safe_attr(cloned, "name"),
            "registered": bool(self._safe_attr(cloned, "registered")),
        }

    def workflow_insert(
        self,
        session_id: str,
        activity: str,
        activities: list[str] | str,
        *,
        workflow_name: str | None = None,
        after: bool = False,
    ) -> dict[str, Any]:
        if not activity:
            raise BinjaBackendError("activity is required")
        if not activities:
            raise BinjaBackendError("activities is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before editing workflows",
        )
        workflow = self._resolve_workflow(session_id, workflow_name)

        try:
            if after:
                changed = bool(workflow.insert_after(activity, activities))
            else:
                changed = bool(workflow.insert(activity, activities))
        except Exception as exc:
            raise BinjaBackendError(f"failed to modify workflow: {exc}") from exc

        return {
            "session_id": session_id,
            "workflow": self._safe_attr(workflow, "name"),
            "activity": activity,
            "activities": activities,
            "after": after,
            "changed": changed,
        }

    def workflow_remove(
        self,
        session_id: str,
        activity: str,
        *,
        workflow_name: str | None = None,
    ) -> dict[str, Any]:
        if not activity:
            raise BinjaBackendError("activity is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before editing workflows",
        )
        workflow = self._resolve_workflow(session_id, workflow_name)

        try:
            changed = bool(workflow.remove(activity))
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove workflow activity: {exc}") from exc

        return {
            "session_id": session_id,
            "workflow": self._safe_attr(workflow, "name"),
            "activity": activity,
            "changed": changed,
        }

    def workflow_graph(
        self,
        session_id: str,
        *,
        workflow_name: str | None = None,
        activity: str = "",
        sequential: bool = False,
    ) -> dict[str, Any]:
        workflow = self._resolve_workflow(session_id, workflow_name)
        try:
            graph = workflow.graph(activity, sequential=sequential, show=False)
        except Exception as exc:
            raise BinjaBackendError(f"failed to query workflow graph: {exc}") from exc

        nodes = list(self._safe_iter(self._safe_attr(graph, "nodes")))
        edge_count = 0
        for node in nodes:
            edge_count += self._iter_count(self._safe_attr(node, "outgoing_edges"))

        return {
            "session_id": session_id,
            "workflow": self._safe_attr(workflow, "name"),
            "activity": activity,
            "sequential": sequential,
            "node_count": len(nodes),
            "edge_count": edge_count,
        }

    def workflow_machine_status(
        self,
        session_id: str,
        *,
        workflow_name: str | None = None,
    ) -> dict[str, Any]:
        workflow = self._resolve_workflow(session_id, workflow_name)
        machine = self._safe_attr(workflow, "machine")
        if machine is None:
            raise BinjaBackendError("workflow machine is not available")

        try:
            status = machine.status()
        except Exception as exc:
            raise BinjaBackendError(f"failed to query workflow machine status: {exc}") from exc

        return {
            "session_id": session_id,
            "workflow": self._safe_attr(workflow, "name"),
            "status": self._to_jsonable(status),
            "is_function_machine": bool(self._safe_attr(machine, "is_function_machine")),
        }

    def workflow_machine_control(
        self,
        session_id: str,
        action: str,
        *,
        workflow_name: str | None = None,
        advanced: bool = True,
        incremental: bool = False,
        activities: list[str] | str | None = None,
        activity: str | None = None,
        enable: bool | None = None,
    ) -> dict[str, Any]:
        with self._analysis_control(session_id, interrupts=False):
            return self._workflow_machine_control(
                session_id,
                action,
                workflow_name=workflow_name,
                advanced=advanced,
                incremental=incremental,
                activities=activities,
                activity=activity,
                enable=enable,
            )

    def _workflow_machine_control(  # noqa: PLR0912, PLR0915
        self,
        session_id: str,
        action: str,
        *,
        workflow_name: str | None,
        advanced: bool,
        incremental: bool,
        activities: list[str] | str | None,
        activity: str | None,
        enable: bool | None,
    ) -> dict[str, Any]:
        workflow = self._resolve_workflow(session_id, workflow_name)
        machine = self._safe_attr(workflow, "machine")
        if machine is None:
            raise BinjaBackendError("workflow machine is not available")

        normalized_action = action.lower()
        actions = {
            "run",
            "resume",
            "halt",
            "reset",
            "enable",
            "disable",
            "dump",
            "breakpoint_set",
            "breakpoint_delete",
            "override_set",
            "override_clear",
        }
        if normalized_action not in actions:
            raise BinjaBackendError("action must be one of: " + ", ".join(sorted(actions)))
        if normalized_action == "override_set" and (activity is None or enable is None):
            raise BinjaBackendError(
                "activity and enable are required for workflow machine override_set"
            )
        if normalized_action == "override_clear" and activity is None:
            raise BinjaBackendError("activity is required for workflow machine override_clear")
        if normalized_action != "dump":
            with self._lock:
                record = self._get_record(session_id)
                record.control_generation += 1
                if normalized_action in {"run", "resume", "halt", "reset", "enable", "disable"}:
                    record.resume_generation += 1
                    record.resume_after_abort = False
            if normalized_action in {"disable", "halt", "reset"}:
                self._note_initial_interruption(record)
        try:
            if normalized_action == "run":
                command_result = machine.run(advanced=advanced, incremental=incremental)
            elif normalized_action == "resume":
                command_result = machine.resume(advanced=advanced, incremental=incremental)
            elif normalized_action == "halt":
                command_result = machine.halt()
            elif normalized_action == "reset":
                command_result = machine.reset()
            elif normalized_action == "enable":
                command_result = machine.enable()
            elif normalized_action == "disable":
                command_result = machine.disable()
            elif normalized_action == "dump":
                command_result = machine.dump()
            elif normalized_action == "breakpoint_set":
                command_result = machine.breakpoint_set(activities or [])
            elif normalized_action == "breakpoint_delete":
                command_result = machine.breakpoint_delete(activities or [])
            elif normalized_action == "override_set":
                command_result = machine.override_set(activity, enable)
            elif normalized_action == "override_clear":
                command_result = machine.override_clear(activity)
        except BinjaBackendError:
            raise
        except Exception as exc:
            raise BinjaBackendError(
                f"failed to run workflow machine action '{action}': {exc}"
            ) from exc

        rejected = (
            isinstance(command_result, dict)
            and isinstance(command_result.get("commandStatus"), dict)
            and command_result["commandStatus"].get("accepted") is False
        )
        dump_snapshot = None
        if rejected:
            if normalized_action != "dump":
                raise BinjaBackendError(
                    f"workflow machine rejected action '{action}': {command_result}"
                )
            # Some native versions expose dump() but reject that request in every
            # machine state. Preserve that response and provide an explicit dump
            # of independently queried native state, never fabricated acceptance.
            dump_snapshot = self._workflow_dump_snapshot(workflow, machine, command_result)
        response = self.workflow_machine_status(session_id, workflow_name=workflow_name)
        response["command_result"] = self._to_jsonable(command_result)
        if normalized_action == "dump":
            response["dump_source"] = (
                "native_state_snapshot" if dump_snapshot is not None else "native_command"
            )
            if dump_snapshot is not None:
                response["dump_snapshot"] = dump_snapshot
        return response

    def _workflow_dump_snapshot(
        self, workflow: Any, machine: Any, rejected_command: Any
    ) -> dict[str, Any]:
        snapshot = {}
        try:
            for name, method in (
                ("status", "status"),
                ("breakpoints", "breakpoint_query"),
                ("overrides", "override_query"),
            ):
                result = getattr(machine, method)()
                if (
                    not isinstance(result, dict)
                    or not isinstance(result.get("commandStatus"), dict)
                    or result["commandStatus"].get("accepted") is not True
                ):
                    raise BinjaBackendError(
                        f"native {method} did not accept snapshot query: {result}"
                    )
                snapshot[name] = self._to_jsonable(result)
            snapshot["configuration"] = workflow.configuration()
        except Exception as exc:
            raise BinjaBackendError(
                f"workflow dump rejected and state snapshot failed: {exc}; "
                f"native dump response: {rejected_command}"
            ) from exc
        return snapshot

    def il_rewrite_capabilities(
        self,
        session_id: str,
        function_start: int | str,
        *,
        level: str = "mlil",
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa=False)
        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "supports_replace_expr": hasattr(il, "replace_expr"),
            "supports_finalize": hasattr(il, "finalize"),
            "supports_generate_ssa_form": hasattr(il, "generate_ssa_form"),
            "supports_translate": hasattr(il, "translate"),
        }

    def il_rewrite_noop_replace(
        self,
        session_id: str,
        function_start: int | str,
        *,
        level: str = "mlil",
        index: int | None = None,
        finalize: bool = True,
        generate_ssa_form: bool = True,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before rewriting IL",
        )
        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa=False)
        instructions = list(il.instructions)
        if not instructions:
            raise BinjaBackendError("no IL instructions available")

        target_index = 0 if index is None else index
        if target_index < 0 or target_index >= len(instructions):
            raise BinjaBackendError(
                f"index out of range for {level}: {target_index} not in [0, {len(instructions)})"
            )

        target = instructions[target_index]
        expr_index = self._safe_attr(target, "expr_index")
        if expr_index is None:
            raise BinjaBackendError("selected IL instruction has no expr_index")

        try:
            il.replace_expr(expr_index, expr_index)
            if finalize and hasattr(il, "finalize"):
                il.finalize()
            if generate_ssa_form and hasattr(il, "generate_ssa_form"):
                il.generate_ssa_form()
        except Exception as exc:
            raise BinjaBackendError(f"failed to rewrite IL: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "index": target_index,
            "expr_index": int(expr_index),
            "rewritten": True,
        }

    def il_translate_identity(
        self,
        session_id: str,
        function_start: int | str,
        *,
        level: str = "mlil",
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)
        il = self._get_il_function(function, level, ssa=False)
        if not hasattr(il, "translate"):
            raise BinjaBackendError(f"translate is not available for IL level '{level}'")

        try:
            translated = il.translate(
                lambda destination, _block, instruction: instruction.copy_to(destination)
            )
            translated.finalize()
            translated_count = self._iter_count(self._safe_attr(translated, "instructions"))
        except Exception as exc:
            raise BinjaBackendError(f"failed to translate IL: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "level": level,
            "translated_instruction_count": translated_count,
        }

    def uidf_parse_possible_value(
        self,
        session_id: str,
        value: str,
        state: str,
        *,
        here: int | str | None = None,
    ) -> dict[str, Any]:
        if not value:
            raise BinjaBackendError("value is required")
        if not state:
            raise BinjaBackendError("state is required")

        view = self._get_view(session_id)
        here_value = self._coerce_address(here, "here") if here is not None else 0
        try:
            state_enum = self._bn.RegisterValueType[state]
        except Exception as exc:
            raise BinjaBackendError(f"unknown RegisterValueType state: {state}") from exc

        try:
            parsed = view.parse_possiblevalueset(value, state_enum, here=here_value)
        except Exception as exc:
            raise BinjaBackendError(f"failed to parse possible value set: {exc}") from exc

        return {
            "session_id": session_id,
            "value": value,
            "state": state,
            "here": hex(here_value),
            "parsed": self._to_jsonable(parsed),
        }

    def uidf_set_user_var_value(  # noqa: PLR0917 - preserve the existing backend API
        self,
        session_id: str,
        function_start: int | str,
        variable_name: str,
        def_addr: int | str,
        value: str,
        state: str,
        *,
        after: bool = True,
    ) -> dict[str, Any]:
        if not variable_name:
            raise BinjaBackendError("variable_name is required")
        if not value:
            raise BinjaBackendError("value is required")
        if not state:
            raise BinjaBackendError("state is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before setting user variable values",
        )

        view = self._get_view(session_id)
        function = self._get_function_by_start(session_id, function_start)
        variable = self._find_variable(function, variable_name)
        if variable is None:
            raise BinjaBackendError(f"variable not found: {variable_name}")
        def_addr_int = self._coerce_address(def_addr, "def_addr")

        try:
            state_enum = self._bn.RegisterValueType[state]
        except Exception as exc:
            raise BinjaBackendError(f"unknown RegisterValueType state: {state}") from exc

        try:
            parsed = view.parse_possiblevalueset(value, state_enum, here=def_addr_int)
            function.set_user_var_value(variable, def_addr_int, parsed, after=after)
        except Exception as exc:
            raise BinjaBackendError(f"failed to set user variable value: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "variable_name": variable_name,
            "def_addr": hex(def_addr_int),
            "after": after,
            "set": True,
        }

    def uidf_clear_user_var_value(
        self,
        session_id: str,
        function_start: int | str,
        variable_name: str,
        def_addr: int | str,
        *,
        after: bool = True,
    ) -> dict[str, Any]:
        if not variable_name:
            raise BinjaBackendError("variable_name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before clearing user variable values",
        )

        function = self._get_function_by_start(session_id, function_start)
        variable = self._find_variable(function, variable_name)
        if variable is None:
            raise BinjaBackendError(f"variable not found: {variable_name}")
        def_addr_int = self._coerce_address(def_addr, "def_addr")

        try:
            function.clear_user_var_value(variable, def_addr_int, after=after)
        except Exception as exc:
            raise BinjaBackendError(f"failed to clear user variable value: {exc}") from exc

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "variable_name": variable_name,
            "def_addr": hex(def_addr_int),
            "after": after,
            "cleared": True,
        }

    def uidf_list_user_var_values(
        self,
        session_id: str,
        function_start: int | str,
    ) -> dict[str, Any]:
        function = self._get_function_by_start(session_id, function_start)

        try:
            values = function.get_all_user_var_values()
        except Exception as exc:
            raise BinjaBackendError(f"failed to list user variable values: {exc}") from exc

        items = []
        for variable, mapping in dict(values).items():
            definitions = []
            for arch_and_addr, possible_value in dict(mapping).items():
                definitions.append(
                    {
                        "arch": self._safe_attr_chain(arch_and_addr, "arch.name"),
                        "address": self._hex_or_none(self._safe_attr(arch_and_addr, "addr")),
                        "value": self._to_jsonable(possible_value),
                    }
                )
            items.append(
                {
                    "variable": self._variable_to_record(variable),
                    "definitions": definitions,
                }
            )

        return {
            "session_id": session_id,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "count": len(items),
            "items": items,
        }

    def loader_rebase(
        self,
        session_id: str,
        address: int | str,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        with self._exclusive_session(session_id):
            return self._rebase_session(session_id, address, force=force)

    def _rebase_session(
        self, session_id: str, address: int | str, *, force: bool
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before rebasing",
        )
        record = self._get_record(session_id)
        view = record.view
        target = self._coerce_address(address, "address")
        if record.has_byte_edits:
            raise BinjaBackendError(
                "rebase is not allowed after byte edits in this session; "
                "reopen the binary in a fresh session before rebasing"
            )

        active_task_ids = self._active_task_ids_for_session(session_id)
        if active_task_ids:
            raise BinjaBackendError(
                "rebase is not allowed while async tasks are active for this session; "
                "wait for completion or cancel the tasks first"
            )

        current_start = self._safe_attr(view, "start")
        filename = self._safe_attr_chain(view, "file.filename")
        if (
            isinstance(filename, str)
            and filename.lower().endswith(".bndb")
            and isinstance(current_start, int)
            and current_start == 0
            and target != 0
        ):
            raise BinjaBackendError(
                "refusing to rebase this .bndb session from base 0; "
                "reopen the original binary and rebase there instead"
            )

        if not force and isinstance(current_start, int) and current_start == target:
            return {
                "session_id": session_id,
                "address": hex(target),
                "force": force,
                "rebased": False,
                "start": self._hex_or_none(current_start),
                "end": self._hex_or_none(self._safe_attr(view, "end")),
            }

        try:
            rebased = view.rebase(target, force=force)
        except Exception as exc:
            raise BinjaBackendError(f"failed to rebase view: {exc}") from exc

        if rebased is not None and rebased is not view:
            shared_file = view.file == rebased.file
            record.view = rebased
            # Native rebase returns a new view sharing its FileMetadata. Closing
            # that file would also abort/invalidate the replacement view.
            if not shared_file:
                self._close_view(view)
            view = rebased
            self._base_detectors.pop(session_id, None)
            record.native_status = self._native_analysis_status(view)
            record.resume_after_abort = (
                record.resume_after_abort and shared_file and record.native_status["is_aborted"]
            )
            record.last_analysis_status = "idle"
            record.last_analysis_started_at = None
            record.last_analysis_completed_at = None
            record.last_analysis_task_id = None
            record.last_analysis_error = None
            record.summary = {}
            self.binary_summary(session_id)

        return {
            "session_id": session_id,
            "address": hex(target),
            "force": force,
            "rebased": rebased is not None,
            "start": self._hex_or_none(self._safe_attr(view, "start")),
            "end": self._hex_or_none(self._safe_attr(view, "end")),
        }

    def loader_load_settings_types(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)
        names = []
        for item in self._safe_iter(view.get_load_settings_type_names()):
            if isinstance(item, bytes):
                names.append(item.decode("utf-8", errors="replace"))
            else:
                names.append(str(item))
        return {"session_id": session_id, "count": len(names), "items": names}

    def loader_load_settings_get(
        self,
        session_id: str,
        type_name: str,
    ) -> dict[str, Any]:
        if not type_name:
            raise BinjaBackendError("type_name is required")
        view = self._get_view(session_id)
        try:
            settings = view.get_load_settings(type_name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to get load settings: {exc}") from exc
        if settings is None:
            raise BinjaBackendError(f"load settings not found: {type_name}")

        try:
            keys = list(settings.keys())
        except Exception:
            keys = []
        try:
            serialized = settings.serialize_settings(resource=view)
        except Exception:
            serialized = "{}"

        return {
            "session_id": session_id,
            "type_name": type_name,
            "key_count": len(keys),
            "keys": keys,
            "serialized_settings": serialized,
        }

    def loader_load_settings_set(  # noqa: PLR0912
        self,
        session_id: str,
        type_name: str,
        key: str,
        value: Any,
        *,
        value_type: str = "string",
    ) -> dict[str, Any]:
        if not type_name:
            raise BinjaBackendError("type_name is required")
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before modifying load settings",
        )
        view = self._get_view(session_id)
        try:
            settings = view.get_load_settings(type_name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to get load settings: {exc}") from exc
        if settings is None:
            raise BinjaBackendError(f"load settings not found: {type_name}")

        normalized = value_type.lower()
        try:
            if normalized == "string":
                changed = bool(settings.set_string(key, str(value), resource=view))
            elif normalized == "integer":
                changed = bool(settings.set_integer(key, int(value), resource=view))
            elif normalized == "bool":
                changed = bool(settings.set_bool(key, bool(value), resource=view))
            elif normalized == "json":
                changed = bool(settings.set_json(key, value, resource=view))
            elif normalized == "string_list":
                if not isinstance(value, list):
                    raise BinjaBackendError("value must be a list for value_type=string_list")
                changed = bool(
                    settings.set_string_list(
                        key,
                        [str(item) for item in value],
                        resource=view,
                    )
                )
            else:
                raise BinjaBackendError(
                    "value_type must be one of: string, integer, bool, json, string_list"
                )
            view.set_load_settings(type_name, settings)
        except BinjaBackendError:
            raise
        except Exception as exc:
            raise BinjaBackendError(f"failed to set load settings: {exc}") from exc

        return {
            "session_id": session_id,
            "type_name": type_name,
            "key": key,
            "value_type": normalized,
            "changed": changed,
        }

    def segment_add_user(
        self,
        session_id: str,
        start: int | str,
        length: int,
        *,
        data_offset: int = 0,
        data_length: int = 0,
        readable: bool = True,
        writable: bool = False,
        executable: bool = False,
        contains_data: bool = True,
        contains_code: bool = False,
    ) -> dict[str, Any]:
        if length <= 0:
            raise BinjaBackendError("length must be > 0")
        if data_offset < 0:
            raise BinjaBackendError("data_offset must be >= 0")
        if data_length < 0:
            raise BinjaBackendError("data_length must be >= 0")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding segments",
        )
        view = self._get_view(session_id)
        start_int = self._coerce_address(start, "start")
        flags = self._build_segment_flags(
            readable=readable,
            writable=writable,
            executable=executable,
            contains_data=contains_data,
            contains_code=contains_code,
        )

        try:
            view.add_user_segment(start_int, length, data_offset, data_length, flags)
        except Exception as exc:
            raise BinjaBackendError(f"failed to add user segment: {exc}") from exc

        segment = view.get_segment_at(start_int)
        return {
            "session_id": session_id,
            "start": hex(start_int),
            "length": length,
            "segment": self._segment_to_record(segment),
        }

    def segment_remove_user(
        self,
        session_id: str,
        start: int | str,
        *,
        length: int = 0,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing segments",
        )
        view = self._get_view(session_id)
        start_int = self._coerce_address(start, "start")
        try:
            view.remove_user_segment(start_int, length=length)
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove user segment: {exc}") from exc
        return {
            "session_id": session_id,
            "start": hex(start_int),
            "length": length,
            "removed": True,
        }

    def section_add_user(
        self,
        session_id: str,
        name: str,
        start: int | str,
        length: int,
        *,
        semantics: str = "DefaultSectionSemantics",
        type_name: str = "",
        align: int = 1,
        entry_size: int = 1,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        if length <= 0:
            raise BinjaBackendError("length must be > 0")
        if align <= 0:
            raise BinjaBackendError("align must be > 0")
        if entry_size <= 0:
            raise BinjaBackendError("entry_size must be > 0")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding sections",
        )
        view = self._get_view(session_id)
        start_int = self._coerce_address(start, "start")
        try:
            semantics_value = self._bn.SectionSemantics[semantics]
        except Exception as exc:
            raise BinjaBackendError(f"unknown SectionSemantics: {semantics}") from exc

        try:
            view.add_user_section(
                name,
                start_int,
                length,
                semantics=semantics_value,
                type=type_name,
                align=align,
                entry_size=entry_size,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to add user section: {exc}") from exc

        section = view.get_section_by_name(name)
        return {
            "session_id": session_id,
            "name": name,
            "section": self._section_to_record(name, section),
        }

    def section_remove_user(self, session_id: str, name: str) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing sections",
        )
        view = self._get_view(session_id)
        try:
            view.remove_user_section(name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove user section: {exc}") from exc
        return {"session_id": session_id, "name": name, "removed": True}

    def external_library_add(
        self,
        session_id: str,
        name: str,
        *,
        auto: bool = False,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding external libraries",
        )
        view = self._get_view(session_id)
        try:
            library = view.add_external_library(name, auto=auto)
        except Exception as exc:
            raise BinjaBackendError(f"failed to add external library: {exc}") from exc
        return {
            "session_id": session_id,
            "external_library": self._external_library_to_record(library),
        }

    def external_library_list(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)
        try:
            libraries = list(view.get_external_libraries())
        except Exception as exc:
            raise BinjaBackendError(f"failed to list external libraries: {exc}") from exc
        return {
            "session_id": session_id,
            "count": len(libraries),
            "items": [self._external_library_to_record(library) for library in libraries],
        }

    def external_library_remove(self, session_id: str, name: str) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing external libraries",
        )
        view = self._get_view(session_id)
        try:
            view.remove_external_library(name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove external library: {exc}") from exc
        return {"session_id": session_id, "name": name, "removed": True}

    def external_location_add(
        self,
        session_id: str,
        source_address: int | str,
        *,
        library_name: str | None = None,
        target_symbol: str | None = None,
        target_address: int | str | None = None,
        auto: bool = False,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before adding external locations",
        )
        view = self._get_view(session_id)
        source_address_int = self._coerce_address(source_address, "source_address")
        symbol = view.get_symbol_at(source_address_int)
        if symbol is None:
            raise BinjaBackendError(f"no symbol at address {hex(source_address_int)}")

        library = None
        if library_name is not None:
            library = view.get_external_library(library_name)
            if library is None:
                raise BinjaBackendError(f"external library not found: {library_name}")

        target_address_int = (
            self._coerce_address(target_address, "target_address")
            if target_address is not None
            else None
        )
        try:
            location = view.add_external_location(
                symbol,
                library,
                target_symbol,
                target_address_int,
                auto=auto,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to add external location: {exc}") from exc

        return {
            "session_id": session_id,
            "source_address": hex(source_address_int),
            "external_location": self._external_location_to_record(location),
        }

    def external_location_get(
        self,
        session_id: str,
        source_address: int | str,
    ) -> dict[str, Any]:
        view = self._get_view(session_id)
        source_address_int = self._coerce_address(source_address, "source_address")
        symbol = view.get_symbol_at(source_address_int)
        if symbol is None:
            raise BinjaBackendError(f"no symbol at address {hex(source_address_int)}")
        location = view.get_external_location(symbol)
        return {
            "session_id": session_id,
            "source_address": hex(source_address_int),
            "external_location": self._external_location_to_record(location),
        }

    def external_location_remove(
        self,
        session_id: str,
        source_address: int | str,
    ) -> dict[str, Any]:
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before removing external locations",
        )
        view = self._get_view(session_id)
        source_address_int = self._coerce_address(source_address, "source_address")
        symbol = view.get_symbol_at(source_address_int)
        if symbol is None:
            raise BinjaBackendError(f"no symbol at address {hex(source_address_int)}")
        try:
            view.remove_external_location(symbol)
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove external location: {exc}") from exc
        return {
            "session_id": session_id,
            "source_address": hex(source_address_int),
            "removed": True,
        }

    def arch_info(self, session_id: str) -> dict[str, Any]:
        view = self._get_view(session_id)
        arch = self._safe_attr(view, "arch")
        platform = self._safe_attr(view, "platform")
        register_names = self._name_list(self._safe_attr(arch, "regs")) if arch else []
        flag_names = self._name_list(self._safe_attr(arch, "flags")) if arch else []
        intrinsic_names = self._name_list(self._safe_attr(arch, "intrinsics")) if arch else []

        calling_conventions = []
        for convention in self._safe_iter(self._safe_attr(platform, "calling_conventions")):
            calling_conventions.append(self._safe_attr(convention, "name"))

        return {
            "session_id": session_id,
            "arch": self._safe_attr(arch, "name"),
            "platform": self._safe_attr(platform, "name"),
            "address_size": self._safe_attr(arch, "address_size"),
            "default_int_size": self._safe_attr(arch, "default_int_size"),
            "max_instr_length": self._safe_attr(arch, "max_instr_length"),
            "register_count": len(register_names),
            "registers": register_names,
            "flag_count": len(flag_names),
            "flags": flag_names,
            "intrinsic_count": len(intrinsic_names),
            "intrinsics": intrinsic_names,
            "calling_conventions": calling_conventions,
        }

    def arch_disasm_bytes(
        self,
        session_id: str,
        data_hex: str,
        *,
        address: int | str = 0,
        arch_name: str | None = None,
    ) -> dict[str, Any]:
        if not data_hex:
            raise BinjaBackendError("data_hex is required")
        try:
            data = bytes.fromhex(data_hex)
        except ValueError as exc:
            raise BinjaBackendError(f"invalid hex bytes: {exc}") from exc
        address_int = self._coerce_address(address, "address")
        arch = self._resolve_arch(session_id, arch_name)

        try:
            instruction_text = arch.get_instruction_text(data, address_int)
            instruction_info = arch.get_instruction_info(data, address_int)
        except Exception as exc:
            raise BinjaBackendError(f"failed to disassemble bytes: {exc}") from exc

        if instruction_text is None:
            raise BinjaBackendError("architecture returned no instruction text")

        tokens, length = instruction_text
        token_items = [
            {"text": str(token), "type": self._enum_name_or_value(token.type)} for token in tokens
        ]
        branch_count = self._iter_count(self._safe_attr(instruction_info, "branches"))

        return {
            "session_id": session_id,
            "arch": self._safe_attr(arch, "name"),
            "address": hex(address_int),
            "length": length,
            "text": "".join(token["text"] for token in token_items),
            "tokens": token_items,
            "branch_count": branch_count,
        }

    def arch_assemble(
        self,
        session_id: str,
        asm: str,
        *,
        address: int | str = 0,
        arch_name: str | None = None,
    ) -> dict[str, Any]:
        if not asm:
            raise BinjaBackendError("asm is required")
        address_int = self._coerce_address(address, "address")
        arch = self._resolve_arch(session_id, arch_name)

        try:
            data = arch.assemble(asm, address_int)
        except Exception as exc:
            raise BinjaBackendError(f"failed to assemble instruction: {exc}") from exc

        return {
            "session_id": session_id,
            "arch": self._safe_attr(arch, "name"),
            "address": hex(address_int),
            "asm": asm,
            "data_hex": data.hex(),
            "size": len(data),
        }

    def transform_inspect(
        self,
        *,
        session_id: str | None = None,
        path: str | None = None,
        mode: str = "full",
        process: bool = False,
    ) -> dict[str, Any]:
        target: Any
        if session_id is not None:
            target = self._get_view(session_id)
        elif path:
            target = path
        else:
            raise BinjaBackendError("session_id or path is required")

        mode_value = self._resolve_transform_mode(mode)
        try:
            session = self._bn.TransformSession(target, mode=mode_value)
            root_context = session.root_context
            if session_id is not None and root_context is not None:
                # Unselected transform contexts close their input when freed.
                # This view belongs to the MCP session, including on failure.
                session.set_selected_contexts(root_context)
            if process:
                session.process()
        except Exception as exc:
            raise BinjaBackendError(f"failed to create/process transform session: {exc}") from exc

        current_view = self._safe_attr(session, "current_view")
        try:
            selected = list(self._safe_iter(self._safe_attr(session, "selected_contexts")))
        except Exception:
            selected = []

        return {
            "session_id": session_id,
            "path": path,
            "mode": mode,
            "processed": process,
            "has_any_stages": bool(self._safe_attr(session, "has_any_stages")),
            "has_single_path": bool(self._safe_attr(session, "has_single_path")),
            "current_view_type": self._safe_attr(current_view, "view_type"),
            "root_context": self._transform_context_to_record(root_context),
            "selected_context_count": len(selected),
        }

    def project_create(self, path: str, name: str) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")
        if not name:
            raise BinjaBackendError("name is required")

        try:
            project = self._bn.Project.create_project(path, name)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create project: {exc}") from exc

        project_id = self._register_project(project)
        return {"project": self._project_to_record(project_id, project)}

    def project_open(self, path: str) -> dict[str, Any]:
        if not path:
            raise BinjaBackendError("path is required")

        try:
            project = self._bn.Project.open_project(path)
        except Exception as exc:
            raise BinjaBackendError(f"failed to open project: {exc}") from exc

        project_id = self._register_project(project)
        return {"project": self._project_to_record(project_id, project)}

    def project_close(self, project_id: str) -> dict[str, Any]:
        project = self._get_project(project_id)
        try:
            closed = bool(project.close())
        except Exception as exc:
            raise BinjaBackendError(f"failed to close project: {exc}") from exc
        self._projects.pop(project_id, None)
        return {"project_id": project_id, "closed": closed}

    def project_list(self, project_id: str) -> dict[str, Any]:
        project = self._get_project(project_id)
        folders = list(self._safe_iter(self._safe_attr(project, "folders")))
        files = list(self._safe_iter(self._safe_attr(project, "files")))

        return {
            "project": self._project_to_record(project_id, project),
            "folder_count": len(folders),
            "file_count": len(files),
            "folders": [self._project_folder_to_record(folder) for folder in folders],
            "files": [self._project_file_to_record(file_obj) for file_obj in files],
        }

    def project_create_folder(
        self,
        project_id: str,
        name: str,
        *,
        parent_folder_id: str | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        project = self._get_project(project_id)
        parent_folder = self._project_find_folder(project, parent_folder_id)

        try:
            folder = project.create_folder(parent_folder, name, description=description)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create project folder: {exc}") from exc

        return {"project_id": project_id, "folder": self._project_folder_to_record(folder)}

    def project_create_file(
        self,
        project_id: str,
        name: str,
        data_base64: str,
        *,
        folder_id: str | None = None,
        description: str = "",
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        if not data_base64:
            raise BinjaBackendError("data_base64 is required")
        project = self._get_project(project_id)
        folder = self._project_find_folder(project, folder_id)
        try:
            data = base64.b64decode(data_base64, validate=True)
        except (ValueError, binascii.Error) as exc:
            raise BinjaBackendError(f"invalid base64 data: {exc}") from exc

        try:
            file_obj = project.create_file(
                data,
                folder,
                name,
                description=description,
            )
        except Exception as exc:
            raise BinjaBackendError(f"failed to create project file: {exc}") from exc

        return {"project_id": project_id, "file": self._project_file_to_record(file_obj)}

    def project_metadata_store(self, project_id: str, key: str, value: Any) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        project = self._get_project(project_id)
        try:
            project.store_metadata(key, value)
            queried = project.query_metadata(key)
        except Exception as exc:
            raise BinjaBackendError(f"failed to store project metadata: {exc}") from exc
        return {
            "project_id": project_id,
            "key": key,
            "value": self._to_jsonable(queried),
        }

    def project_metadata_query(self, project_id: str, key: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        project = self._get_project(project_id)
        try:
            value = project.query_metadata(key)
        except Exception:
            value = None
        return {"project_id": project_id, "key": key, "value": self._to_jsonable(value)}

    def project_metadata_remove(self, project_id: str, key: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        project = self._get_project(project_id)
        try:
            project.remove_metadata(key)
        except Exception as exc:
            raise BinjaBackendError(f"failed to remove project metadata: {exc}") from exc
        return {"project_id": project_id, "key": key, "removed": True}

    def database_info(self, session_id: str) -> dict[str, Any]:
        database = self._get_database(session_id)
        snapshots = list(self._safe_iter(self._safe_attr(database, "snapshots")))
        current = self._safe_attr(database, "current_snapshot")
        try:
            global_keys = list(self._safe_iter(self._safe_attr(database, "global_keys")))
        except Exception:
            global_keys = []

        return {
            "session_id": session_id,
            "snapshot_count": len(snapshots),
            "current_snapshot": self._snapshot_to_record(current),
            "global_key_count": len(global_keys),
            "global_keys": [str(key) for key in global_keys],
        }

    def _database_global_keys(self, database: Any) -> set[str] | None:
        try:
            keys = self._safe_iter(self._safe_attr(database, "global_keys"))
            return {str(key) for key in keys}
        except Exception:
            return None

    def database_list_snapshots(
        self,
        session_id: str,
        *,
        offset: int = 0,
        limit: int = 100,
    ) -> dict[str, Any]:
        self._validate_offset_limit(offset, limit)
        database = self._get_database(session_id)
        snapshots = list(self._safe_iter(self._safe_attr(database, "snapshots")))
        items = [
            self._snapshot_to_record(snapshot) for snapshot in snapshots[offset : offset + limit]
        ]
        return {
            "session_id": session_id,
            "offset": offset,
            "limit": limit,
            "total": len(snapshots),
            "items": items,
        }

    def database_read_global(self, session_id: str, key: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        database = self._get_database(session_id)
        global_keys = self._database_global_keys(database)
        if global_keys is not None and key not in global_keys:
            raise BinjaBackendError(f"database global key not found: {key}")
        try:
            value = database.read_global(key)
        except AssertionError as exc:
            raise BinjaBackendError(f"database global key not found: {key}") from exc
        except Exception as exc:
            message = str(exc).strip() or type(exc).__name__
            raise BinjaBackendError(f"failed to read database global key: {message}") from exc
        return {"session_id": session_id, "key": key, "value": value}

    def database_write_global(self, session_id: str, key: str, value: str) -> dict[str, Any]:
        if not key:
            raise BinjaBackendError("key is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before writing database globals",
        )
        database = self._get_database(session_id)
        try:
            database.write_global(key, value)
            written = database.read_global(key)
        except Exception as exc:
            raise BinjaBackendError(f"failed to write database global key: {exc}") from exc
        return {"session_id": session_id, "key": key, "value": written}

    def plugin_list_valid(
        self,
        session_id: str,
        *,
        address: int | str | None = None,
        length: int = 0,
    ) -> dict[str, Any]:
        view = self._get_view(session_id)
        _ = (address, length, view)
        try:
            commands = list(self._bn.PluginCommand)
        except Exception as exc:
            raise BinjaBackendError(f"failed to enumerate plugin commands: {exc}") from exc

        items = []
        for command in commands:
            items.append(
                {
                    "name": self._safe_attr(command, "name"),
                    "description": self._safe_attr(command, "description"),
                    "type": self._enum_name_or_value(self._safe_attr(command, "type")),
                }
            )
        return {
            "session_id": session_id,
            "count": len(items),
            "items": items,
            "context_filtered": False,
        }

    def plugin_execute(
        self,
        session_id: str,
        name: str,
        *,
        address: int | str | None = None,
        length: int = 0,
        perform: bool = False,
    ) -> dict[str, Any]:
        if not name:
            raise BinjaBackendError("name is required")
        self._require_writable_session(
            session_id,
            "session is read-only; switch to write mode before executing plugin commands",
        )
        try:
            commands = list(self._bn.PluginCommand)
        except Exception as exc:
            raise BinjaBackendError(f"failed to enumerate plugin commands: {exc}") from exc

        command = None
        for candidate in commands:
            if self._safe_attr(candidate, "name") == name:
                command = candidate
                break
        if command is None:
            raise BinjaBackendError(f"plugin command not found: {name}")

        if not perform:
            return {
                "session_id": session_id,
                "name": name,
                "executed": False,
                "dry_run": True,
            }

        view = self._get_view(session_id)
        try:
            context = self._plugin_command_context(view, command, address, length)
            is_valid = getattr(command, "is_valid", None)
            if callable(is_valid) and not is_valid(context):
                raise BinjaBackendError(f"invalid context for plugin command: {name}")
            result = command.execute(context)
            if result is False:
                raise BinjaBackendError(f"plugin command reported failure: {name}")
        except Exception as exc:
            raise BinjaBackendError(f"failed to execute plugin command '{name}': {exc}") from exc

        return {
            "session_id": session_id,
            "name": name,
            "executed": True,
            "dry_run": False,
        }

    def _plugin_command_context(
        self, view: Any, command: Any, address: int | str | None, length: int
    ) -> Any:
        """Build native function/IL contexts from the public address selection."""
        if length < 0:
            raise BinjaBackendError("length must be non-negative")
        context = self._bn.PluginCommandContext(view)
        if address is not None:
            context.address = self._coerce_address(address, "address")
        context.length = length
        command_type = self._enum_name_or_value(self._safe_attr(command, "type"))
        if command_type == "ProjectPluginCommand":
            project = context.project
            if project is not None and not hasattr(project, "handle"):
                # Binary Ninja 6.0 Project stores _handle, while its own plugin
                # dispatcher accesses handle. Alias only this genuine native
                # object; do not mutate the native class or fabricate context.
                project.handle = project._handle
        if not isinstance(command_type, str) or address is None:
            return context
        if command_type == "FunctionPluginCommand":
            context.function = self._find_function_containing(view, context.address)
        for prefix, level in (
            ("LowLevelIL", "llil"),
            ("MediumLevelIL", "mlil"),
            ("HighLevelIL", "hlil"),
        ):
            if command_type not in {
                prefix + "FunctionPluginCommand",
                prefix + "InstructionPluginCommand",
            }:
                continue
            function = self._find_function_containing(view, context.address)
            if function is None:
                break
            il = self._get_il_function(function, level, ssa=False)
            context.function = il
            if command_type.endswith("InstructionPluginCommand"):
                context.instruction = next(
                    (
                        instruction
                        for instruction in il.instructions
                        if instruction.address == context.address
                    ),
                    None,
                )
            break
        return context

    def plugin_repo_status(self) -> dict[str, Any]:
        manager = self._bn.RepositoryManager()
        repo_errors: list[str] = []

        repositories = []
        try:
            repositories = list(self._safe_iter(self._safe_attr(manager, "repositories")))
        except Exception as exc:
            repo_errors.append(str(exc))

        repo_items = []
        for repository in repositories:
            plugin_items = []
            try:
                plugins = list(self._safe_iter(self._safe_attr(repository, "plugins")))
            except Exception as exc:
                repo_errors.append(f"{self._safe_attr(repository, 'path')}: {exc}")
                plugins = []

            for plugin in plugins:
                plugin_items.append(
                    {
                        "path": self._safe_attr(plugin, "path"),
                        "name": self._safe_attr(plugin, "name"),
                        "installed": bool(self._safe_attr(plugin, "installed")),
                        "enabled": bool(self._safe_attr(plugin, "enabled")),
                        "disable_pending": bool(self._safe_attr(plugin, "disable_pending")),
                        "delete_pending": bool(self._safe_attr(plugin, "delete_pending")),
                    }
                )

            repo_items.append(
                {
                    "path": self._safe_attr(repository, "path"),
                    "full_path": self._safe_attr(repository, "full_path"),
                    "url": self._safe_attr(repository, "url"),
                    "plugins": plugin_items,
                    "plugin_count": len(plugin_items),
                }
            )

        return {
            "repository_count": len(repo_items),
            "repositories": repo_items,
            "errors": repo_errors,
        }

    def plugin_repo_check_updates(self, *, perform: bool = False) -> dict[str, Any]:
        if not perform:
            return {
                "checked": False,
                "updates_available": None,
                "dry_run": True,
                "note": "Set perform=true to call RepositoryManager.check_for_updates",
            }

        manager = self._bn.RepositoryManager()
        try:
            updated = bool(manager.check_for_updates())
        except Exception as exc:
            raise BinjaBackendError(f"failed to check plugin repository updates: {exc}") from exc
        return {"checked": True, "updates_available": updated, "dry_run": False}

    def plugin_repo_plugin_action(  # noqa: PLR0912
        self,
        repository_path: str,
        plugin_path: str,
        action: str,
    ) -> dict[str, Any]:
        if not repository_path:
            raise BinjaBackendError("repository_path is required")
        if not plugin_path:
            raise BinjaBackendError("plugin_path is required")
        if not action:
            raise BinjaBackendError("action is required")

        manager = self._bn.RepositoryManager()
        repositories = list(self._safe_iter(self._safe_attr(manager, "repositories")))
        repository = None
        for candidate in repositories:
            path = self._safe_attr(candidate, "path")
            full_path = self._safe_attr(candidate, "full_path")
            if repository_path in {path, full_path}:
                repository = candidate
                break
        if repository is None:
            raise BinjaBackendError(f"repository not found: {repository_path}")

        plugins = list(self._safe_iter(self._safe_attr(repository, "plugins")))
        plugin = None
        for candidate in plugins:
            if plugin_path in {
                self._safe_attr(candidate, "path"),
                self._safe_attr(candidate, "name"),
            }:
                plugin = candidate
                break
        if plugin is None:
            raise BinjaBackendError(f"plugin not found in repository: {plugin_path}")

        normalized = action.lower()
        try:
            if normalized == "install":
                changed = bool(plugin.install())
            elif normalized == "uninstall":
                changed = bool(plugin.uninstall())
            elif normalized == "enable":
                changed = bool(plugin.enable())
            elif normalized == "disable":
                disable_method = getattr(plugin, "disable", None)
                if callable(disable_method):
                    changed = bool(disable_method())
                else:
                    was_enabled = bool(plugin.enabled)
                    plugin.enabled = False
                    if plugin.enabled:
                        raise BinjaBackendError(
                            "native plugin disable did not change enabled state"
                        )
                    changed = was_enabled
            else:
                raise BinjaBackendError(
                    "action must be one of: install, uninstall, enable, disable"
                )
        except BinjaBackendError:
            raise
        except Exception as exc:
            raise BinjaBackendError(
                f"failed to run plugin repository action '{normalized}': {exc}"
            ) from exc

        return {
            "repository_path": self._safe_attr(repository, "path"),
            "plugin_path": self._safe_attr(plugin, "path"),
            "action": normalized,
            "changed": changed,
            "installed": bool(self._safe_attr(plugin, "installed")),
            "enabled": bool(self._safe_attr(plugin, "enabled")),
            "disable_pending": bool(self._safe_attr(plugin, "disable_pending")),
            "delete_pending": bool(self._safe_attr(plugin, "delete_pending")),
        }

    def base_address_detect(
        self,
        session_id: str,
        *,
        arch_name: str | None = None,
        algorithm: str = "instruction",
        analysis: str = "full",
        min_strlen: int = 10,
        alignment: int = 1024,
        low_boundary: int = 0,
        high_boundary: int = 0xFFFFFFFFFFFFFFFF,
        max_pointers: int = 128,
    ) -> dict[str, Any]:
        if algorithm not in {"instruction", "sampling"}:
            raise BinjaBackendError("algorithm must be instruction or sampling")
        if algorithm == "sampling" and (
            analysis != "full" or alignment != 1024 or max_pointers != 128
        ):
            raise BinjaBackendError(
                "sampling does not support analysis, alignment, or max_pointers overrides; "
                "omit these instruction-only options"
            )
        view = self._get_view(session_id)
        detector = self._bn.BaseAddressDetection(view)
        self._base_detectors[session_id] = detector

        arch = arch_name if arch_name is None else self._resolve_arch(session_id, arch_name)
        try:
            if algorithm == "sampling":
                sample = getattr(detector, "detect_base_address_with_sampling", None)
                if not callable(sample):
                    raise BinjaBackendError(
                        "sampling base detection is unavailable in this Binary Ninja version"
                    )
                detected = bool(
                    sample(
                        arch=arch,
                        min_strlen=min_strlen,
                        low_boundary=low_boundary,
                        high_boundary=high_boundary,
                    )
                )
            else:
                detected = bool(
                    detector.detect_base_address(
                        arch=arch,
                        analysis=analysis,
                        min_strlen=min_strlen,
                        alignment=alignment,
                        low_boundary=low_boundary,
                        high_boundary=high_boundary,
                        max_pointers=max_pointers,
                    )
                )
        except Exception as exc:
            raise BinjaBackendError(f"failed to detect base address: {exc}") from exc

        scores = []
        for item in self._safe_iter(self._safe_attr(detector, "scores")):
            if isinstance(item, tuple) and len(item) >= 2:
                scores.append({"base_address": self._hex_or_none(item[0]), "score": item[1]})
            else:
                scores.append({"raw": self._to_jsonable(item)})

        return {
            "session_id": session_id,
            "detected": detected,
            "algorithm": algorithm,
            "confidence": self._safe_attr(detector, "confidence"),
            "preferred_base_address": self._hex_or_none(
                self._safe_attr(detector, "preferred_base_address")
            ),
            "aborted": bool(self._safe_attr(detector, "aborted")),
            "scores": scores,
            "score_count": len(scores),
        }

    def base_address_reasons(self, session_id: str, base_address: int | str) -> dict[str, Any]:
        detector = self._base_detectors.get(session_id)
        if detector is None:
            raise BinjaBackendError("no base address detection context for this session")
        base_address_int = self._coerce_address(base_address, "base_address")

        try:
            reasons = list(detector.get_reasons(base_address_int))
        except Exception as exc:
            raise BinjaBackendError(f"failed to get base address reasons: {exc}") from exc

        items = []
        for reason in reasons:
            items.append(
                {
                    "pointer": self._hex_or_none(self._safe_attr(reason, "pointer")),
                    "offset": self._hex_or_none(self._safe_attr(reason, "offset")),
                    "type": self._enum_name_or_value(self._safe_attr(reason, "type")),
                }
            )

        return {
            "session_id": session_id,
            "base_address": hex(base_address_int),
            "count": len(items),
            "items": items,
        }

    def base_address_abort(self, session_id: str) -> dict[str, Any]:
        detector = self._base_detectors.get(session_id)
        if detector is None:
            raise BinjaBackendError("no base address detection context for this session")
        try:
            detector.abort()
        except Exception as exc:
            raise BinjaBackendError(f"failed to abort base address detection: {exc}") from exc
        return {
            "session_id": session_id,
            "aborted": bool(self._safe_attr(detector, "aborted")),
        }

    def core_info(self) -> dict[str, Any]:
        version = self._safe_call(self._bn, "core_version")
        if version is None:
            version = getattr(self._bn, "__version__", "unknown")

        install_directory = self._safe_call(self._bn, "get_install_directory")
        return {
            "version": version,
            "install_directory": install_directory,
            "deterministic_env": self._determinism_env_snapshot(),
        }

    def shutdown(self) -> None:
        self._shutdown()
        self._workflow_clones.clear()

    def _resolve_call_target(self, target: str, session_id: str | None) -> tuple[Any, str]:
        if target.startswith("bn."):
            return self._bn, target[3:]
        if target.startswith("bv."):
            if session_id is None:
                raise BinjaBackendError("session_id is required when target starts with 'bv.'")
            return self._get_view(session_id), target[3:]

        raise BinjaBackendError("target must start with 'bn.' or 'bv.'")

    def _resolve_attr_path(self, root: Any, attr_path: str) -> Any:
        if not attr_path:
            return root

        obj = root
        for part in attr_path.split("."):
            if not part:
                raise BinjaBackendError("invalid target path")
            if not hasattr(obj, part):
                raise BinjaBackendError(f"attribute not found: {part}")
            obj = getattr(obj, part)
        return obj

    def _get_view(self, session_id: str) -> Any:
        return self._get_record(session_id).view

    def _register_type_library(self, library: Any) -> str:
        for type_library_id, candidate in self._type_libraries.items():
            if candidate is library:
                return type_library_id

        type_library_id = uuid4().hex
        self._type_libraries[type_library_id] = library
        return type_library_id

    def _get_type_library(self, type_library_id: str) -> Any:
        library = self._type_libraries.get(type_library_id)
        if library is None:
            raise BinjaBackendError(f"unknown type_library_id: {type_library_id}")
        return library

    def _type_library_to_record(self, type_library_id: str, library: Any) -> dict[str, Any]:
        named_types = self._safe_attr(library, "named_types") or {}
        named_objects = self._safe_attr(library, "named_objects") or {}
        return {
            "type_library_id": type_library_id,
            "name": self._safe_attr(library, "name"),
            "guid": self._safe_attr(library, "guid"),
            "arch": self._safe_attr_chain(library, "arch.name"),
            "platform_names": self._to_jsonable(self._safe_attr(library, "platform_names")),
            "named_type_count": len(named_types),
            "named_object_count": len(named_objects),
        }

    def _register_type_archive(self, archive: Any) -> str:
        archive_id = self._safe_attr(archive, "id")
        if isinstance(archive_id, str) and archive_id:
            self._type_archives[archive_id] = archive
            return archive_id

        generated = uuid4().hex
        self._type_archives[generated] = archive
        return generated

    def _get_type_archive(self, type_archive_id: str) -> Any:
        archive = self._type_archives.get(type_archive_id)
        if archive is None:
            raise BinjaBackendError(f"unknown type_archive_id: {type_archive_id}")
        return archive

    def _type_archive_to_record(self, archive: Any) -> dict[str, Any]:
        return {
            "type_archive_id": self._safe_attr(archive, "id"),
            "path": self._safe_attr(archive, "path"),
            "platform": self._safe_attr_chain(archive, "platform.name"),
            "type_count": self._iter_count(self._safe_attr(archive, "type_names")),
        }

    def _resolve_workflow(self, session_id: str, workflow_name: str | None) -> Any:
        view = self._get_view(session_id)
        if workflow_name is None:
            workflow = self._safe_attr(view, "workflow")
            if workflow is None:
                raise BinjaBackendError("view has no workflow")
            return workflow

        with self._lock:
            cloned = self._workflow_clones.get((session_id, workflow_name))
        if cloned is not None:
            return cloned
        current = self._safe_attr(view, "workflow")
        if self._safe_attr(current, "name") == workflow_name:
            return current

        try:
            return self._bn.Workflow(workflow_name)
        except Exception as exc:
            raise BinjaBackendError(f"unable to resolve workflow '{workflow_name}': {exc}") from exc

    def _resolve_arch(self, session_id: str, arch_name: str | None) -> Any:
        if arch_name is None:
            arch = self._safe_attr(self._get_view(session_id), "arch")
            if arch is None:
                raise BinjaBackendError("session has no architecture")
            return arch

        try:
            return self._bn.Architecture[arch_name]
        except Exception as exc:
            raise BinjaBackendError(f"unknown architecture: {arch_name}") from exc

    def _resolve_transform_mode(self, mode: str) -> Any:
        normalized = mode.lower()
        mode_enum = self._bn.TransformSessionMode
        if normalized in {"disabled", "off"}:
            return mode_enum.TransformSessionModeDisabled
        if normalized in {"interactive", "manual"}:
            return mode_enum.TransformSessionModeInteractive
        if normalized in {"full", "default"}:
            return mode_enum.TransformSessionModeFull
        raise BinjaBackendError("mode must be one of: disabled, interactive, full")

    def _transform_context_to_record(self, context: Any) -> dict[str, Any] | None:
        if context is None:
            return None
        return {
            "filename": self._safe_attr(context, "filename"),
            "is_root": bool(self._safe_attr(context, "is_root")),
            "is_leaf": bool(self._safe_attr(context, "is_leaf")),
            "child_count": self._safe_attr(context, "child_count"),
            "transform_name": self._safe_attr(context, "transform_name"),
            "available_files": self._to_jsonable(self._safe_attr(context, "available_files")),
            "requested_files": self._to_jsonable(self._safe_attr(context, "requested_files")),
            "available_transforms": self._to_jsonable(
                self._safe_attr(context, "available_transforms")
            ),
        }

    def _register_project(self, project: Any) -> str:
        for project_id, candidate in self._projects.items():
            if candidate is project:
                return project_id
        project_id = uuid4().hex
        self._projects[project_id] = project
        return project_id

    def _get_project(self, project_id: str) -> Any:
        project = self._projects.get(project_id)
        if project is None:
            raise BinjaBackendError(f"unknown project_id: {project_id}")
        return project

    def _project_to_record(self, project_id: str, project: Any) -> dict[str, Any]:
        return {
            "project_id": project_id,
            "id": self._safe_attr(project, "id"),
            "name": self._safe_attr(project, "name"),
            "path": self._safe_attr(project, "path"),
            "description": self._safe_attr(project, "description"),
            "is_open": bool(self._safe_attr(project, "is_open")),
        }

    def _project_folder_to_record(self, folder: Any) -> dict[str, Any]:
        parent = self._safe_attr(folder, "parent")
        return {
            "id": self._safe_attr(folder, "id"),
            "name": self._safe_attr(folder, "name"),
            "description": self._safe_attr(folder, "description"),
            "parent_id": self._safe_attr(parent, "id"),
        }

    def _project_file_to_record(self, file_obj: Any) -> dict[str, Any]:
        folder = self._safe_attr(file_obj, "folder")
        path_on_disk = self._safe_attr(file_obj, "path_on_disk")
        if path_on_disk is None and hasattr(file_obj, "get_path_on_disk"):
            try:
                path_on_disk = file_obj.get_path_on_disk()
            except Exception:
                path_on_disk = None

        return {
            "id": self._safe_attr(file_obj, "id"),
            "name": self._safe_attr(file_obj, "name"),
            "description": self._safe_attr(file_obj, "description"),
            "folder_id": self._safe_attr(folder, "id"),
            "path_on_disk": path_on_disk,
        }

    def _project_find_folder(self, project: Any, folder_id: str | None) -> Any:
        if folder_id is None:
            return None
        for folder in self._safe_iter(self._safe_attr(project, "folders")):
            if self._safe_attr(folder, "id") == folder_id:
                return folder
        raise BinjaBackendError(f"project folder not found: {folder_id}")

    def _get_database(self, session_id: str) -> Any:
        view = self._get_view(session_id)
        database = self._safe_attr_chain(view, "file.database")
        if database is None:
            raise BinjaBackendError(
                "database is not available for this session; open a .bndb-backed session first"
            )
        return database

    def _snapshot_to_record(self, snapshot: Any) -> dict[str, Any] | None:
        if snapshot is None:
            return None
        return {
            "id": self._safe_attr(snapshot, "id"),
            "name": self._safe_attr(snapshot, "name"),
            "has_contents": bool(self._safe_attr(snapshot, "has_contents")),
            "is_auto_save": bool(self._safe_attr(snapshot, "is_auto_save")),
            "has_undo": bool(self._safe_attr(snapshot, "has_undo")),
        }

    def _build_segment_flags(
        self,
        *,
        readable: bool,
        writable: bool,
        executable: bool,
        contains_data: bool,
        contains_code: bool,
    ) -> Any:
        flags = 0
        if readable:
            flags |= int(self._bn.SegmentFlag.SegmentReadable)
        if writable:
            flags |= int(self._bn.SegmentFlag.SegmentWritable)
        if executable:
            flags |= int(self._bn.SegmentFlag.SegmentExecutable)
        if contains_data:
            flags |= int(self._bn.SegmentFlag.SegmentContainsData)
        if contains_code:
            flags |= int(self._bn.SegmentFlag.SegmentContainsCode)
        return flags

    def _segment_to_record(self, segment: Any) -> dict[str, Any] | None:
        if segment is None:
            return None
        return {
            "start": self._hex_or_none(self._safe_attr(segment, "start")),
            "end": self._hex_or_none(self._safe_attr(segment, "end")),
            "readable": bool(self._safe_attr(segment, "readable")),
            "writable": bool(self._safe_attr(segment, "writable")),
            "executable": bool(self._safe_attr(segment, "executable")),
            "data_offset": self._safe_attr(segment, "data_offset"),
            "data_length": self._safe_attr(segment, "data_length"),
            "auto_defined": bool(self._safe_attr(segment, "auto_defined")),
        }

    def _section_to_record(self, name: str, section: Any) -> dict[str, Any] | None:
        if section is None:
            return None
        return {
            "name": name,
            "start": self._hex_or_none(self._safe_attr(section, "start")),
            "end": self._hex_or_none(self._safe_attr(section, "end")),
            "length": self._safe_attr(section, "length"),
            "type": self._safe_attr(section, "type"),
            "semantics": self._enum_name_or_value(self._safe_attr(section, "semantics")),
            "align": self._safe_attr(section, "align"),
            "entry_size": self._safe_attr(section, "entry_size"),
            "auto_defined": bool(self._safe_attr(section, "auto_defined")),
        }

    def _external_library_to_record(self, library: Any) -> dict[str, Any] | None:
        if library is None:
            return None
        return {
            "name": self._safe_attr(library, "name"),
            "backing_file": self._safe_attr_chain(library, "backing_file.name"),
        }

    def _external_location_to_record(self, location: Any) -> dict[str, Any] | None:
        if location is None:
            return None
        return {
            "source_symbol": self._safe_attr_chain(location, "source_symbol.full_name"),
            "target_symbol": self._safe_attr(location, "target_symbol"),
            "target_address": self._hex_or_none(self._safe_attr(location, "target_address")),
            "external_library": self._safe_attr_chain(location, "library.name")
            or self._safe_attr_chain(location, "external_library.name"),
            "auto_defined": bool(self._safe_attr(location, "auto_defined")),
        }

    def _require_writable_session(self, session_id: str, message: str) -> None:
        record = self._get_record(session_id)
        if record.read_only:
            raise BinjaBackendError(message)

    def _transition_sessions_to_writable(self, session_ids: list[str]) -> list[str]:
        transitioned: list[str] = []
        seen: set[str] = set()
        for session_id in session_ids:
            if session_id in seen:
                continue
            seen.add(session_id)
            record = self._get_record(session_id)
            if record.read_only:
                record.read_only = False
                transitioned.append(session_id)
        return transitioned

    def _mark_session_byte_edits(self, session_id: str) -> None:
        record = self._get_record(session_id)
        record.has_byte_edits = True

    @staticmethod
    def _close_view(view: Any) -> None:
        file_obj = getattr(view, "file", None)
        if file_obj is not None and hasattr(file_obj, "close"):
            file_obj.close()

    @staticmethod
    def _safe_attr(obj: Any, attr: str) -> Any:
        return getattr(obj, attr, None)

    @staticmethod
    def _safe_attr_chain(obj: Any, chain: str) -> Any:
        current = obj
        for part in chain.split("."):
            current = getattr(current, part, None)
            if current is None:
                return None
        return current

    @staticmethod
    def _safe_iter(value: Any) -> list[Any] | Any:
        if value is None:
            return []
        return value

    @staticmethod
    def _iter_count(value: Any) -> int:
        try:
            return len(value)
        except TypeError:
            return len(list(value)) if value is not None else 0

    @staticmethod
    def _name_list(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, dict):
            return sorted(str(key) for key in value)
        result = []
        for item in value:
            if isinstance(item, str):
                result.append(item)
            else:
                result.append(str(getattr(item, "name", item)))
        return sorted(result)

    @staticmethod
    def _hex_or_none(value: Any) -> str | None:
        if isinstance(value, int):
            return hex(value)
        return None

    @staticmethod
    def _enum_name_or_value(value: Any) -> str | int | None:
        if value is None:
            return None

        name = getattr(value, "name", None)
        if isinstance(name, str):
            return name

        if isinstance(value, int):
            return value

        return str(value)

    @staticmethod
    def _safe_call(obj: Any, method_name: str) -> Any:
        method = getattr(obj, method_name, None)
        if callable(method):
            try:
                return method()
            except Exception:
                return None
        return None

    @staticmethod
    def _safe_call_with_arg(obj: Any, method_name: str, arg: Any) -> Any:
        method = getattr(obj, method_name, None)
        if callable(method):
            try:
                return method(arg)
            except Exception:
                return None
        return None

    @staticmethod
    def _coerce_address(value: int | str, label: str) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value, 0)
            except ValueError as exc:
                raise BinjaBackendError(f"{label} must be an integer or integer string") from exc
        raise BinjaBackendError(f"{label} must be an integer or integer string")

    @staticmethod
    def _validate_offset_limit(offset: int, limit: int) -> None:
        if offset < 0:
            raise BinjaBackendError("offset must be >= 0")
        if limit <= 0:
            raise BinjaBackendError("limit must be > 0")

    def _active_task_ids_for_session(self, session_id: str) -> list[str]:
        active: list[str] = []
        with self._lock:
            task_items = list(self._tasks.items())

        for task_id, record in task_items:
            if record.session_id != session_id:
                continue
            status = self._task_status_value(record)
            if status in {"queued", "running", "cancelling"}:
                active.append(task_id)
        return active

    def _function_to_record(self, function: Any) -> dict[str, Any]:
        full_name = self._safe_attr_chain(function, "symbol.full_name")
        if full_name is None:
            full_name = self._safe_attr(function, "name")

        return {
            "start": self._hex_or_none(self._safe_attr(function, "start")),
            "name": full_name,
            "arch": self._safe_attr_chain(function, "arch.name"),
        }

    def _basic_block_to_record(self, block: Any) -> dict[str, Any]:
        return {
            "start": self._hex_or_none(self._safe_attr(block, "start")),
            "end": self._hex_or_none(self._safe_attr(block, "end")),
            "index": self._safe_attr(block, "index"),
            "incoming_edges": self._iter_count(self._safe_attr(block, "incoming_edges")),
            "outgoing_edges": self._iter_count(self._safe_attr(block, "outgoing_edges")),
        }

    def _linear_disassembly_line_to_record(self, line: Any) -> dict[str, Any]:
        function = self._safe_attr(line, "function")
        return {
            "text": str(self._safe_attr(line, "contents") or ""),
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "line_type": self._enum_name_or_value(self._safe_attr(line, "type")),
        }

    def _disasm_instruction_to_record(self, instruction: Any) -> dict[str, Any]:
        if isinstance(instruction, tuple) and len(instruction) >= 2:
            tokens = instruction[0]
            address = instruction[1]
            text = "".join(str(token) for token in tokens)
        else:
            address = None
            text = str(instruction)

        return {
            "address": self._hex_or_none(address),
            "text": text,
        }

    def _get_function_by_start(self, session_id: str, function_start: int | str) -> Any:
        start = self._coerce_address(function_start, "function_start")
        view = self._get_view(session_id)

        function = view.get_function_at(start)
        if function is not None:
            return function

        for candidate in self._safe_iter(self._safe_attr(view, "functions")):
            if int(self._safe_attr(candidate, "start") or 0) == start:
                return candidate

        raise BinjaBackendError(f"function not found at start {hex(start)}")

    def _find_function_containing(self, view: Any, address: int) -> Any | None:
        get_functions_containing = self._safe_attr(view, "get_functions_containing")
        if callable(get_functions_containing):
            containing = list(self._safe_iter(get_functions_containing(address)))
            if containing:
                containing.sort(key=lambda function: int(self._safe_attr(function, "start") or 0))
                return containing[0]

        function = self._safe_call_with_arg(view, "get_function_at", address)
        if function is not None:
            return function

        functions_at = self._safe_call_with_arg(view, "get_functions_at", address)
        if functions_at is not None:
            candidates = list(self._safe_iter(functions_at))
            if candidates:
                candidates.sort(key=lambda candidate: int(self._safe_attr(candidate, "start") or 0))
                return candidates[0]

        for candidate in self._safe_iter(self._safe_attr(view, "functions")):
            if self._function_contains_address(candidate, address):
                return candidate
        return None

    def _function_contains_address(self, function: Any, address: int) -> bool:
        start = self._safe_attr(function, "start")
        if isinstance(start, int) and address == start:
            return True

        highest_address = self._safe_attr(function, "highest_address")
        if (
            isinstance(start, int)
            and isinstance(highest_address, int)
            and highest_address > start
            and start <= address < highest_address
        ):
            return True

        for block in self._safe_iter(self._safe_attr(function, "basic_blocks")):
            block_start = self._safe_attr(block, "start")
            block_end = self._safe_attr(block, "end")
            if (
                isinstance(block_start, int)
                and isinstance(block_end, int)
                and block_start <= address < block_end
            ):
                return True

        return False

    def _symbol_to_record(self, symbol: Any) -> dict[str, Any]:
        address = int(self._safe_attr(symbol, "address") or 0)
        return {
            "name": self._safe_attr(symbol, "full_name"),
            "short_name": self._safe_attr(symbol, "short_name"),
            "raw_name": self._safe_attr(symbol, "raw_name"),
            "address": self._hex_or_none(address),
            "type": self._enum_name_or_value(self._safe_attr(symbol, "type")),
            "auto": bool(self._safe_attr(symbol, "auto")),
            "address_int": address,
        }

    def _data_var_to_record(self, data_var: Any) -> dict[str, Any]:
        return {
            "address": self._hex_or_none(self._safe_attr(data_var, "address")),
            "name": self._safe_attr(data_var, "name"),
            "type": repr(self._safe_attr(data_var, "type")),
            "auto_discovered": bool(self._safe_attr(data_var, "auto_discovered")),
            "value": self._to_jsonable(self._safe_attr(data_var, "value")),
        }

    def _tag_to_record(self, tag: Any) -> dict[str, Any]:
        tag_type = self._safe_attr(tag, "type")
        return {
            "data": self._safe_attr(tag, "data"),
            "type_name": self._safe_attr(tag_type, "name"),
            "icon": self._safe_attr(tag_type, "icon"),
        }

    def _reference_source_to_record(self, reference: Any) -> dict[str, Any]:
        function = self._safe_attr(reference, "function")
        from_address = int(self._safe_attr(reference, "address") or 0)

        return {
            "from": self._hex_or_none(from_address),
            "from_int": from_address,
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "function_name": self._safe_attr(function, "name"),
            "arch": self._safe_attr_chain(reference, "arch.name"),
        }

    def _variable_reference_source_to_record(self, reference: Any) -> dict[str, Any]:
        variable = self._safe_attr(reference, "var")
        source = self._safe_attr(reference, "src") or reference
        function = self._safe_attr(source, "func")
        reference_type = self._safe_attr(source, "type")
        if reference_type is None:
            reference_type = self._safe_attr(source, "il_type")
        return {
            "address": self._hex_or_none(self._safe_attr(source, "address")),
            "arch": self._safe_attr_chain(source, "arch.name"),
            "function_start": self._hex_or_none(self._safe_attr(function, "start")),
            "type": self._enum_name_or_value(reference_type),
            "variable": self._variable_to_record(variable) if variable is not None else None,
        }

    def _register_value_to_record(self, value: Any) -> dict[str, Any]:
        return {
            "rendered": str(value),
            "type": self._enum_name_or_value(self._safe_attr(value, "type")),
            "value": self._to_jsonable(self._safe_attr(value, "value")),
        }

    def _variable_to_record(self, variable: Any) -> dict[str, Any]:
        variable_type = self._safe_attr(variable, "type")
        return {
            "name": self._safe_attr(variable, "name"),
            "source_type": self._enum_name_or_value(self._safe_attr(variable, "source_type")),
            "storage": self._safe_attr(variable, "storage"),
            "index": self._safe_attr(variable, "index"),
            "type": repr(variable_type),
        }

    def _find_variable(self, function: Any, name: str) -> Any | None:
        for variable in self._safe_iter(self._safe_attr(function, "vars")):
            if self._safe_attr(variable, "name") == name:
                return variable
        return None

    def _get_il_function(self, function: Any, level: str, ssa: bool) -> Any:
        normalized_level = level.lower()

        if normalized_level == "llil":
            il = function.llil
        elif normalized_level == "mlil":
            il = function.mlil
        elif normalized_level == "hlil":
            il = function.hlil
        else:
            raise BinjaBackendError("level must be one of: llil, mlil, hlil")

        if il is None:
            raise BinjaBackendError(f"{normalized_level} is not available for this function")
        if ssa:
            ssa_form = getattr(il, "ssa_form", None)
            if ssa_form is None:
                raise BinjaBackendError(f"SSA form is not available for level '{normalized_level}'")
            il = ssa_form

        return il

    def _il_instruction_to_record(self, instruction: Any) -> dict[str, Any]:
        if instruction is None:
            return {
                "index": 0,
                "address": None,
                "operation": None,
                "text": "",
                "tokens": [],
                "operands": [],
                "prefix_operands": [],
            }
        operation = self._safe_attr(instruction, "operation")
        tokens = []
        for token in self._safe_iter(self._safe_attr(instruction, "tokens")):
            tokens.append(
                {
                    "text": self._safe_attr(token, "text") or str(token),
                    "type": self._enum_name_or_value(self._safe_attr(token, "type")),
                    "value": self._to_jsonable(self._safe_attr(token, "value")),
                    "size": self._safe_attr(token, "size"),
                    "operand": self._safe_attr(token, "operand"),
                }
            )

        operands = self._il_operand_to_record(self._safe_attr(instruction, "operands"))
        prefix_operands = self._il_operand_to_record(
            self._safe_attr(instruction, "prefix_operands")
        )

        return {
            "index": int(self._safe_attr(instruction, "instr_index") or 0),
            "address": self._hex_or_none(self._safe_attr(instruction, "address")),
            "operation": self._safe_attr(operation, "name") or str(operation),
            "text": str(instruction),
            "expr_index": self._safe_attr(instruction, "expr_index"),
            "size": self._safe_attr(instruction, "size"),
            "tokens": tokens,
            "operands": operands,
            "prefix_operands": prefix_operands,
            "possible_values": self._to_jsonable(self._safe_attr(instruction, "possible_values")),
        }

    def _il_operand_to_record(self, operand: Any, *, depth: int = 0) -> Any:
        if operand is None or isinstance(operand, (bool, int, float, str)):
            return operand
        if depth >= 2:
            return repr(operand)

        if isinstance(operand, (list, tuple)):
            return [self._il_operand_to_record(item, depth=depth + 1) for item in operand]

        if hasattr(operand, "operation") and hasattr(operand, "instr_index"):
            operation = self._safe_attr(operand, "operation")
            return {
                "kind": "il_instruction",
                "index": int(self._safe_attr(operand, "instr_index") or 0),
                "address": self._hex_or_none(self._safe_attr(operand, "address")),
                "operation": self._safe_attr(operation, "name") or str(operation),
                "text": str(operand),
            }

        return self._to_jsonable(operand)

    def _make_binary_reader(self, view: Any, address: int, endian: str) -> Any:
        endian_value = self._parse_endian(endian)
        try:
            return self._bn.BinaryReader(view, endian=endian_value, address=address)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create BinaryReader: {exc}") from exc

    def _make_binary_writer(self, view: Any, address: int, endian: str) -> Any:
        endian_value = self._parse_endian(endian)
        try:
            return self._bn.BinaryWriter(view, endian=endian_value, address=address)
        except Exception as exc:
            raise BinjaBackendError(f"failed to create BinaryWriter: {exc}") from exc

    def _parse_endian(self, endian: str) -> Any:
        normalized = endian.lower()
        if normalized in {"little", "le"}:
            return self._bn.Endianness.LittleEndian
        if normalized in {"big", "be"}:
            return self._bn.Endianness.BigEndian
        raise BinjaBackendError("endian must be one of: little, big")

    def _apply_determinism_env(self, enabled: bool) -> None:
        if enabled:
            for key in DETERMINISM_ENV_KEYS:
                os.environ[key] = "1"
            return

        for key in DETERMINISM_ENV_KEYS:
            os.environ.pop(key, None)

    def _determinism_env_snapshot(self) -> dict[str, str | None]:
        return {key: os.environ.get(key) for key in DETERMINISM_ENV_KEYS}

    @staticmethod
    def _bytes_like_to_hex(value: Any) -> str | None:
        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value).hex()

        if isinstance(value, (str, bool, int, float)):
            return None

        to_bytes = getattr(value, "__bytes__", None)
        if not callable(to_bytes):
            return None

        try:
            return bytes(value).hex()
        except Exception:
            return None

    def _search_match_to_jsonable(self, value: Any) -> Any:
        if value is None:
            return None

        maybe_hex = self._bytes_like_to_hex(value)
        if maybe_hex is not None:
            return maybe_hex

        return self._to_jsonable(value)

    def _to_jsonable(self, value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value

        if isinstance(value, bytes):
            return value.hex()

        if isinstance(value, (list, tuple, set)):
            return [self._to_jsonable(item) for item in value]

        if isinstance(value, dict):
            return {str(key): self._to_jsonable(item) for key, item in value.items()}

        # Avoid dataclasses.asdict here because it deep-copies values and can fail on ctypes-backed
        # objects (e.g., BN wrappers that carry pointers).
        if is_dataclass(value) and not isinstance(value, type):
            result: dict[str, Any] = {}
            for data_field in fields(value):
                try:
                    field_value = getattr(value, data_field.name)
                except Exception:
                    field_value = None
                result[data_field.name] = self._to_jsonable(field_value)
            return result

        return repr(value)
