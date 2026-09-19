"""Native semantic regressions uncovered while adding complete CLI coverage."""

import os
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from binary_ninja_headless_mcp.backend import BinjaBackend, BinjaBackendError
from binary_ninja_headless_mcp.fake_binja import FakeBinaryNinjaModule


@pytest.fixture(scope="module")
def native_session():
    bn = pytest.importorskip("binaryninja")

    backend = BinjaBackend(bn)
    path = Path(os.environ.get("BINJA_NATIVE_TEST_BINARY", "/agent/analysis/ls-3d9ac2ff/inputs/ls"))
    if not path.exists():
        pytest.skip("BINJA_NATIVE_TEST_BINARY must point to a preserved native fixture")
    sid = backend.open_session(str(path), read_only=False)["session_id"]
    try:
        yield bn, backend, sid, backend._get_view(sid)
    finally:
        backend.shutdown()


@pytest.mark.parametrize(
    "kind",
    [
        "default",
        "address",
        "range",
        "function",
        "llil_function",
        "mlil_function",
        "hlil_function",
        "llil_instruction",
        "mlil_instruction",
        "hlil_instruction",
    ],
)
def test_native_plugin_execution_reports_actual_invocation(native_session, kind):
    bn, backend, sid, view = native_session
    function = next(f for f in view.functions if f.mlil and f.hlil and f.llil)
    address = function.start
    if kind.endswith("_instruction"):
        il = backend._get_il_function(function, kind.split("_")[0], False)
        address = next(iter(il.instructions)).address
    name = "cli-regression-" + uuid4().hex
    calls = []
    registration = {
        "default": "register",
        "address": "register_for_address",
        "range": "register_for_range",
        "function": "register_for_function",
        "llil_function": "register_for_low_level_il_function",
        "mlil_function": "register_for_medium_level_il_function",
        "hlil_function": "register_for_high_level_il_function",
        "llil_instruction": "register_for_low_level_il_instruction",
        "mlil_instruction": "register_for_medium_level_il_instruction",
        "hlil_instruction": "register_for_high_level_il_instruction",
    }[kind]

    def invoke(bv, *args):
        calls.append(args)
        bv.store_metadata(name, "executed")

    getattr(bn.PluginCommand, registration)(name, "native CLI regression", invoke)
    dry = backend.plugin_execute(sid, name, address=address, length=4)
    assert dry["dry_run"] and not calls
    result = backend.plugin_execute(sid, name, address=address, length=4, perform=True)
    assert result["executed"] is True
    assert len(calls) == 1 and view.query_metadata(name) == "executed"
    if kind == "address":
        assert calls == [(address,)]
    if kind == "range":
        assert calls == [(address, 4)]


def test_native_plugin_invalid_context_rejected(native_session):
    bn, backend, sid, _ = native_session
    name = "cli-invalid-" + uuid4().hex
    calls = []
    bn.PluginCommand.register_for_range(name, "needs range", lambda *args: calls.append(args))
    with pytest.raises(BinjaBackendError, match="context"):
        backend.plugin_execute(sid, name, perform=True)
    assert not calls


def test_archive_missing_type_is_error_and_references_resolve_names(native_session, tmp_path):
    _, backend, sid, view = native_session
    parsed = view.parse_types_from_string(
        "typedef struct { int x; } cli_B; typedef struct { cli_B b; } cli_A;"
    )
    for name, typ in parsed.types.items():
        view.define_user_type(name, typ)
    record = backend.type_archive_create(sid, str(tmp_path / "types.bnta"))
    aid = record["type_archive"]["type_archive_id"]
    archive = backend._get_type_archive(aid)
    for operation in (backend.type_archive_pull, backend.type_archive_push):
        with pytest.raises(BinjaBackendError, match="type"):
            operation(sid, aid, ["cli_missing"])
    pushed = backend.type_archive_push(sid, aid, ["cli_A"])
    assert pushed["pushed"]
    a_id, b_id = archive.get_type_id("cli_A"), archive.get_type_id("cli_B")
    assert a_id and b_id
    assert b_id in backend.type_archive_references(aid, "cli_A")["outgoing_recursive"]
    assert a_id in backend.type_archive_references(aid, "cli_B")["incoming_recursive"]
    with pytest.raises(BinjaBackendError, match="type"):
        backend.type_archive_references(aid, "cli_missing")
    assert backend.type_archive_pull(sid, aid, ["cli_A"])["pulled"]


@pytest.mark.parametrize("level", ["llil", "mlil"])
def test_native_identity_translation_copies_expressions(native_session, monkeypatch, level):
    _, backend, sid, view = native_session
    function = next(f for f in view.functions if f.mlil and len(list(f.mlil.instructions)) > 2)
    il = backend._get_il_function(function, level, False)
    original_translate = type(il).translate
    translated_functions = []

    def capture(self, callback):
        translated = original_translate(self, callback)
        translated_functions.append(translated)
        return translated

    monkeypatch.setattr(type(il), "translate", capture)
    result = backend.il_translate_identity(sid, function.start, level=level)
    translated = translated_functions[0]

    def semantic(value):
        if hasattr(value, "operation") and hasattr(value, "operands"):
            return (
                value.address,
                value.operation.name,
                value.size,
                tuple(semantic(v) for v in value.operands),
            )
        if isinstance(value, (list, tuple)):
            return tuple(semantic(v) for v in value)
        if hasattr(value, "identifier"):
            return (type(value).__name__, value.identifier)
        return str(value)

    source = [semantic(i) for i in il.instructions]
    copied = [semantic(i) for i in translated.instructions]
    assert source and copied == source
    assert result["translated_instruction_count"] == len(source)


def test_native_workflow_clone_retains_configuration(native_session):
    _, backend, sid, _ = native_session
    name = "cli.workflow." + uuid4().hex
    original = backend.workflow_describe(sid)
    backend.workflow_clone(sid, name)
    cloned = backend.workflow_describe(sid, workflow_name=name)
    assert cloned["subactivities"] == original["subactivities"]
    assert cloned["subactivities"]
    activity = cloned["subactivities"][0]
    removed = backend.workflow_remove(sid, activity, workflow_name=name)
    assert removed["changed"]
    assert activity not in backend.workflow_describe(sid, workflow_name=name)["subactivities"]
    assert activity in backend.workflow_describe(sid)["subactivities"]


def test_repository_disable_supports_native_property_api():
    class Plugin:
        path = "fixture"
        name = "Fixture"
        installed = True
        enabled = True

    plugin = Plugin()
    module = FakeBinaryNinjaModule()
    module.RepositoryManager = lambda: SimpleNamespace(
        repositories=[SimpleNamespace(path="repo", plugins=[plugin])]
    )
    backend = BinjaBackend(module)
    try:
        result = backend.plugin_repo_plugin_action("repo", "fixture", "disable")
        assert result["changed"] and not result["enabled"] and not plugin.enabled
    finally:
        backend.shutdown()


@pytest.mark.parametrize("accepted", [True, False])
def test_workflow_machine_preserves_native_acceptance(accepted):
    backend = BinjaBackend(FakeBinaryNinjaModule())
    try:
        sid = backend.open_session("fixture", read_only=False)["session_id"]
        native_response = {"commandStatus": {"accepted": accepted}, "fixture": 1}
        machine = backend._get_view(sid).workflow.machine
        machine.dump = lambda: native_response
        machine.status = lambda: {"state": "Idle"}
        if accepted:
            response = backend.workflow_machine_control(sid, "dump")
            assert response["command_result"] == native_response
        else:
            with pytest.raises(BinjaBackendError, match="rejected"):
                backend.workflow_machine_control(sid, "dump")
    finally:
        backend.shutdown()


def test_native_workflow_dump_reports_snapshot_provenance(native_session):
    _, backend, sid, _ = native_session
    response = backend.workflow_machine_control(sid, "dump")
    if response["dump_source"] == "native_command":
        assert response["command_result"]["commandStatus"]["accepted"] is True
    else:
        assert response["dump_source"] == "native_state_snapshot"
        assert response["command_result"]["commandStatus"]["accepted"] is False
        snapshot = response["dump_snapshot"]
        for name in ("status", "breakpoints", "overrides"):
            assert snapshot[name]["commandStatus"]["accepted"] is True
        assert snapshot["configuration"]


def test_workflow_clone_ownership_released_on_close_and_shutdown():
    import gc
    import weakref

    class RetainedClone:
        pass

    backend = BinjaBackend(FakeBinaryNinjaModule())
    try:
        first = backend.open_session("first", read_only=False)["session_id"]
        second = backend.open_session("second", read_only=False)["session_id"]
        clone_a, clone_b = RetainedClone(), RetainedClone()
        first_ref, second_ref = weakref.ref(clone_a), weakref.ref(clone_b)
        backend._workflow_clones[(first, "clone-a")] = clone_a
        backend._workflow_clones[(second, "clone-b")] = clone_b
        del clone_a, clone_b
        backend.close_session(first)
        gc.collect()
        assert first_ref() is None
        assert second_ref() is not None
        backend.shutdown()
        gc.collect()
        assert second_ref() is None
        assert not backend._workflow_clones
    finally:
        backend.shutdown()


def test_native_external_location_reports_associated_library(native_session):
    _, backend, sid, view = native_session
    symbol = next(symbol for symbol in view.get_symbols() if view.get_symbol_at(symbol.address))
    name = "cli-external-" + uuid4().hex
    backend.external_library_add(sid, name)
    try:
        result = backend.external_location_add(
            sid, symbol.address, library_name=name, target_symbol="cli_target"
        )
        assert result["external_location"]["external_library"] == name
        readback = backend.external_location_get(sid, symbol.address)
        assert readback["external_location"]["external_library"] == name
    finally:
        backend.external_location_remove(sid, symbol.address)
        backend.external_library_remove(sid, name)


def test_nested_native_variable_reference_source():
    bn = pytest.importorskip("binaryninja")
    from binaryninja.function import ILReferenceSource, VariableReferenceSource

    source = ILReferenceSource(
        func=SimpleNamespace(start=0x1200),
        arch=bn.Architecture["x86_64"],
        address=0x1234,
        il_type=bn.FunctionGraphType.MediumLevelILFunctionGraph,
        expr_id=0,
    )
    reference = VariableReferenceSource(None, source)
    backend = BinjaBackend(bn)
    try:
        result = backend._variable_reference_source_to_record(reference)
        assert result["address"] == "0x1234"
        assert result["function_start"] == "0x1200"
        assert result["arch"] == "x86_64"
        assert result["type"] == "MediumLevelILFunctionGraph"
    finally:
        backend.shutdown()


def test_external_debug_parser_selection_uses_debug_file():
    module = FakeBinaryNinjaModule()
    backend = BinjaBackend(module)
    parsed = SimpleNamespace(types=[1], functions=[2], data_variables=[3])
    try:
        sid = backend.open_session("stripped", update_analysis=False, read_only=False)["session_id"]
        target = backend._get_view(sid)
        debug = module.load("external.debug", update_analysis=False)
        applied = []
        target.apply_debug_info = applied.append
        parser = SimpleNamespace(
            name="fixture-dwarf",
            parse_debug_info=lambda bv, dv: parsed if bv is target and dv is debug else None,
        )
        selected = []

        def parsers_for_view(view):
            selected.append(view)
            return [parser] if view is debug else []

        module.DebugInfoParser = SimpleNamespace(get_parsers_for_view=parsers_for_view)
        module.load = lambda *_args, **_kwargs: debug
        result = backend.debug_parse_and_apply(
            sid, debug_path="external.debug", parser_name="fixture-dwarf"
        )
        assert selected == [debug]
        assert applied == [parsed]
        assert result["applied"] and result["type_count"] == 1
        assert debug.file.closed
    finally:
        backend.shutdown()


@pytest.mark.parametrize("legacy_tuple", [True, False])
def test_imported_library_object_preserves_native_type(legacy_tuple):
    backend = BinjaBackend(FakeBinaryNinjaModule())
    library = SimpleNamespace(name="fixture-library")
    native_type = SimpleNamespace(signature="int cli_object(int)")
    try:
        sid = backend.open_session("fixture", update_analysis=False)["session_id"]
        backend._type_libraries["fixture"] = library
        view = backend._get_view(sid)
        view.import_library_object = lambda _name, lib: (
            (lib, native_type) if legacy_tuple else native_type
        )
        result = backend.type_import_library_object(sid, "cli_object", type_library_id="fixture")
        assert result["imported"]
        assert result["type"] == repr(native_type)
        assert result["library_name"] == library.name
    finally:
        backend.shutdown()


def test_native_sampling_base_detection_has_exact_known_base():
    bn = pytest.importorskip("binaryninja")
    path = Path("/agent/analysis/baseaddr-firmware/inputs/firmware-absolute-x86_64.bin")
    if not path.exists():
        pytest.skip("Preserved base-address fixture is required")
    backend = BinjaBackend(bn)
    try:
        sid = backend.open_session(str(path), update_analysis=False)["session_id"]
        with pytest.raises(BinjaBackendError, match="algorithm"):
            backend.base_address_detect(sid, algorithm="unknown")
        assert sid not in backend._base_detectors
        with pytest.raises(BinjaBackendError, match="instruction-only"):
            backend.base_address_detect(sid, algorithm="sampling", alignment=4096)
        result = backend.base_address_detect(
            sid,
            algorithm="sampling",
            arch_name="x86_64",
            low_boundary=0x3F0000,
            high_boundary=0x410000,
        )
        assert result["algorithm"] == "sampling"
        assert result["detected"] is True
        assert result["preferred_base_address"] == "0x400000"
        assert result["scores"][0] == {"base_address": "0x400000", "score": 64}
        reasons = backend.base_address_reasons(sid, "0x400000")
        assert reasons["count"] == 64
        assert all(
            int(r["pointer"], 16) - int(r["offset"], 16) == 0x400000 for r in reasons["items"]
        )
    finally:
        backend.shutdown()


def test_sampling_requires_native_runtime_capability():
    module = FakeBinaryNinjaModule()
    module.BaseAddressDetection = lambda _view: SimpleNamespace()
    backend = BinjaBackend(module)
    try:
        sid = backend.open_session("fixture", update_analysis=False)["session_id"]
        with pytest.raises(BinjaBackendError, match="unavailable in this Binary Ninja version"):
            backend.base_address_detect(sid, algorithm="sampling")
    finally:
        backend.shutdown()


@pytest.mark.parametrize("matched", [True, False])
def test_load_resolves_only_exact_managed_project_path(matched):
    module = FakeBinaryNinjaModule()
    backend = BinjaBackend(module)
    path = "/project/staged-file"
    candidate = SimpleNamespace(path_on_disk=path if matched else "/other/file")
    backend._projects["fixture"] = SimpleNamespace(
        get_file_by_path_on_disk=lambda _path: candidate, close=lambda: True
    )
    original_load = module.load
    received = []

    def load(source, **kwargs):
        received.append((source, kwargs))
        return original_load("fixture", **kwargs)

    module.load = load
    try:
        sid = backend.open_session(path, update_analysis=False, options={"fixture.option": 42})[
            "session_id"
        ]
        assert received == [
            (
                candidate if matched else path,
                {"update_analysis": False, "options": {"fixture.option": 42}},
            )
        ]
        backend.close_session(sid)
    finally:
        backend.shutdown()


def test_native_project_file_open_provides_plugin_project_context(tmp_path):
    import base64

    bn = pytest.importorskip("binaryninja")
    source = Path(
        os.environ.get("BINJA_NATIVE_TEST_BINARY", "/agent/analysis/ls-3d9ac2ff/inputs/ls")
    )
    if not source.exists():
        pytest.skip("Preserved native fixture required")
    backend = BinjaBackend(bn)
    try:
        pid = backend.project_create(str(tmp_path / "cli.bnproj"), "CLI project")["project"][
            "project_id"
        ]
        created = backend.project_create_file(
            pid, "fixture", base64.b64encode(source.read_bytes()).decode()
        )
        sid = backend.open_session(
            created["file"]["path_on_disk"], update_analysis=False, read_only=False
        )["session_id"]
        view = backend._get_view(sid)
        assert view.project is not None
        assert view.project_file.id == created["file"]["id"]
        name = "cli-project-" + uuid4().hex
        bn.PluginCommand.register_for_project(
            name,
            "native project regression",
            lambda project: project.store_metadata(name, "executed"),
        )
        result = backend.plugin_execute(sid, name, perform=True)
        assert result["executed"] is True
        assert backend.project_metadata_query(pid, name)["value"] == "executed"
        backend.close_session(sid)
        backend.project_close(pid)
    finally:
        backend.shutdown()
