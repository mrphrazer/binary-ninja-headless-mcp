from __future__ import annotations

import json
import uuid
from pathlib import Path

from binary_ninja_headless_mcp.backend import BinjaBackend


def _open_rw(real_backend: BinjaBackend, sample_binary_path: str) -> str:
    summary = real_backend.open_session(
        sample_binary_path,
        update_analysis=False,
        read_only=False,
        deterministic=True,
    )
    return summary["session_id"]


def _find_function_start(functions: dict[str, object], name: str) -> str:
    for item in functions["items"]:  # type: ignore[index]
        if isinstance(item, dict) and item.get("name") == name:
            start = item.get("start")
            if isinstance(start, str):
                return start
    raise AssertionError(f"function not found: {name}")


def test_backend_advanced_types_debug_workflow_il_uidf(  # noqa: PLR0915
    real_backend: BinjaBackend,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_rw(real_backend, sample_binary_path)
    real_backend.analysis_update(session_id, wait=True)

    parsed = real_backend.type_parse_string(session_id, "int mcp_type(int x);")
    assert parsed["parsed_name"] == "mcp_type"

    parsed_decls = real_backend.type_parse_declarations(
        session_id,
        "typedef struct { int x; } mcp_s; int mcp_fn(int a);",
    )
    assert parsed_decls["type_count"] >= 1

    defined = real_backend.type_define_user(
        session_id,
        "int mcp_defined_t;",
        name="mcp_defined_t",
    )
    assert defined["defined"] is True
    renamed = real_backend.type_rename(session_id, "mcp_defined_t", "mcp_defined_t2")
    assert renamed["renamed"] is True
    assert real_backend.type_undefine_user(session_id, "mcp_defined_t2")["undefined"] is True

    library_path = tmp_path / "mcp_types.bntl"
    created_library = real_backend.type_library_create(
        session_id,
        "mcp_lib",
        path=str(library_path),
    )
    type_library_id = created_library["type_library"]["type_library_id"]
    assert created_library["type_library"]["name"] == "mcp_lib"
    assert library_path.exists()

    exported = real_backend.type_export_to_library(
        session_id,
        type_library_id,
        "int mcp_lib_type;",
        name="mcp_lib_type",
    )
    assert exported["exported"] is True

    imported_type = real_backend.type_import_library_type(
        session_id,
        "mcp_lib_type",
        type_library_id=type_library_id,
    )
    assert imported_type["imported"] is True

    imported_obj = real_backend.type_import_library_object(
        session_id,
        "mcp_lib_type",
        type_library_id=type_library_id,
    )
    assert "imported" in imported_obj

    listed_libraries = real_backend.type_library_list(session_id)
    assert listed_libraries["count"] >= 1
    loaded_library = real_backend.type_library_load(session_id, str(library_path), add_to_view=True)
    assert loaded_library["type_library"]["name"] == "mcp_lib"
    looked_up_library = real_backend.type_library_get(session_id, type_library_id)
    assert looked_up_library["type_library"]["type_library_id"] == type_library_id

    archive_path = tmp_path / "mcp_types.bnta"
    created_archive = real_backend.type_archive_create(session_id, str(archive_path), attach=True)
    type_archive_id = created_archive["type_archive"]["type_archive_id"]
    assert archive_path.exists()
    opened_archive = real_backend.type_archive_open(session_id, str(archive_path), attach=True)
    assert opened_archive["type_archive"]["path"] == str(archive_path)
    listed_archives = real_backend.type_archive_list(session_id)
    assert listed_archives["count"] >= 1
    json.dumps(listed_archives)
    assert (
        real_backend.type_archive_get(session_id, type_archive_id)["type_archive"][
            "type_archive_id"
        ]
        == type_archive_id
    )

    pushed = real_backend.type_archive_push(session_id, type_archive_id, ["mcp_lib_type"])
    assert "pushed" in pushed
    pulled = real_backend.type_archive_pull(session_id, type_archive_id, ["mcp_lib_type"])
    assert "pulled" in pulled
    listed_after_push = real_backend.type_archive_list(session_id)
    json.dumps(listed_after_push)
    assert all(
        isinstance(type_name, str)
        for item in listed_after_push["items"]
        for type_name in item["type_names"]
    )
    refs = real_backend.type_archive_references(type_archive_id, "mcp_lib_type")
    assert "outgoing_direct" in refs

    parsers = real_backend.debug_list_parsers(session_id)
    assert parsers["count"] >= 1
    debug_apply = real_backend.debug_parse_and_apply(session_id)
    assert debug_apply["applied"] is True

    workflows = real_backend.workflow_list()
    assert workflows["count"] >= 1
    workflow_desc = real_backend.workflow_describe(session_id)
    assert isinstance(workflow_desc["name"], str)
    workflow_graph = real_backend.workflow_graph(session_id)
    assert workflow_graph["node_count"] >= 1
    machine_status = real_backend.workflow_machine_status(session_id)
    assert "status" in machine_status
    machine_dump = real_backend.workflow_machine_control(session_id, "dump")
    assert "status" in machine_dump

    clone_name = f"mcp_clone_{uuid.uuid4().hex[:8]}"
    cloned = real_backend.workflow_clone(session_id, clone_name)
    assert cloned["workflow"] == clone_name

    activity = ""
    if workflow_desc["subactivities"]:
        activity = workflow_desc["subactivities"][0]
    elif workflow_desc["roots"]:
        activity = workflow_desc["roots"][0]
    if activity:
        inserted_before = real_backend.workflow_insert(
            session_id,
            activity,
            [activity],
            workflow_name=clone_name,
            after=False,
        )
        assert "changed" in inserted_before
        inserted_after = real_backend.workflow_insert(
            session_id,
            activity,
            [activity],
            workflow_name=clone_name,
            after=True,
        )
        assert "changed" in inserted_after
        removed = real_backend.workflow_remove(
            session_id,
            activity,
            workflow_name=clone_name,
        )
        assert "changed" in removed

    functions = real_backend.list_functions(session_id, offset=0, limit=200)
    main_start = _find_function_start(functions, "main")

    capabilities = real_backend.il_rewrite_capabilities(session_id, main_start, level="mlil")
    assert capabilities["supports_replace_expr"] is True
    noop_replace = real_backend.il_rewrite_noop_replace(session_id, main_start, level="mlil")
    assert noop_replace["rewritten"] is True
    translate_identity = real_backend.il_translate_identity(session_id, main_start, level="mlil")
    assert "translated_instruction_count" in translate_identity

    variables = real_backend.function_variables(session_id, main_start)
    assert variables["count"] >= 1
    first_var_name = variables["items"][0]["name"]
    parsed_value = real_backend.uidf_parse_possible_value(
        session_id,
        "0x2a",
        "ConstantValue",
    )
    assert "parsed" in parsed_value
    set_value = real_backend.uidf_set_user_var_value(
        session_id,
        main_start,
        first_var_name,
        main_start,
        "0x2a",
        "ConstantValue",
    )
    assert set_value["set"] is True
    listed_values = real_backend.uidf_list_user_var_values(session_id, main_start)
    assert listed_values["count"] >= 1
    cleared = real_backend.uidf_clear_user_var_value(
        session_id,
        main_start,
        first_var_name,
        main_start,
    )
    assert cleared["cleared"] is True


def test_backend_advanced_loader_external_arch_transform_project_database_plugin_base(  # noqa: PLR0915
    real_backend: BinjaBackend,
    sample_binary_path: str,
    tmp_path: Path,
) -> None:
    session_id = _open_rw(real_backend, sample_binary_path)
    real_backend.analysis_update(session_id, wait=True)

    summary = real_backend.binary_summary(session_id)
    base = int(summary["end"], 16) + 0x2000
    added_segment = real_backend.segment_add_user(session_id, base, 0x1000)
    assert added_segment["segment"]["start"] == hex(base)
    assert real_backend.segment_remove_user(session_id, base)["removed"] is True

    added_section = real_backend.section_add_user(session_id, ".mcpsec", base, 0x100)
    assert added_section["section"]["name"] == ".mcpsec"
    assert real_backend.section_remove_user(session_id, ".mcpsec")["removed"] is True

    load_types = real_backend.loader_load_settings_types(session_id)
    assert load_types["count"] >= 1
    load_type_name = load_types["items"][0]
    load_settings = real_backend.loader_load_settings_get(session_id, load_type_name)
    assert load_settings["key_count"] >= 1
    set_result = real_backend.loader_load_settings_set(
        session_id,
        load_type_name,
        "loader.imageBase",
        "0x400000",
        value_type="string",
    )
    assert "changed" in set_result

    functions = real_backend.list_functions(session_id, offset=0, limit=200)
    main_start = _find_function_start(functions, "main")
    added_library = real_backend.external_library_add(session_id, "mcp_ext_lib")
    assert added_library["external_library"]["name"] == "mcp_ext_lib"
    listed_libraries = real_backend.external_library_list(session_id)
    assert listed_libraries["count"] >= 1
    added_location = real_backend.external_location_add(
        session_id,
        main_start,
        library_name="mcp_ext_lib",
        target_symbol="mcp_target",
    )
    assert added_location["external_location"]["target_symbol"] == "mcp_target"
    got_location = real_backend.external_location_get(session_id, main_start)
    assert got_location["external_location"]["target_symbol"] == "mcp_target"
    assert real_backend.external_location_remove(session_id, main_start)["removed"] is True
    assert real_backend.external_library_remove(session_id, "mcp_ext_lib")["removed"] is True

    arch_info = real_backend.arch_info(session_id)
    assert isinstance(arch_info["arch"], str)
    disassembled = real_backend.arch_disasm_bytes(session_id, "9090", address=0x1000)
    assert disassembled["length"] >= 1
    assembled = real_backend.arch_assemble(session_id, "nop", address=0x1000)
    assert assembled["size"] >= 1

    transform = real_backend.transform_inspect(
        path=sample_binary_path,
        mode="full",
        process=False,
    )
    assert "has_single_path" in transform

    project_dir = tmp_path / "project"
    project_created = real_backend.project_create(str(project_dir), "mcp-proj")
    project_id = project_created["project"]["project_id"]
    project_list = real_backend.project_list(project_id)
    assert project_list["folder_count"] >= 0
    folder = real_backend.project_create_folder(project_id, "docs")["folder"]
    assert isinstance(folder["id"], str)
    file_record = real_backend.project_create_file(
        project_id,
        "note.txt",
        "SGVsbG8=",
        folder_id=folder["id"],
    )["file"]
    assert isinstance(file_record["id"], str)
    stored_metadata = real_backend.project_metadata_store(project_id, "mcp.key", {"v": 1})
    assert stored_metadata["value"]["v"] == 1
    queried_metadata = real_backend.project_metadata_query(project_id, "mcp.key")
    assert queried_metadata["value"]["v"] == 1
    assert real_backend.project_metadata_remove(project_id, "mcp.key")["removed"] is True
    assert real_backend.project_close(project_id)["closed"] is True

    bndb_path = tmp_path / "hello_advanced.bndb"
    created_bndb = real_backend.create_database(session_id, str(bndb_path))
    assert created_bndb["created"] is True
    bndb_session = real_backend.open_session(str(bndb_path), update_analysis=False, read_only=False)
    bndb_session_id = bndb_session["session_id"]

    database_info = real_backend.database_info(bndb_session_id)
    assert database_info["snapshot_count"] >= 1
    snapshots = real_backend.database_list_snapshots(bndb_session_id, offset=0, limit=20)
    assert snapshots["total"] >= 1
    written_global = real_backend.database_write_global(bndb_session_id, "mcp.key", "value")
    assert written_global["value"] == "value"
    read_global = real_backend.database_read_global(bndb_session_id, "mcp.key")
    assert read_global["value"] == "value"

    plugins = real_backend.plugin_list_valid(session_id)
    assert plugins["count"] >= 0
    if plugins["items"]:
        executed = real_backend.plugin_execute(session_id, plugins["items"][0]["name"])
        assert executed["dry_run"] is True

    repo_status = real_backend.plugin_repo_status()
    assert "repositories" in repo_status
    repo_updates = real_backend.plugin_repo_check_updates()
    assert repo_updates["dry_run"] is True

    base_detection = real_backend.base_address_detect(session_id, analysis="basic")
    assert "score_count" in base_detection
    if base_detection["scores"]:
        first_base = base_detection["scores"][0]["base_address"]
        reasons = real_backend.base_address_reasons(session_id, first_base)
        assert reasons["count"] >= 0
    aborted = real_backend.base_address_abort(session_id)
    assert "aborted" in aborted

    rebased = real_backend.loader_rebase(session_id, summary["start"])
    assert "rebased" in rebased
