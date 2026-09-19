"""Native, stateful CLI verification with independent persistence/readback checks.

The runner owns transport, evidence, and the writable fixture session. Every
operation here traverses that transport; ``native`` is the public binja.eval
bridge, used for independent observations and fixture preparation only.
"""

from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from uuid import uuid4


def _project(r):
    path = r.output / "stateful-project"
    name = "CLI persistence project"
    created = r.verify(
        "project.create",
        "create",
        {"path": str(path), "name": name},
        lambda p: p["project"]["is_open"] and p["project"]["name"] == name,
        "Native project opens with requested name",
    )
    pid = created["project"]["project_id"]
    folder = r.tool(
        "project.create_folder", project_id=pid, name="parent", description="root folder"
    )["folder"]
    child = r.tool(
        "project.create_folder",
        project_id=pid,
        name="child",
        parent_folder_id=folder["id"],
        description="nested folder",
    )["folder"]
    content = b"CLI native project round-trip\x00\xff\n"
    file_record = r.tool(
        "project.create_file",
        project_id=pid,
        name="evidence.bin",
        folder_id=child["id"],
        data_base64=base64.b64encode(content).decode(),
        description="binary content",
    )["file"]
    metadata = {"purpose": "CLI persistence", "integers": [1, 2, 3], "enabled": True}
    r.verify(
        "project.metadata_store",
        "nested-value",
        {"project_id": pid, "key": "cli.evidence", "value": metadata},
        lambda p: p["value"] == metadata,
        "Nested metadata survives native write/readback",
    )
    r.verify(
        "project.metadata_query",
        "before-close",
        {"project_id": pid, "key": "cli.evidence"},
        lambda p: p["value"] == metadata,
        "Separate metadata query matches exact input",
    )
    r.verify(
        "project.close",
        "before-reopen",
        {"project_id": pid},
        lambda p: p["closed"],
        "Native close succeeds",
    )
    opened = r.verify(
        "project.open",
        "reopen",
        {"path": str(path)},
        lambda p: p["project"]["is_open"] and p["project"]["id"] == created["project"]["id"],
        "Reopened disk project retains native identity",
    )
    pid = opened["project"]["project_id"]
    try:
        listing = r.verify(
            "project.list",
            "persisted-tree",
            {"project_id": pid},
            lambda p: p["folder_count"] == 2 and p["file_count"] == 1,
            "Reopened project retains both folders and one file",
        )
        folders = {x["id"]: x for x in listing["folders"]}
        r.record(
            "project.create_folder",
            "nested-parent-readback",
            folders[child["id"]]["parent_id"] == folder["id"],
            "Persisted child points to requested parent",
            {"folders": listing["folders"]},
        )
        saved = listing["files"][0]
        observed = Path(saved["path_on_disk"]).read_bytes()
        r.record(
            "project.create_file",
            "persisted-bytes",
            observed == content
            and saved["folder_id"] == child["id"]
            and saved["id"] == file_record["id"],
            "Exact binary payload and folder survive project reopen",
            {"file": saved, "bytes_hex": observed.hex()},
        )
        r.verify(
            "project.metadata_query",
            "persisted-value",
            {"project_id": pid, "key": "cli.evidence"},
            lambda p: p["value"] == metadata,
            "Metadata survives closing and reopening project",
        )
        r.tool("project.metadata_remove", project_id=pid, key="cli.evidence")
        missing = r.tool("project.metadata_query", project_id=pid, key="cli.evidence")
        r.record(
            "project.metadata_remove",
            "readback-absent",
            missing["value"] is None,
            "Removed project metadata is absent",
            missing,
        )
    finally:
        r.verify(
            "project.close",
            "cleanup",
            {"project_id": pid},
            lambda p: p["closed"],
            "Reopened project closes",
        )


def _libraries(r):
    sid = r.session_id
    library_name = "cli-library-" + uuid4().hex
    path = r.output / "stateful-types.bntl"
    payload = r.verify(
        "type_library.create",
        "attached",
        {"session_id": sid, "name": library_name, "path": str(path)},
        lambda p: p["type_library"]["name"] == library_name,
        "Created library has requested native name",
    )
    lid = payload["type_library"]["type_library_id"]
    exported = r.tool(
        "type.export_to_library",
        session_id=sid,
        type_library_id=lid,
        name="cli_persisted_type",
        type_source="struct { unsigned int marker; unsigned long payload; }",
    )
    r.verify(
        "type_library.get",
        "export-readback",
        {"session_id": sid, "type_library_id": lid},
        lambda p: p["type_library"]["named_type_count"] == 1,
        "Native exported library contains one type",
    )
    r.verify(
        "type_library.list",
        "attached-readback",
        {"session_id": sid},
        lambda p: any(x["name"] == library_name for x in p["items"]),
        "Attached library appears in view registry",
    )
    r.native(
        f"lib = next(x for x in bv.type_libraries if x.name == {library_name!r})\n"
        "bv.export_object_to_library(lib, 'cli_persisted_object', "
        "'int cli_persisted_object(unsigned int count, unsigned long payload)')"
    )
    persisted = r.native(
        f"lib = next(x for x in bv.type_libraries if x.name == {library_name!r})\n"
        f"lib.finalize()\n_ = lib.write_to_file({str(path)!r})"
    )
    r.record(
        "type_library.create",
        "disk-file",
        path.is_file() and path.stat().st_size > 0,
        "Library serialization produces nonempty native file",
        {"path": str(path), "native_write": persisted},
    )
    loaded = r.verify(
        "type_library.load",
        "disk-reload",
        {"session_id": sid, "path": str(path), "add_to_view": False},
        lambda p: (
            p["type_library"]["name"] == library_name
            and p["type_library"]["named_type_count"] == 1
            and p["type_library"]["named_object_count"] == 1
        ),
        "Loaded file retains the exported type",
    )
    imported = r.tool(
        "type.import_library_type",
        session_id=sid,
        type_library_id=loaded["type_library"]["type_library_id"],
        name="cli_persisted_type",
    )
    actual = r.native(
        f"lib = bn.TypeLibrary.load_from_file({str(path)!r})\n"
        "_ = [m.name for m in lib.named_types[bn.QualifiedName('cli_persisted_type')].members]"
    )
    r.record(
        "type_library.load",
        "type-content-roundtrip",
        imported["imported"] and "marker" in actual and "payload" in actual,
        "Reloaded library imports both original struct members",
        {"import": imported, "native_type": actual},
    )
    r.record(
        "type.export_to_library",
        "persisted-member-readback",
        exported["exported"] and actual == ["marker", "payload"],
        "Exported type retains both original members after native library reload",
        {"export": exported, "persisted_members": actual},
    )
    imported_members = r.native(
        "t = bv.get_type_by_name('cli_persisted_type')\n"
        "if isinstance(t, bn.NamedTypeReferenceType):\n    t = t.target(bv)\n"
        "_ = [m.name for m in t.members]"
    )
    r.record(
        "type.import_library_type",
        "view-member-readback",
        imported["imported"] and imported_members == ["marker", "payload"],
        "Imported type definition in BinaryView retains both original struct members",
        {"import": imported, "view_members": imported_members},
    )
    imported_object = r.tool(
        "type.import_library_object",
        session_id=sid,
        type_library_id=loaded["type_library"]["type_library_id"],
        name="cli_persisted_object",
    )
    signature = r.native(
        f"lib = bn.TypeLibrary.load_from_file({str(path)!r})\n"
        "t = lib.named_objects[bn.QualifiedName('cli_persisted_object')]\n"
        "_ = {'return_width': t.return_value.width, "
        "'parameter_names': [p.name for p in t.parameters], "
        "'parameter_widths': [p.type.width for p in t.parameters], 'signature': repr(t)}"
    )
    r.record(
        "type.import_library_object",
        "persisted-function-signature",
        imported_object["imported"]
        and imported_object["library_name"] == library_name
        and signature["return_width"] == 4
        and signature["parameter_names"] == ["count", "payload"]
        and signature["parameter_widths"] == [4, 8]
        and all(
            part in (imported_object["type"] or "") for part in ["int32_t", "count", "payload"]
        ),
        "Object import returns the persisted function signature and source library",
        {"import": imported_object, "native_signature": signature},
    )


def _archives(r):
    sid = r.session_id
    path = r.output / "stateful-types.bnta"
    r.native(
        "parsed = bv.parse_types_from_string('struct cli_archive_child { int marker; }; "
        "struct cli_archive_parent { struct cli_archive_child child; long count; };')\n"
        "for name, typ in parsed.types.items():\n    bv.define_user_type(name, typ)\n"
        "_ = [str(x) for x in parsed.types]"
    )
    created = r.verify(
        "type_archive.create",
        "attached",
        {"session_id": sid, "path": str(path), "attach": True},
        lambda p: bool(p["type_archive"]["type_archive_id"]),
        "Native archive receives persistent identity",
    )
    aid = created["type_archive"]["type_archive_id"]
    args = {"session_id": sid, "type_archive_id": aid}
    r.tool("type_archive.push", **args, names=["cli_archive_parent"])
    native = r.native(
        f"a = bv.get_type_archive({aid!r})\n_ = {{'parent': a.get_type_id('cli_archive_parent'), "
        "'child': a.get_type_id('cli_archive_child'), "
        "'members': [m.name for m in a.get_type_by_name('cli_archive_parent').members]}"
    )
    r.record(
        "type_archive.push",
        "dependency-readback",
        bool(native["parent"]) and bool(native["child"]) and "count" in native["members"],
        "Pushing parent also preserves dependent child in archive",
        native,
    )
    r.verify(
        "type_archive.get",
        "pushed-types",
        args,
        lambda p: p["type_archive"]["type_count"] == 2,
        "Archive contains parent and dependency",
    )
    r.verify(
        "type_archive.references",
        "outgoing-dependency",
        {"type_archive_id": aid, "name": "cli_archive_parent"},
        lambda p: (
            native["child"] in p["outgoing_direct"] and native["child"] in p["outgoing_recursive"]
        ),
        "Reference query resolves parent name to child native type ID",
    )
    r.verify(
        "type_archive.references",
        "incoming-dependency",
        {"type_archive_id": aid, "name": "cli_archive_child"},
        lambda p: (
            native["parent"] in p["incoming_direct"] and native["parent"] in p["incoming_recursive"]
        ),
        "Reverse reference query finds parent type ID",
    )
    r.verify(
        "type_archive.list",
        "attached-readback",
        {"session_id": sid},
        lambda p: any(x["type_archive_id"] == aid for x in p["items"]),
        "Archive is attached to BinaryView",
    )
    r.native(
        "bv.undefine_user_type('cli_archive_parent')\n"
        "_ = bv.get_type_by_name('cli_archive_parent') is None"
    )
    r.tool("type_archive.pull", **args, names=["cli_archive_parent"])
    recovered = r.native("[m.name for m in bv.get_type_by_name('cli_archive_parent').members]")
    r.record(
        "type_archive.pull",
        "restore-deleted-type",
        "child" in recovered and "count" in recovered,
        "Pull restores removed parent and its member declarations",
        {"recovered_type": recovered},
    )
    r.verify(
        "type_archive.open",
        "disk-reopen",
        {"session_id": sid, "path": str(path), "attach": False},
        lambda p: (
            p["type_archive"]["type_archive_id"] == aid and p["type_archive"]["type_count"] == 2
        ),
        "Opening archive on disk retains identity and both types",
    )


def run_stateful(runner):
    """Run native project, library, archive, and workflow scenarios."""
    _project(runner)
    _libraries(runner)
    _archives(runner)
    _workflows(runner)


def _workflows(r):
    sid = r.session_id
    original = r.verify(
        "workflow.describe",
        "view-default",
        {"session_id": sid},
        lambda p: bool(p["subactivities"]) and bool(json.loads(p["configuration"])),
        "Analyzed native view exposes nonempty workflow topology",
    )
    r.verify(
        "workflow.list",
        "registered",
        {},
        lambda p: original["name"] in p["items"],
        "Current native workflow appears in registry",
    )
    name = "cli.workflow." + uuid4().hex
    r.verify(
        "workflow.clone",
        "unregistered",
        {"session_id": sid, "name": name, "register": False},
        lambda p: p["workflow"] == name and not p["registered"],
        "Clone has requested name and remains editable",
    )
    args = {"session_id": sid, "workflow_name": name}
    cloned = r.verify(
        "workflow.describe",
        "clone-retained",
        args,
        lambda p: p["subactivities"] == original["subactivities"],
        "Unregistered clone retains all native activities after request returns",
    )
    config = json.loads(cloned["configuration"])
    # Choose an existing nonempty parent and an activity absent from its children.
    parent, children = next(
        (k, v["subactivities"]) for k, v in config.items() if v["subactivities"]
    )
    anchor = children[0]
    activity = next(
        k for k, v in config.items() if k not in children and k != parent and not v["subactivities"]
    )
    for tool, after, activities in [
        ("workflow.insert", False, activity),
        ("workflow.insert_after", True, [activity]),
    ]:
        changed = r.tool(tool, **args, activity=anchor, activities=activities)
        desc = r.tool("workflow.describe", **args)
        siblings = json.loads(desc["configuration"])[parent]["subactivities"]
        position = siblings.index(anchor)
        adjacent = position + 1 if after else position - 1
        r.record(
            tool,
            "array" if after else "string",
            changed["changed"] and adjacent >= 0 and siblings[adjacent] == activity,
            "Independent topology readback places activity on requested side of anchor",
            {"parent": parent, "anchor": anchor, "activity": activity, "siblings": siblings},
        )
    changed = r.tool("workflow.remove", **args, activity=activity)
    desc = r.tool("workflow.describe", **args)
    r.record(
        "workflow.remove",
        "topology-readback",
        changed["changed"] and activity not in json.loads(desc["configuration"]),
        "Removing cloned activity removes its definition",
        {"activity": activity, "remaining": desc["subactivities"]},
    )
    untouched = r.tool("workflow.describe", session_id=sid)
    r.record(
        "workflow.clone",
        "source-isolation",
        untouched["configuration"] == original["configuration"],
        "Editing clone leaves original workflow unchanged",
        {"source_workflow": original["name"]},
    )
    for sequential in [False, True]:
        r.verify(
            "workflow.graph",
            "sequential" if sequential else "topology",
            dict(args, sequential=sequential),
            lambda p: p["node_count"] > 0 and p["edge_count"] > 0,
            "Edited workflow yields a nonempty native graph",
        )
    r.verify(
        "workflow.describe",
        "recursive",
        dict(args, immediate=False, activity=parent),
        lambda p: bool(p["subactivities"]),
        "Recursive subactivity query returns edited topology",
    )
    registered_name = "cli.workflow.registered." + uuid4().hex
    r.verify(
        "workflow.clone",
        "registered",
        {"session_id": sid, "name": registered_name, "register": True},
        lambda p: p["registered"],
        "Optional registration succeeds",
    )
    r.verify(
        "workflow.list",
        "registered-clone",
        {},
        lambda p: registered_name in p["items"],
        "Registered clone survives in native global registry",
    )
    _machine(r, original)


def _machine(r, workflow):
    sid = r.session_id
    activity = workflow["subactivities"][0]

    def control(action, **kwargs):
        return r.tool("workflow.machine.control", session_id=sid, action=action, **kwargs)

    r.verify(
        "workflow.machine.status",
        "native-status",
        {"session_id": sid},
        lambda p: bool(p["status"]["machineState"]["state"]),
        "Workflow machine exposes native state",
    )
    control("breakpoint_set", activities=activity)
    observed = r.native("bv.workflow.machine.breakpoint_query()")
    r.record(
        "workflow.machine.control",
        "breakpoint_set",
        activity in observed["response"]["activities"],
        "Native breakpoint query contains requested activity",
        observed,
    )
    control("breakpoint_delete", activities=[activity])
    observed = r.native("bv.workflow.machine.breakpoint_query()")
    r.record(
        "workflow.machine.control",
        "breakpoint_delete",
        observed["commandStatus"]["accepted"]
        and activity not in observed.get("response", {}).get("activities", []),
        "Native breakpoint query confirms deletion",
        observed,
    )
    for enable in [False, True]:
        control("override_set", activity=activity, enable=enable)
        observed = r.native(f"bv.workflow.machine.override_query({activity!r})")
        r.record(
            "workflow.machine.control",
            "override_set-" + str(enable).lower(),
            observed["response"]["activity"]["override"] is enable,
            "Native override query matches requested boolean",
            observed,
        )
    control("override_clear", activity=activity)
    observed = r.native(f"bv.workflow.machine.override_query({activity!r})")
    r.record(
        "workflow.machine.control",
        "override_clear",
        "override" not in observed["response"]["activity"],
        "Native override query no longer contains an override",
        observed,
    )
    for action, expected in [("disable", "Suspend"), ("enable", "Idle"), ("reset", "Idle")]:
        payload = control(action)
        observed = r.native("bv.workflow.machine.status()")
        r.record(
            "workflow.machine.control",
            action,
            observed["machineState"]["state"] == expected,
            "Native machine reaches " + expected,
            {"tool": payload, "native": observed},
        )
    for action in ["run", "resume"]:
        payload = control(action, advanced=True, incremental=False)
        observed = r.native("bv.workflow.machine.status()")
        r.record(
            "workflow.machine.control",
            action,
            payload["command_result"]["commandStatus"]["accepted"] is True
            and observed["machineState"]["state"] in {"Idle", "Ready", "Running", "Stall"},
            "Native machine accepts scheduling request and exposes resulting state",
            {"tool": payload, "native": observed},
        )
    payload = control("dump")
    if payload["dump_source"] == "native_command":
        passed = payload["command_result"]["commandStatus"]["accepted"] is True
    else:
        snapshot = payload["dump_snapshot"]
        passed = (
            payload["dump_source"] == "native_state_snapshot"
            and payload["command_result"]["commandStatus"]["accepted"] is False
            and all(
                snapshot[k]["commandStatus"]["accepted"] is True
                for k in ["status", "breakpoints", "overrides"]
            )
            and json.loads(snapshot["configuration"]) == json.loads(workflow["configuration"])
        )
    r.record(
        "workflow.machine.control",
        "dump",
        passed,
        "Dump yields native command data or explicitly identified native state snapshot",
        payload,
    )
    _halt_running(r)


def _prepare_gate_workflow(r, label):
    """Register a real workflow with observable, bounded native activity gates."""
    name = "cli.workflow." + label + "." + uuid4().hex
    gate = name + ".gate"
    following = name + ".following"
    setup = f"""import threading, json
if not hasattr(bn, '_cli_verification_halt_events'):
    bn._cli_verification_halt_events = {{}}
entered, release, done, continued = [threading.Event() for _ in range(4)]
bn._cli_verification_halt_events[{name!r}] = (entered, release, done, continued)
def gate_action(context):
    entered.set()
    release.wait(30)
    done.set()
def following_action(context):
    continued.set()
w = bv.workflow.clone({name!r})
a = bn.Activity(json.dumps({{'name': {gate!r}, 'eligibility': {{'runOnce': True}}}}),
                action=gate_action, eligibility=lambda *args: True)
b = bn.Activity(json.dumps({{'name': {following!r}, 'eligibility': {{'runOnce': True}}}}),
                action=following_action, eligibility=lambda *args: True)
assert w.register_activity(a)
assert w.register_activity(b)
assert w.insert('core.module.update', [{gate!r}, {following!r}])
assert w.register()
_ = w.name
"""
    r.native(setup)
    events = f"bn._cli_verification_halt_events[{name!r}]"
    return name, gate, events


def _halt_running(r):
    """Exercise halt while a real native Activity is active, without timing races."""
    name, gate, events = _prepare_gate_workflow(r, "halt")
    with r.isolated(update_analysis=False, options={"analysis.workflows.moduleWorkflow": name}):
        try:
            r.native("bv.update_analysis()")
            entered = r.native(f"{events}[0].wait(10)")
            before = r.native("bv.workflow.machine.status()")
            r.record(
                "workflow.machine.control",
                "halt-native-precondition",
                entered
                and before["machineState"]["state"] == "Active"
                and before["machineState"]["activity"] == gate,
                "Real native callback is active and blocked at the controlled gate",
                before,
            )
            halted = r.tool("workflow.machine.control", session_id=r.session_id, action="halt")
            r.native(f"{events}[1].set()\n_ = {events}[2].wait(10)")
            observed = r.native(
                f"import time\ntime.sleep(0.05)\n_ = {{'status': bv.workflow.machine.status(), "
                f"'gate_completed': {events}[2].is_set(), "
                f"'successor_executed': {events}[3].is_set()}}"
            )
            r.record(
                "workflow.machine.control",
                "halt",
                halted["command_result"]["commandStatus"]["accepted"] is True
                and observed["gate_completed"]
                and not observed["successor_executed"],
                "Accepted halt prevents the next native activity after active callback returns",
                observed,
            )
        finally:
            # The callback also has its own deadline, so a lost transport cannot
            # leave a native analysis thread waiting indefinitely.
            r.native(f"{events}[1].set()\n{events}[2].wait(10)\nbv.abort_analysis()")


def run_cancellation(r):
    """Cancel a proven running native analysis task and verify its terminal state."""
    name, gate, events = _prepare_gate_workflow(r, "cancel")
    with r.isolated(update_analysis=False, options={"analysis.workflows.moduleWorkflow": name}):
        try:
            task = r.tool("task.analysis_update", session_id=r.session_id)
            task_id = task["task_id"]
            entered = r.native(f"{events}[0].wait(10)")
            native_before = r.native("bv.workflow.machine.status()")
            before = r.tool("task.status", task_id=task_id)
            r.record(
                "task.analysis_update",
                "running-native-gate",
                entered
                and before["status"] == "running"
                and not before["result_ready"]
                and native_before["machineState"]["state"] == "Active"
                and native_before["machineState"]["activity"] == gate,
                "Task is running in a real blocked native Activity before cancellation",
                {"task": before, "native": native_before},
            )
            cancelled = r.tool("task.cancel", task_id=task_id)
            r.native(f"{events}[1].set()\n_ = {events}[2].wait(10)")
            deadline = time.monotonic() + 15
            terminal = r.tool("task.status", task_id=task_id)
            while not terminal["result_ready"] and time.monotonic() < deadline:
                time.sleep(0.025)
                terminal = r.tool("task.status", task_id=task_id)
            r.record(
                "task.cancel",
                "running-cancelled",
                cancelled["cancel_requested"]
                and cancelled["cancel_hook_called"]
                and terminal["status"] == "cancelled"
                and terminal["result_ready"],
                "Cancelling a proven running task reaches cancelled, never completed",
                {"before": before, "cancel": cancelled, "terminal": terminal},
            )
            r.verify(
                "task.result",
                "native-cancelled",
                {"task_id": task_id},
                lambda p: p["status"] == "cancelled" and "result" not in p,
                "Cancelled native task exposes an explicit cancelled terminal result",
            )
            managed = r.tool("analysis.status", session_id=r.session_id)
            native = r.native(
                f"{{'aborted': bv.analysis_is_aborted, 'gate_completed': {events}[2].is_set(), "
                f"'successor_executed': {events}[3].is_set()}}"
            )
            r.record(
                "task.cancel",
                "native-analysis-drained",
                managed["status"] == "cancelled"
                and not managed["control_in_progress"]
                and native["aborted"]
                and native["gate_completed"],
                "Managed analysis is terminal and native analysis is aborted after gate release",
                {"managed": managed, "native": native},
            )
        finally:
            r.native(f"{events}[1].set()\n{events}[2].wait(10)\nbv.abort_analysis()")
