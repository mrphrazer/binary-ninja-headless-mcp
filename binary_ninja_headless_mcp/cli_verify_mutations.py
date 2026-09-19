"""Native mutation scenarios with independent readback and reversible fixtures.

Called by the CLI coverage runner; this module never substitutes a fake backend.
"""

from __future__ import annotations

import json
from uuid import uuid4


def run_mutations(r):
    """Exercise mutable BinaryView capabilities through the runner's CLI transport."""
    with r.isolated():
        _memory(r)
        _annotations(r)
        _metadata(r)
        _undo(r)
        _patches(r)
        _segments(r)
        _external(r)
        _load_settings(r)
        _types(r)
    _raw_memory(r)
    with r.isolated():
        old_start = r.native("bv.start")
        old_symbol = r.native("bv.get_symbol_by_raw_name('cli_add').address")
        target = old_start + 0x1000000
        r.verify(
            "loader.rebase",
            "relocate-native-image",
            {"session_id": r.session_id, "address": target},
            lambda p: p["rebased"] and int(p["start"], 16) == target,
            "Native image is relocated to the requested base",
        )
        shifted = r.native("bv.get_symbol_by_raw_name('cli_add').address")
        r.record(
            "loader.rebase",
            "symbol-delta",
            shifted == old_symbol + target - old_start,
            "Existing symbol moves by the exact rebase delta",
            shifted,
        )
        r.verify(
            "loader.rebase",
            "same-base-noop",
            {"session_id": r.session_id, "address": target},
            lambda p: p["rebased"] is False,
            "Repeated base is an explicit no-op",
        )


def _memory(r):
    sid = r.session_id
    address = r.symbols["cli_message"]
    original = r.native(f"bv.read({address}, 16).hex()")
    r.verify(
        "memory.read",
        "known-sentinel",
        {"session_id": sid, "address": address, "length": 16},
        lambda p: p["data_hex"] == b"BINJA_CLI_NATIVE_SENTINEL"[:16].hex(),
        "Read returns the known compiled sentinel bytes",
    )
    try:
        for endian in ("little", "big"):
            for width in (1, 2, 4, 8):
                value = int.from_bytes(bytes(range(1, width + 1)), endian)
                args = dict(session_id=sid, address=address, width=width, endian=endian)
                r.verify(
                    "memory.writer_write",
                    f"{endian}-{width}",
                    {**args, "value": value},
                    lambda p, w=width: p["written"] and p["next_offset"] == address + w,
                    "Writer advances by width and reports success",
                )
                actual = r.native(f"bv.read({address}, {width}).hex()")
                r.record(
                    "memory.writer_write",
                    f"{endian}-{width}-bytes",
                    actual == bytes(range(1, width + 1)).hex(),
                    "Native bytes match independently encoded integer",
                    actual,
                )
                r.verify(
                    "memory.reader_read",
                    f"{endian}-{width}",
                    args,
                    lambda p, v=value, w=width: p["value"] == v and p["next_offset"] == address + w,
                    "Reader returns written integer and advances by width",
                )
        r.verify(
            "memory.write",
            "literal-bytes",
            {"session_id": sid, "address": address, "data_hex": "11223344"},
            lambda p: p["written"] == 4,
            "Exactly four bytes are written",
        )
        r.record(
            "memory.write",
            "native-readback",
            r.native(f"bv.read({address}, 4).hex()") == "11223344",
            "Native view contains all four supplied bytes",
        )
    finally:
        r.tool("memory.write", session_id=sid, address=address, data_hex=original)
    r.record(
        "memory.write",
        "restored",
        r.native(f"bv.read({address}, 16).hex()") == original,
        "Original fixture bytes restored",
    )


def _raw_memory(r):
    original = bytes(range(32))
    database = r.output / f"raw-{uuid4().hex}.bndb"
    created = r.native(
        "raw = bn.BinaryView.new(bytes(range(32)))\n"
        "raw.arch = bn.Architecture['x86_64']\n"
        "try:\n"
        f"    _ = raw.create_database({str(database)!r})\n"
        "finally:\n"
        "    raw.file.close()"
    )
    r.record(
        "memory.insert",
        "raw-fixture-database",
        created,
        "A genuine Raw-only database is created as the mutable fixture",
    )
    opened = r.verify(
        "session.open",
        "raw-only-database",
        dict(path=str(database), update_analysis=False, read_only=False),
        lambda p: p["view_type"] == "Raw" and p["end"] == "0x20",
        "Opening the saved native database preserves its Raw view and exact length",
    )
    sid = opened["session_id"]
    try:
        r.verify(
            "memory.insert",
            "raw-view",
            dict(session_id=sid, address=4, data_hex="deadbeef"),
            lambda p: p["inserted"] == 4,
            "Raw view inserts four bytes",
        )
        r.verify(
            "memory.read",
            "raw-insertion-readback",
            dict(session_id=sid, address=0, length=36),
            lambda p: p["data_hex"] == (original[:4] + b"\xde\xad\xbe\xef" + original[4:]).hex(),
            "Insertion shifts the original tail without corrupting it",
        )
        inserted = original[:4] + b"\xde\xad\xbe\xef" + original[4:]
        saved = database.with_suffix(".inserted.bin")
        r.verify(
            "binary.save",
            "raw-inserted-bytes",
            dict(session_id=sid, path=str(saved)),
            lambda p: p["saved"],
            "Raw byte insertion is saved to a standalone binary",
        )
        r.record(
            "memory.insert",
            "persisted-file-readback",
            saved.read_bytes() == inserted,
            "Independent filesystem read proves saved insertion and tail contents",
        )
        r.verify(
            "memory.remove",
            "raw-view",
            dict(session_id=sid, address=4, length=4),
            lambda p: p["removed"] == 4,
            "Raw view removes precisely the inserted bytes",
        )
        r.verify(
            "memory.read",
            "raw-removal-readback",
            dict(session_id=sid, address=0, length=32),
            lambda p: p["data_hex"] == original.hex(),
            "Removal restores the entire original raw buffer",
        )
    finally:
        r.tool("session.close", session_id=sid)


def _annotations(r):
    sid, fn, data = r.session_id, r.function_start, r.symbols["cli_message"] + 8
    old_name = r.native(f"bv.get_function_at({fn}).name")
    r.verify(
        "annotation.rename_function",
        "rename-and-readback",
        dict(session_id=sid, function_start=fn, new_name="cli_renamed_function"),
        lambda p: p["function"]["name"] == "cli_renamed_function",
        "Function result carries new name",
    )
    r.record(
        "annotation.rename_function",
        "native-readback",
        r.native(f"bv.get_function_at({fn}).name") == "cli_renamed_function",
        "Native function has new name",
    )
    r.tool("annotation.rename_function", session_id=sid, function_start=fn, new_name=old_name)
    r.verify(
        "annotation.define_symbol",
        "new-data-symbol",
        dict(session_id=sid, address=data, name="cli_user_symbol", symbol_type="DataSymbol"),
        lambda p: p["symbol"]["name"] == "cli_user_symbol",
        "A user symbol is defined",
    )
    r.verify(
        "annotation.rename_symbol",
        "rename-user-symbol",
        dict(session_id=sid, address=data, new_name="cli_renamed_symbol"),
        lambda p: p["symbol"]["name"] == "cli_renamed_symbol",
        "Symbol result carries new name",
    )
    r.record(
        "annotation.rename_symbol",
        "native-readback",
        r.native(f"bv.get_symbol_at({data}).name") == "cli_renamed_symbol",
        "Native symbol has renamed value",
    )
    r.verify(
        "annotation.undefine_symbol",
        "remove-user-symbol",
        dict(session_id=sid, address=data),
        lambda p: p["undefined"],
        "User symbol removal reports success",
    )
    r.record(
        "annotation.undefine_symbol",
        "native-readback",
        r.native(f"bv.get_symbol_at({data}) is None"),
        "Native symbol was actually removed",
    )
    for kind, width in (("char", 1), ("int", 4), ("pointer", 8)):
        r.verify(
            "annotation.define_data_var",
            kind,
            dict(session_id=sid, address=data, type_name=kind, width=width, name="cli_data"),
            lambda p: p["data_var"]["name"] == "cli_data",
            "Named user data variable is defined",
        )
        r.record(
            "annotation.define_data_var",
            kind + "-native-width",
            r.native(f"bv.get_data_var_at({data}).type.width") == width,
            "Native data type has requested width",
        )
        r.verify(
            "annotation.rename_data_var",
            kind,
            dict(session_id=sid, address=data, new_name="cli_data_renamed"),
            lambda p: p["data_var"]["name"] == "cli_data_renamed",
            "Data variable has requested name",
        )
        r.verify(
            "annotation.undefine_data_var",
            kind,
            dict(session_id=sid, address=data),
            lambda p: p["undefined"],
            "User data variable removal reports success",
        )
        r.record(
            "annotation.undefine_data_var",
            kind + "-native-absent",
            r.native(
                f"bv.get_data_var_at({data}) is None or bv.get_data_var_at({data}).auto_discovered"
            ),
            "User definition removed; any native fallback must be auto-discovered",
        )
    comment = 'CLI native comment: quotes " and Unicode λ\nsecond line'
    r.verify(
        "annotation.set_comment",
        "unicode-multiline",
        dict(session_id=sid, address=fn, comment=comment),
        lambda p: p["comment"] == comment,
        "Comments preserve Unicode, quotes, and newlines",
    )
    r.verify(
        "annotation.get_comment",
        "readback",
        dict(session_id=sid, address=fn),
        lambda p: p["comment"] == comment,
        "Independent get returns exact comment",
    )
    r.verify(
        "annotation.set_comment",
        "clear",
        dict(session_id=sid, address=fn, comment=""),
        lambda p: p["comment"] == "",
        "Empty comment clears native annotation",
    )
    for tool in ("annotation.add_tag", "annotation.get_tags"):
        args = dict(session_id=sid, address=fn)
        if tool.endswith("add_tag"):
            args.update(tag_type="CLI native check", data="cli-tag-value", icon="C")
        r.verify(
            tool,
            "native-tag",
            args,
            lambda p: any(
                t["data"] == "cli-tag-value" and t["type_name"] == "CLI native check"
                for t in p["items"]
            ),
            "Tag list contains exact type and data",
        )


def _metadata(r):
    values = ("native text λ", 17, True, 1.25, [1, "two", False], {"nested": [1, 2], "flag": True})
    for prefix in ("metadata.", "function.metadata_"):
        args = dict(session_id=r.session_id, key="cli.native.verification")
        if prefix.startswith("function"):
            args["function_start"] = r.function_start
        for index, value in enumerate(values):
            r.verify(
                prefix + "store",
                f"value-{index}",
                {**args, "value": value},
                lambda p, v=value: (
                    json.dumps(p["value"], sort_keys=True) == json.dumps(v, sort_keys=True)
                ),
                "Stored metadata matches supplied typed value",
            )
            r.verify(
                prefix + "query",
                f"value-{index}",
                args,
                lambda p, v=value: (
                    json.dumps(p["value"], sort_keys=True) == json.dumps(v, sort_keys=True)
                ),
                "Separate query preserves metadata value and shape",
            )
        r.verify(
            prefix + "remove", "delete", args, lambda p: p["removed"], "Metadata removal succeeds"
        )
        r.verify(
            prefix + "query",
            "absent-after-remove",
            args,
            lambda p: p["value"] is None,
            "Deleted metadata is absent",
        )


def _undo(r):
    args = dict(session_id=r.session_id)
    address = r.function_start
    r.tool("annotation.set_comment", **args, address=address, comment="before transaction")
    transaction = r.verify(
        "undo.begin",
        "begin",
        args,
        lambda p: bool(p["transaction_id"]),
        "Begin returns a native transaction identifier",
    )["transaction_id"]
    r.tool("annotation.set_comment", **args, address=address, comment="committed transaction")
    r.verify(
        "undo.commit",
        "commit",
        {**args, "transaction_id": transaction},
        lambda p: p["committed"],
        "Commit accepts returned transaction identifier",
    )
    for tool, expected in (
        ("undo.undo", "before transaction"),
        ("undo.redo", "committed transaction"),
    ):
        r.tool(tool, **args)
        r.record(
            tool,
            "native-comment-state",
            r.native(f"bv.get_comment_at({address})") == expected,
            "Native comment matches expected transaction state",
            expected,
        )
    transaction = r.tool("undo.begin", **args)["transaction_id"]
    r.tool("annotation.set_comment", **args, address=address, comment="uncommitted")
    r.verify(
        "undo.revert",
        "revert-open-transaction",
        {**args, "transaction_id": transaction},
        lambda p: p["reverted"],
        "Revert accepts an open transaction",
    )
    r.record(
        "undo.revert",
        "native-comment-state",
        r.native(f"bv.get_comment_at({address})") == "committed transaction",
        "Revert restores state before open transaction",
    )


def _patches(r):
    # Real compiler-generated branches/calls supply valid native patch sites.
    sites = r.native("""{
        'branch': next(a for f in bv.functions for _, a in f.instructions
                       if bv.is_always_branch_patch_available(a)
                       and bv.is_invert_branch_patch_available(a)),
        'call': next(a for f in bv.functions for _, a in f.instructions
                     if bv.is_skip_and_return_value_patch_available(a)),
    }""")
    branch, call = sites["branch"], sites["call"]
    r.verify(
        "patch.status",
        "conditional-branch",
        dict(session_id=r.session_id, address=branch),
        lambda p: p["is_always_branch_patch_available"] and p["is_invert_branch_patch_available"],
        "Compiled conditional branch supports branch patches",
    )
    for name in (
        "convert_to_nop",
        "always_branch",
        "never_branch",
        "invert_branch",
        "skip_and_return_value",
        "assemble",
    ):
        address = call if name == "skip_and_return_value" else branch
        original = r.native(f"bv.read({address}, 32).hex()")
        args = dict(session_id=r.session_id, address=address)
        if name == "skip_and_return_value":
            args["value"] = 7
        if name == "assemble":
            args["asm"] = "nop"
            expected = r.native(f"bv.arch.assemble('nop', {address}).hex()")
        else:
            extra = ", 7" if name == "skip_and_return_value" else ""
            length = r.native(f"bv.get_instruction_length({address})")
            transform = "convert_to_nop" if name == "never_branch" else name
            expected = r.native(
                f"bv.arch.{transform}(bv.read({address}, {length}), {address}{extra}).hex()"
            )
        try:
            r.verify(
                "patch." + name,
                "native-transform",
                args,
                lambda p: p.get("patched", p.get("written", 0) > 0),
                "Native patch reports a successful mutation",
            )
            actual = r.native(f"bv.read({address}, {len(expected) // 2}).hex()")
            r.record(
                "patch." + name,
                "independent-native-bytes",
                actual == expected and actual != original[: len(actual)],
                "Patched bytes match architecture transform and differ from original",
                actual,
            )
        finally:
            r.tool("memory.write", session_id=r.session_id, address=address, data_hex=original)
        r.record(
            "patch." + name,
            "restored-original-bytes",
            r.native(f"bv.read({address}, 32).hex()") == original,
            "Original instruction bytes restored",
        )


def _segments(r):
    start = (r.native("bv.end") + 0x1FFFF) & ~0xFFFF
    args = dict(session_id=r.session_id)
    r.verify(
        "segment.add_user",
        "new-mapping",
        {
            **args,
            "start": start,
            "length": 4096,
            "readable": True,
            "writable": True,
            "executable": False,
        },
        lambda p: int(p["segment"]["start"], 16) == start,
        "Requested user segment exists",
    )
    r.record(
        "segment.add_user",
        "native-flags",
        r.native(
            f"(bv.get_segment_at({start}).writable and not bv.get_segment_at({start}).executable)"
        ),
        "Native mapping preserves writable/nonexecutable flags",
    )
    r.verify(
        "section.add_user",
        "named-section",
        {
            **args,
            "name": ".cli_native",
            "start": start,
            "length": 128,
            "semantics": "ReadWriteDataSectionSemantics",
            "type_name": "cli",
            "align": 8,
            "entry_size": 4,
        },
        lambda p: p["section"]["name"] == ".cli_native" and p["section"]["align"] == 8,
        "Section preserves name and alignment",
    )
    r.verify(
        "section.remove_user",
        "remove",
        {**args, "name": ".cli_native"},
        lambda p: p["removed"],
        "Section removal reports success",
    )
    r.record(
        "section.remove_user",
        "native-absent",
        r.native("bv.get_section_by_name('.cli_native') is None"),
        "Native section is absent",
    )
    r.verify(
        "segment.remove_user",
        "remove",
        {**args, "start": start, "length": 4096},
        lambda p: p["removed"],
        "Segment removal reports success",
    )
    r.record(
        "segment.remove_user",
        "native-absent",
        r.native(f"bv.get_segment_at({start}) is None"),
        "Native segment is absent",
    )


def _external(r):
    args = dict(session_id=r.session_id)
    address = r.symbols["cli_global"]
    for auto in (False, True):
        library = f"cli_native_library_{auto}"
        variant = "auto" if auto else "user"
        r.verify(
            "external.library_add",
            variant,
            {**args, "name": library, "auto": auto},
            lambda p, lib=library: p["external_library"]["name"] == lib,
            "Requested external library is returned",
        )
        r.verify(
            "external.library_list",
            variant,
            args,
            lambda p, lib=library: any(x["name"] == lib for x in p["items"]),
            "Native library list includes added library",
        )
        r.verify(
            "external.location_add",
            variant,
            {
                **args,
                "source_address": address,
                "library_name": library,
                "target_symbol": "cli_target",
                "target_address": "0x1234",
                "auto": auto,
            },
            lambda p: (
                p["external_location"]["target_symbol"] == "cli_target"
                and p["external_location"]["target_address"] == "0x1234"
            ),
            "Location has requested symbol and target address",
        )
        r.verify(
            "external.location_get",
            variant,
            {**args, "source_address": address},
            lambda p, lib=library: p["external_location"]["external_library"] == lib,
            "Separate lookup preserves external library association",
        )
        r.verify(
            "external.location_remove",
            variant,
            {**args, "source_address": address},
            lambda p: p["removed"],
            "External location removal reports success",
        )
        r.verify(
            "external.location_get",
            variant + "-removed",
            {**args, "source_address": address},
            lambda p: p["external_location"] is None,
            "Removed location is absent",
        )
        r.verify(
            "external.library_remove",
            variant,
            {**args, "name": library},
            lambda p: p["removed"],
            "External library removal reports success",
        )
        r.record(
            "external.library_remove",
            variant + "-native-absent",
            r.native(f"bv.get_external_library({library!r}) is None"),
            "Native library is absent",
        )


def _load_settings(r):
    # A real registered native Settings object covers all write overloads without
    # changing global user configuration or relying on version-specific ELF keys.
    definitions = {
        "text": {"type": "string", "default": ""},
        "number": {"type": "number", "default": 0},
        "flag": {"type": "boolean", "default": False},
        "list": {"type": "array", "default": [], "elementType": "string"},
    }
    r.native(
        "s = bn.Settings('cli-native-verification')\ns.register_group('cli', 'CLI native')\n"
        + "\n".join(
            f"assert s.register_setting('cli.{key}', "
            f"{json.dumps({**value, 'title': key, 'description': key})!r})"
            for key, value in definitions.items()
        )
        + "\nbv.set_load_settings('CLI Native', s)\n_ = True"
    )
    args = dict(session_id=r.session_id)
    r.verify(
        "loader.load_settings_types",
        "registered-native-settings",
        args,
        lambda p: "CLI Native" in p["items"],
        "Native settings registry includes attached settings",
    )
    for value_type, key, value, getter, expected in (
        ("string", "text", "CLI λ", "get_string", "CLI λ"),
        ("integer", "number", 12345, "get_integer", 12345),
        ("bool", "flag", True, "get_bool", True),
        ("string_list", "list", ["one", "two"], "get_string_list", ["one", "two"]),
        ("json", "list", '["three", "four"]', "get_string_list", ["three", "four"]),
    ):
        r.verify(
            "loader.load_settings_set",
            value_type,
            {
                **args,
                "type_name": "CLI Native",
                "key": "cli." + key,
                "value": value,
                "value_type": value_type,
            },
            lambda p: p["changed"],
            "Native settings setter accepts typed value",
        )
        actual = r.native(f"bv.get_load_settings('CLI Native').{getter}('cli.{key}', resource=bv)")
        r.record(
            "loader.load_settings_set",
            value_type + "-native-readback",
            actual == expected,
            "Independent native getter returns exact typed value",
            actual,
        )
    r.verify(
        "loader.load_settings_get",
        "serialized-readback",
        {**args, "type_name": "CLI Native"},
        lambda p: "cli.text" in p["keys"] and bool(json.loads(p["serialized_settings"])),
        "Settings query returns registered keys and nonempty serialized settings",
    )


def _types(r):
    args = dict(session_id=r.session_id)
    for dependencies in (False, True):
        r.verify(
            "type.parse_string",
            f"dependencies-{dependencies}",
            {
                **args,
                "type_source": "unsigned int cli_parsed_count",
                "import_dependencies": dependencies,
            },
            lambda p: p["parsed_name"] == "cli_parsed_count" and "int" in p["parsed_type"],
            "Single declaration parser preserves declarator name and integer type",
        )
    declarations = (
        "typedef struct { unsigned int count; unsigned char bytes[4]; } CliParsedRecord; "
        "extern CliParsedRecord cli_parsed_global; int cli_parsed_function(CliParsedRecord *value);"
    )
    r.verify(
        "type.parse_declarations",
        "types-variables-functions",
        {
            **args,
            "declarations": declarations,
            "options": ["-DCLI_NATIVE=1"],
            "include_dirs": [],
            "import_dependencies": True,
        },
        lambda p: (
            any(x["name"] == "CliParsedRecord" for x in p["types"])
            and any(x["name"] == "cli_parsed_global" for x in p["variables"])
            and any(x["name"] == "cli_parsed_function" for x in p["functions"])
        ),
        "Declaration parser separates named types, variables, and functions",
    )
    for explicit in (False, True):
        name = "CliMutationExplicit" if explicit else "CliMutationInferred"
        define = {
            **args,
            "type_source": "struct "
            + ("IgnoredTag" if explicit else name)
            + " { unsigned int count; unsigned char bytes[4]; }",
            "import_dependencies": False,
        }
        if explicit:
            define["name"] = name
        r.verify(
            "type.define_user",
            "explicit-name" if explicit else "inferred-name",
            define,
            lambda p, n=name: p["defined"] and p["name"] == n,
            "User definition honors explicit name or inferred structure tag",
        )
        observed = r.native(
            f"[(m.name, m.offset, m.type.width) for m in bv.get_type_by_name({name!r}).members]"
        )
        r.record(
            "type.define_user",
            name + "-native-layout",
            observed == [["count", 0, 4], ["bytes", 4, 4]],
            "Native structure members preserve names, offsets, and widths",
            observed,
        )
        renamed = name + "Renamed"
        r.verify(
            "type.rename",
            name,
            {**args, "old_name": name, "new_name": renamed},
            lambda p: p["renamed"],
            "Rename reports success",
        )
        r.record(
            "type.rename",
            name + "-native-lookup",
            r.native(
                f"bv.get_type_by_name({name!r}) is None and "
                f"bv.get_type_by_name({renamed!r}).width == 8"
            ),
            "Old type name disappears and new name retains structure layout",
        )
        r.verify(
            "type.undefine_user",
            name,
            {**args, "name": renamed},
            lambda p: p["undefined"],
            "Undefine reports success",
        )
        r.record(
            "type.undefine_user",
            name + "-native-absent",
            r.native(f"bv.get_type_by_name({renamed!r}) is None"),
            "Native type lookup confirms removal",
        )
