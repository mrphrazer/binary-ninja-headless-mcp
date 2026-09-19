"""Native semantic coverage for CLI binary inspection and architecture tools.

The runner supplies CLI invocations and an independent native Binary Ninja oracle.
Assertions deliberately compare fixture facts or native values, not just success flags.
"""

from __future__ import annotations


def run_reads(r):  # noqa: PLR0915 - ordered native coverage scenarios
    """Exercise every inspection tool, including all IL levels and SSA variants."""
    sid = r.session_id
    start = r.function_start
    native = r.native

    def check(name, variant, args, predicate, expectation):
        return r.verify(name, variant, {"session_id": sid, **args}, predicate, expectation)

    facts = native(
        "{'start':bv.start,'end':bv.end,'arch':bv.arch.name,"
        "'functions':len(bv.functions),'strings':len(bv.strings),"
        "'sections':len(bv.sections),'segments':len(bv.segments),"
        "'data_vars':len(bv.data_vars),'symbols':sum(len(x) for x in bv.symbols.values())}"
    )
    check(
        "binary.summary",
        "fixture_identity",
        {},
        lambda p: (
            p["arch"] == facts["arch"]
            and p["function_count"] == facts["functions"]
            and int(p["start"], 16) == facts["start"]
        ),
        "Native architecture, mapped start, and function count agree",
    )
    pages = {
        "functions": lambda x: x["start"] == hex(start),
        "strings": lambda x: "BINJA_CLI_NATIVE_SENTINEL" in (x["value"] or ""),
        "sections": lambda x: x["name"] == ".text",
        "segments": lambda x: int(x["start"], 16) <= start < int(x["end"], 16) and x["executable"],
        "symbols": lambda x: x["address"] == hex(r.symbols["cli_global"]),
        "data_vars": lambda x: x["address"] == hex(r.symbols["cli_global"]),
    }
    for group, fixture_predicate in pages.items():
        full = check(
            "binary." + group,
            "fixture_contents",
            {"limit": 10000},
            lambda p, g=group, pred=fixture_predicate: (
                p["total"] == facts[g] and any(pred(item) for item in p["items"])
            ),
            "Fixture item is present and total equals native enumeration",
        )
        check(
            "binary." + group,
            "pagination",
            {"offset": 1, "limit": 2},
            lambda p, full=full: p["items"] == full["items"][1:3] and p["total"] == full["total"],
            "Offset and limit select exact slice without changing total",
        )
    check(
        "binary.get_function_at",
        "known_function",
        {"address": start},
        lambda p: p["function"]["start"] == hex(start),
        "Lookup returns fixture function address",
    )
    check(
        "binary.functions_at",
        "known_function",
        {"address": start},
        lambda p: any(x["start"] == hex(start) for x in p["items"]),
        "Exact-address lookup contains fixture function",
    )
    block_starts = native(f"[b.start for b in bv.get_basic_blocks_at({start})]")
    check(
        "binary.basic_blocks_at",
        "native_blocks",
        {"address": start},
        lambda p: [int(x["start"], 16) for x in p["items"]] == sorted(block_starts),
        "Basic block start addresses equal native blocks at fixture entry",
    )
    expected_disasm = native(
        "[{'address':hex(a),'text':''.join(str(t) for t in ts)} "
        f"for ts,a in bv.get_function_at({start}).instructions]"
    )
    for name in ("binary.get_function_disassembly_at", "disasm.function"):
        check(
            name,
            "native_instructions",
            {"address": start},
            lambda p: (
                [(x["address"], x["text"]) for x in p["items"]]
                == [(x["address"], x["text"]) for x in expected_disasm]
            ),
            "Every disassembled instruction matches native address and text",
        )
    check(
        "disasm.range",
        "bounded_instruction",
        {"start": start, "length": 1, "limit": 1},
        lambda p: (
            len(p["items"]) == 1
            and p["items"][0]["address"] == hex(start)
            and p["items"][0]["text"] == native(f"bv.get_disassembly({start})")
        ),
        "One-instruction range equals native disassembly at fixture entry",
    )
    linear = check(
        "disasm.linear",
        "nonempty_listing",
        {"limit": 10000},
        lambda p: any("cli_add" in str(x) for x in p["items"]),
        "Linear rendering includes named fixture function",
    )
    check(
        "disasm.linear",
        "pagination",
        {"offset": 2, "limit": 3},
        lambda p: p["items"] == linear["items"][2:5] and p["total"] == linear["total"],
        "Linear page equals exact slice of complete fixture listing",
    )

    for level in ("llil", "mlil", "hlil"):
        for ssa in (False, True):
            variant = level + ("_ssa" if ssa else "")
            expression = f"bv.get_function_at({start}).{level}" + (".ssa_form" if ssa else "")
            expected = native(
                "[{'index':i.instr_index,'address':hex(i.address),'text':str(i),"
                f"'operation':i.operation.name}} for i in {expression}.instructions]"
            )
            args = {"function_start": start, "level": level, "ssa": ssa}

            def il_equal(p, expected=expected):
                return [
                    {k: x[k] for k in ("index", "address", "text", "operation")} for x in p["items"]
                ] == expected

            check(
                "il.function",
                variant,
                args,
                il_equal,
                "All IL instructions equal independent native enumeration",
            )
            check(
                "binary.get_function_il_at",
                variant,
                {"address": start, "level": level, "ssa": ssa},
                il_equal,
                "IL alias produces complete native instruction sequence",
            )
            check(
                "il.function",
                variant + "_page",
                {**args, "offset": 1, "limit": 2},
                lambda p, expected=expected: (
                    [x["index"] for x in p["items"]] == [x["index"] for x in expected[1:3]]
                ),
                "IL pagination retains native instruction indices",
            )
            instruction = expected[0]
            address = int(instruction["address"], 16)
            check(
                "il.instruction_by_addr",
                variant,
                {**args, "address": address},
                lambda p, i=instruction: (
                    p["instruction"]["text"] == i["text"]
                    and p["instruction"]["index"] == i["index"]
                ),
                "Address lookup yields the first native IL instruction at address",
            )
            indices = sorted({i["index"] for i in expected if i["address"] == hex(address)})
            check(
                "il.address_to_index",
                variant,
                {**args, "address": address},
                lambda p, indices=indices: p["indices"] == indices,
                "Address maps to exactly the native instruction indices",
            )
            check(
                "il.index_to_address",
                variant,
                {**args, "index": instruction["index"]},
                lambda p, address=address: p["address"] == hex(address),
                "Index-to-address reverses native IL mapping",
            )
            # Native possible-value objects are serialized by repr when not scalar.
            possible = native(
                f"repr(getattr({expression}[{instruction['index']}], 'possible_values', None))"
            )
            check(
                "value.possible",
                variant,
                {**args, "address": address},
                lambda p, possible=possible: (
                    repr(p["possible_values"]) == possible
                    if possible == "None"
                    else p["possible_values"] == possible
                ),
                "Possible values equal independent native value rendering",
            )

    for after in (False, True):
        variant = "after" if after else "before"
        getter = "get_reg_value_after" if after else "get_reg_value_at"
        register = native("bv.arch.stack_pointer")
        expected = native(
            "(lambda v: {'rendered':str(v),'type':v.type.name,'value':v.value})"
            f"(bv.get_function_at({start}).{getter}({start},{register!r}))"
        )
        check(
            "value.reg",
            variant,
            {"function_start": start, "address": start, "register": register, "after": after},
            lambda p, expected=expected: p["value"] == expected,
            "Stack-pointer abstract register value equals native query",
        )
        getter = "get_stack_contents_after" if after else "get_stack_contents_at"
        expected = native(
            "(lambda v: {'rendered':str(v),'type':v.type.name,'value':v.value})"
            f"(bv.get_function_at({start}).{getter}({start},0,4))"
        )
        check(
            "value.stack",
            variant,
            {
                "function_start": start,
                "address": start,
                "stack_offset": 0,
                "size": 4,
                "after": after,
            },
            lambda p, expected=expected: p["value"] == expected,
            "Stack abstract value equals native query before/after entry",
        )
    flag_address = r.symbols["cli_branch"]
    flag_data = native(
        f"f=bv.get_function_at({flag_address})\n"
        "candidates=[i for i in f.lifted_il.instructions "
        "if f.get_flags_written_by_lifted_il_instruction(i.instr_index)]\n"
        "i=candidates[0] if candidates else list(f.lifted_il.instructions)[0]\n"
        "_={'address':i.address,"
        "'read':[str(x) for x in f.get_flags_read_by_lifted_il_instruction(i.instr_index)],"
        "'written':[str(x) for x in f.get_flags_written_by_lifted_il_instruction(i.instr_index)]}"
    )
    check(
        "value.flags_at",
        "branch_flags",
        {"function_start": flag_address, "address": flag_data["address"]},
        lambda p: (
            p["flags_read"] == flag_data["read"] and p["flags_written"] == flag_data["written"]
        ),
        "Conditional-branch flag reads and writes equal native lifted IL",
    )

    refs = native(f"[x.address for x in bv.get_code_refs({start})]")
    check(
        "xref.code_refs_to",
        "fixture_caller",
        {"address": start},
        lambda p: sorted(int(x["from"], 16) for x in p["items"]) == sorted(refs) and bool(refs),
        "Known fixture function has real native call sites",
    )
    check(
        "xref.code_refs_from",
        "reverse_call",
        {"address": refs[0]},
        lambda p: hex(start) in [x["to"] for x in p["items"]],
        "Call site resolves back to fixture callee",
    )
    message = r.symbols["cli_message"]
    data_refs = native(f"list(bv.get_data_refs({message}))")
    check(
        "xref.data_refs_to",
        "fixture_pointer",
        {"address": message},
        lambda p: (
            sorted(int(x["from"], 16) for x in p["items"]) == sorted(data_refs) and bool(data_refs)
        ),
        "Fixture message has concrete native data references",
    )
    check(
        "xref.data_refs_from",
        "reverse_pointer",
        {"address": data_refs[0]},
        lambda p: hex(message) in [x["to"] for x in p["items"]],
        "Data pointer resolves back to fixture message",
    )

    pattern = b"BINJA_CLI_NATIVE_SENTINEL".hex()
    for tool in ("search.data", "search.all_data"):
        check(
            tool,
            "sentinel",
            {"data_hex": pattern, "start": facts["start"], "end": facts["end"]},
            lambda p: hex(message) in [x["address"] for x in p["items"]],
            "Exact sentinel bytes resolve to message symbol",
        )
    check(
        "search.next_data",
        "sentinel",
        {"data_hex": pattern, "start": facts["start"]},
        lambda p: p["found"] and p["address"] == hex(message),
        "First sentinel match equals message symbol",
    )
    check(
        "binary.search_text",
        "sentinel",
        {"query": "BINJA_CLI_NATIVE_SENTINEL"},
        lambda p: hex(message) in [x["address"] for x in p["items"]],
        "Raw text search resolves sentinel bytes to message symbol",
    )
    check(
        "search.all_text",
        "symbol_text",
        {"query": "cli_add", "start": facts["start"], "end": facts["end"]},
        lambda p: p["count"] > 0 and any("cli_add" in str(x) for x in p["items"]),
        "Rendered text search finds fixture function name",
    )
    expected_text = native(f"bv.find_next_text({facts['start']}, 'cli_add')")
    check(
        "search.next_text",
        "symbol_text",
        {"start": facts["start"], "query": "cli_add"},
        lambda p: p["found"] and p["address"] == hex(expected_text),
        "First text match equals native search result",
    )
    check(
        "search.all_text",
        "regex",
        {"start": facts["start"], "end": facts["end"], "query": "cli_a[d]+", "regex": True},
        lambda p: p["count"] > 0,
        "Regular expression finds named fixture function",
    )
    # Zero is present in ELF header/rendering on both supported architectures.
    constant = 0
    matches = native(
        "[x[0] if isinstance(x,tuple) else x for x in "
        f"bv.find_all_constant({facts['start']},{facts['end']},{constant})]"
    )
    check(
        "search.all_constant",
        "native_zero",
        {"start": facts["start"], "end": facts["end"], "constant": constant},
        lambda p: [int(x["address"], 16) for x in p["items"]] == matches[:100] and bool(matches),
        "Zero constant matches and result limit equal native rendered-token search",
    )
    check(
        "search.next_constant",
        "native_zero",
        {"start": facts["start"], "constant": constant},
        lambda p: p["found"] and p["address"] == hex(matches[0]),
        "Next constant search returns first native match",
    )

    info = check(
        "arch.info",
        "native_arch",
        {},
        lambda p: (
            p["arch"] == facts["arch"]
            and p["address_size"] == native("bv.arch.address_size")
            and set(p["registers"]) == set(native("list(bv.arch.regs)"))
        ),
        "Architecture name, address width, and register set equal native architecture",
    )
    nop_hex = native("bv.arch.assemble('nop', 0).hex()")
    for explicit in (False, True):
        args = {"arch_name": info["arch"]} if explicit else {}
        check(
            "arch.assemble",
            "explicit" if explicit else "view_arch",
            {"asm": "nop", **args},
            lambda p: p["data_hex"] == nop_hex and p["size"] == len(bytes.fromhex(nop_hex)),
            "NOP encoding matches native assembler exactly",
        )
        check(
            "arch.disasm_bytes",
            "explicit" if explicit else "view_arch",
            {"data_hex": nop_hex, **args},
            lambda p: p["text"].strip() == "nop" and p["length"] == len(bytes.fromhex(nop_hex)),
            "Assembled NOP decodes with correct mnemonic and instruction size",
        )
    for mode in ("disabled", "interactive", "full"):
        for process in (False, True):
            check(
                "transform.inspect",
                mode + ("_process" if process else "_inspect"),
                {"mode": mode, "process": process},
                lambda p, mode=mode, process=process: (
                    p["mode"] == mode
                    and p["processed"] == process
                    and p["root_context"] is not None
                    and p["root_context"]["is_root"]
                ),
                "Native transform context preserves root and requested processing mode",
            )
            r.verify(
                "transform.inspect",
                "path_" + mode + ("_process" if process else "_inspect"),
                {"path": str(r.fixture), "mode": mode, "process": process},
                lambda p, mode=mode, process=process: (
                    p["session_id"] is None
                    and p["path"] == str(r.fixture)
                    and p["mode"] == mode
                    and p["processed"] == process
                    and p["root_context"] is not None
                    and p["root_context"]["is_root"]
                ),
                "Path-based transform creates an independent native root context",
            )
    # A transform context must never close the view borrowed from the MCP session.
    check(
        "binary.summary",
        "after_transform_ownership",
        {},
        lambda p: p["function_count"] == facts["functions"],
        "Session remains usable after all transform contexts are released",
    )

    run_functions(r)


def run_functions(r):
    """Verify call graph, variables, SSA def/use and typed fixture data."""
    start = r.function_start
    branch = r.symbols["cli_branch"]
    common = {"session_id": r.session_id, "function_start": start}
    fexpr = f"bv.get_function_at({start})"
    blocks = r.native(f"[(b.start,b.end) for b in {fexpr}.basic_blocks]")
    r.verify(
        "function.basic_blocks",
        "native_graph",
        common,
        lambda p: (
            [(int(x["start"], 16), int(x["end"], 16)) for x in p["items"]]
            == sorted(tuple(x) for x in blocks)
        ),
        "Basic block ranges equal native CFG",
    )
    r.verify(
        "function.callers",
        "fixture_branch",
        common,
        lambda p: hex(branch) in [x["start"] for x in p["items"]],
        "cli_branch is a known caller of cli_add",
    )
    r.verify(
        "function.callees",
        "fixture_add",
        {**common, "function_start": branch},
        lambda p: hex(start) in [x["start"] for x in p["items"]],
        "cli_add is a known callee of cli_branch",
    )
    names = r.native(f"[v.name for v in {fexpr}.vars]")
    r.verify(
        "function.variables",
        "native_variables",
        common,
        lambda p: [x["name"] for x in p["items"]] == names and bool(names),
        "Variable enumeration retains native names and ordering",
    )
    for level in ("mlil", "hlil"):
        # Choose a variable with actual references instead of accepting an empty response.
        chosen = r.native(
            f"f={fexpr}\n"
            f"rows=[(v.name,[x.address for x in f.get_{level}_var_refs(v)]) for v in f.vars]\n"
            "_=next(row for row in rows if row[1])"
        )
        name, addresses = chosen
        args = {**common, "level": level}
        r.verify(
            "function.var_refs",
            level,
            {**args, "variable_name": name},
            lambda p, addresses=addresses: [int(x["address"], 16) for x in p["items"]] == addresses,
            "Variable references equal independently enumerated native addresses",
        )
        expected = r.native(
            "[(x.src.address,x.var.name) for x in "
            f"{fexpr}.get_{level}_var_refs_from({addresses[0]})]"
        )
        r.verify(
            "function.var_refs_from",
            level,
            {**args, "address": addresses[0]},
            lambda p, expected=expected: (
                [(int(x["address"], 16), x["variable"]["name"]) for x in p["items"]]
                == [tuple(x) for x in expected]
            ),
            "Reverse variable references match native address/name pairs",
        )
        # An SSA argument version zero has uses and intentionally no local definition.
        ssa = r.native(
            f"f={fexpr}\nil=f.{level}.ssa_form\n"
            "rows=[(v,il.get_ssa_var_uses(v)) for v in il.ssa_vars]\n"
            "v,uses=next(row for row in rows if row[1])\n"
            "definition=il.get_ssa_var_definition(v)\n"
            "_={'name':v.var.name,'version':v.version,"
            "'definition':str(definition) if definition is not None else None,"
            "'uses':[str(x) for x in uses]}"
        )
        r.verify(
            "function.ssa_var_def_use",
            level,
            {**args, "variable_name": ssa["name"], "version": ssa["version"]},
            lambda p, ssa=ssa: (
                (p["definition"]["text"] if p["definition"] else None) == ssa["definition"]
                and [x["text"] for x in p["uses"]] == ssa["uses"]
            ),
            "SSA variable definition and each use equal native SSA expressions",
        )
        memory = r.native(
            f"il=bv.get_function_at({branch}).{level}.ssa_form\n"
            "version=0\ndefinition=il.get_ssa_memory_definition(version)\n"
            "_={'definition':str(definition) if definition is not None else None,"
            "'uses':[str(x) for x in il.get_ssa_memory_uses(version)]}"
        )
        r.verify(
            "function.ssa_memory_def_use",
            level,
            {**args, "function_start": branch, "version": 0},
            lambda p, memory=memory: (
                (p["definition"]["text"] if p["definition"] else None) == memory["definition"]
                and [x["text"] for x in p["uses"]] == memory["uses"]
            ),
            "SSA incoming memory definition/uses match native expressions",
        )
    address = r.symbols["cli_global"]
    r.verify(
        "data.typed_at",
        "global_value",
        {"session_id": r.session_id, "address": address},
        lambda p: p["data_var"]["address"] == hex(address) and p["data_var"]["value"] == 0x12345678,
        "Typed data lookup reads the fixture global initializer",
    )
