# Binary Ninja Headless MCP

A headless [Binary Ninja](https://binary.ninja/) server that speaks [MCP](https://modelcontextprotocol.io/) (Model Context Protocol), giving AI agents full access to deep reverse-engineering workflows — disassembly, IL, patching, types, xrefs, and more — without a GUI.

Designed to run in the same Docker container as the agent runtime. No sidecars, no extra services.

This entire project---code, tests, and documentation---is 100% vibe coded.

## Why

Existing Binary Ninja MCP servers are either GUI-bound or expose a limited tool surface. This server is headless-only and designed for agent-driven workflows in sandboxed VM/container environments: the agent gets full control over the analysis system, automating large parts of reverse engineering while you interactively discuss and steer the process.

The goal is an interface where agents can inspect, refine, and extend an analysis over time — updating types, symbols, and metadata, improving the analysis database incrementally, applying patches and iterating safely with undo/redo, and running custom scripts when a workflow needs something bespoke.

## Features

- **181 tools** across 36 feature groups: analysis, disassembly, IL, patching, undo/redo, types, workflows, memory, search, xrefs, scripting, and more.
- **Read-only by default** with safe mutation workflows (undo/redo, transactions).
- **Scripting access** via `binja.eval` and `binja.call` for anything the tool catalog doesn't cover.
- **Stdio and TCP transports.**
- **Zero runtime dependencies** beyond Binary Ninja itself.
- **Fake backend mode** for CI and development without a Binary Ninja license.

## Prerequisites

- Python `3.11+`
- A [Binary Ninja](https://binary.ninja/) installation with a headless-capable license and the `binaryninja` Python module importable in your runtime (for real analysis)
- For CI/development without Binary Ninja, use fake backend mode

## Installation

```bash
git clone https://github.com/mrphrazer/binary-ninja-headless-mcp.git
cd binary-ninja-headless-mcp
pip install .
```

Or install directly from the repo root without cloning:

```bash
pip install git+https://github.com/mrphrazer/binary-ninja-headless-mcp.git
```

## Quick Start

Stdio transport (default):

```bash
python3 binary_ninja_headless_mcp.py
```

TCP transport:

```bash
python3 binary_ninja_headless_mcp.py --transport tcp --host 127.0.0.1 --port 8765
```

Fake backend mode (no Binary Ninja required):

```bash
python3 binary_ninja_headless_mcp.py --fake-backend
```

## Use With AI Agents

This server speaks standard MCP over `stdio` (default) or `tcp`, so any MCP-capable agent host can use it.

### Claude Code

```bash
claude mcp add binary_ninja_headless_mcp -- python3 /path/to/binary-ninja-headless-mcp/binary_ninja_headless_mcp.py
```

Or add it to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "binary_ninja_headless_mcp": {
      "command": "python3",
      "args": ["binary_ninja_headless_mcp.py"],
      "cwd": "/path/to/binary-ninja-headless-mcp"
    }
  }
}
```

### Codex

```bash
codex mcp add binary_ninja_headless_mcp -- python3 binary_ninja_headless_mcp.py
```

### Generic MCP Host

- Register a server named `binary_ninja_headless_mcp`.
- Use command `python3` with args `["binary_ninja_headless_mcp.py"]` when `cwd` is the repo root, or use an absolute script path in `args`.
- Set `cwd` to the repo path if you want relative paths like `samples/ls` to resolve correctly.
- Use stdio transport unless your host requires TCP.
- For fake mode (no Binary Ninja installed), append `--fake-backend`.
- Verify connectivity by calling `health.ping`, then `session.open`.

## Docker Co-Location Pattern

Recommended deployment model: run the agent process and this MCP server in the same container image.

Example baseline:

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . /app
RUN python -m pip install --upgrade pip && pip install ruff pytest
CMD ["python3", "binary_ninja_headless_mcp.py"]
```

If you need real Binary Ninja analysis in-container, add your Binary Ninja runtime + license setup in this same image and start the agent with this MCP server configured.

## MCP Methods

- `initialize`
- `ping`
- `tools/list`
- `tools/call`
- `shutdown`

`tools/list` behavior:

- Without explicit pagination params, returns the full tool catalog.
- If `offset` or `limit` is provided, uses paginated output (`offset=0`, `limit=50` default in paged mode).
- Supports filtering via:
  - `prefix` (for example `binary.`)
  - `query` (substring match against tool name/description)
- Returns pagination metadata: `offset`, `limit`, `total`, `has_more`.
- When a page is truncated (`has_more=true`), includes `next_offset` and a `notice` hint.

Tool call response behavior:

- `structuredContent` is the canonical full payload.
- `content[0].text` is a compact summary string (not full JSON duplication).
- This split is intentional to keep context usage smaller while still exposing full machine-readable data.

## Quality And Testing

This repository is well tested and has enforced quality gates.

- Test suite: run `pytest --collect-only -q` for the current collected test count.
- CI workflow enforces:
  - `ruff format --check .`
  - `ruff check .`
  - `pytest`
- CI uses `BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND=1` so checks run without requiring Binary Ninja installation.
- Additional structural tests verify tool registry consistency and backend reachability.

## Context Controls

- Read-only mode is the default for opened sessions (`read_only=true`).
- `binary.basic_blocks_at` and `function.basic_blocks` are paginated (`offset`/`limit`).
- `memory.read` has a hard response cap: `length <= 65536`.

## Limitations

- Enterprise APIs are currently not covered.
- Debugger APIs are currently not covered.

## Security Model

- MCP communication (`stdio`/`tcp`) is unauthenticated by default.
- The server exposes arbitrary scripting via `binja.eval` and broad API access via `binja.call`.
- This is by design for trusted, containerized agent environments.
- Do not expose this server directly to untrusted users or networks.

## Local Dev Workflow

```bash
ruff format --check .
ruff check .
BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND=1 pytest -q
```

## Feature Fuzzer

Use the built-in MCP feature fuzzer to exercise a broad tool surface against `samples/ls`.

Real Binary Ninja backend:

```bash
python3 -m binary_ninja_headless_mcp.fuzzer --binary samples/ls --iterations 120 --seed 1337
```

Fake backend smoke run:

```bash
python3 -m binary_ninja_headless_mcp.fuzzer --binary samples/ls --fake-backend --allow-tool-errors --iterations 20
```

Write a JSON coverage report:

```bash
python3 -m binary_ninja_headless_mcp.fuzzer --binary samples/ls --report-json /tmp/mcp-fuzzer-report.json
```

Useful flags:

- `--min-success-tools N`: exits non-zero if fewer than `N` tools succeeded.
- `--verbose`: print each tool call while fuzzing.
- `--update-analysis`: open the seed session with `update_analysis=true`.

## Analysis and session lifecycle

`session.open`, `session.open_bytes`, and `session.open_existing` with
`update_analysis=true` return only after analysis finishes. `analysis.update_and_wait`
has the same synchronous contract. Neither switches to a task or partial result
on a timer. Sessions are registered before analysis; an analysis failure or
cancellation returns a tool error containing the retained `session_id` in both
structured data and compact text, so another call can inspect, retry, or close it.

`analysis.update` now returns a tracked task, just like `task.analysis_update`.
Poll `task.status` and fetch `task.result` when `result_ready` is true. All terminal
states (`completed`, `failed`, `cancelled`) have a result envelope; failed tasks
include `error`. A pending result request is a tool error. This is a deliberate
change from the earlier untracked `analysis.update` response.

Only one managed analysis may be queued, running, or cancelling per session.
Different sessions can analyze concurrently. `analysis.status` adds `status`,
start/completion timestamps, `last_analysis_task_id`, and `last_analysis_error` to
the existing native `state`, `progress`, `info`, and `is_aborted` fields. These
managed fields are compatible with Ghidra's lifecycle vocabulary; the native
progress fields remain Binary Ninja specific. `has_log` is false: there is no
fabricated Ghidra-style analysis log. Native updates triggered by edits or raw API
calls are visible in native progress but are not separate managed tasks.

Cancelling a queued task removes its analysis reservation without aborting the
view. Cancelling running analysis requests a native abort and retains ownership
until both analysis and abort finish. Once terminal, the session can analyze
again; the workflow suspended by our abort is resumed. Cancelling an old terminal
task has no effect on a later run. Running search tasks are best effort and drain
normally if already started.

An explicit `analysis.set_hold` or disabled workflow is preserved. Analysis returns
an actionable error while held or disabled; a normal native wait return only counts
as completion when the engine reports idle and is not aborted. Release the hold or
enable the workflow before retrying.
Explicit native control changes invalidate an overlapping managed run even if a
later control restores an idle state. New analysis requests are rejected while
control calls are still in flight. A later explicit workflow disable also
takes precedence over the automatic resume associated with an earlier cancellation.

Binary Ninja can mark interrupted initial analysis as finished before completing
function discovery. On retry, the server re-requests linear sweep when the view's
`analysis.linearSweep.autorun` setting permits it, preserving its configured
analysis mode. This recovery is retained until a managed analysis completes.
Native heuristics can still produce a different function set after interruption
in reduced analysis modes. Reopen the original input for an independent fresh
analysis when comparing results; completion means the requested native pass
finished, not proof that every possible function was discovered.

`loader.rebase` requires exclusive use of the session. It rejects active analysis
and other admitted operations; new native calls are rejected during replacement,
while status/list calls use cached metadata. Close waits for replacement to finish.
A rebased view keeps ownership of shared native file metadata, and view-specific
caches are reset. Raw evaluation also protects every session exposed in its context
from concurrent close for the duration of the evaluation.
Use the dedicated lifecycle/control tools for cancellation and rebasing; arbitrary
native calls can bypass managed coordination.

`session.close` prevents new operations, cancels work, and waits for admitted MCP
calls and background tasks before closing the view. Reopened upload sessions share
ownership of their temporary backing file; it is deleted after the last dependent
session closes, so closing a parent does not break its children.
This ownership is established before a reopened session becomes visible, including
while its initial analysis is still running.
If draining or aborting exceeds 30 seconds, it returns an error, retains the
resources in `closing` state, and permits a later `session.close` retry.
`analysis.status`, `session.list`, and task metadata remain available. Shutdown
uses one shared 30-second drain deadline; EOF and transport errors also perform
cleanup. The line-delimited stdio transport processes requests sequentially;
use asynchronous tasks for polling on that connection. A second TCP connection
can inspect or cancel a synchronous call on the first connection.

## Lifecycle verification

The dedicated stateful driver checks strict results and clean EOF shutdown over
an actual stdio subprocess, and fails on unexpected errors or timeouts:

```bash
python3 -m binary_ninja_headless_mcp.lifecycle_fuzzer \
  --binary samples/ls --seed 1337 --transitions 100 \
  --output-dir /tmp/binja-lifecycle-1337
BINJA_NATIVE_TEST_BINARY="$PWD/samples/ls" \
  python3 -m pytest tests/test_transport_lifecycle.py
```

Use a fresh output directory per run. The driver preserves the input, writes a
checkpoint database, incremental request/response trace, progress, stderr, input
hash, engine version, and final report. `--timeout` sets the external response/task
watchdog (default 300 seconds); a timeout fails verification. To run additional
seeds on a large binary, `--analysis-database /path/to/checkpoint.bndb` reuses a
completed analysis in a private copy and records the database hash.
`--load-options '{"analysis.limits.cacheSize":64}'` passes explicit native settings
and records them in the report; neither driver changes product defaults. No native
license is needed for `--fake-backend` smoke runs or deterministic lifecycle race tests.

The broad feature fuzzer excludes plugin execution and repository modification
from live runs; these actions have tests using doubles. `--trace-jsonl` preserves
calls incrementally. It reports an unavailable debug parser explicitly. Its default
exit status fails on all unexpected tool errors; `--allow-tool-errors` is for
exploratory diagnostics and is not a correctness gate. Run it on a disposable copy
when exercising writes. The feature fuzzer also accepts `--load-options` and
`--analysis-database`: it copies the database privately and separately probes raw
byte loading without repeating initial analysis.

## Feature Catalog

The server currently exposes `181` tools across `36` feature groups.

### analysis
- `analysis.status`: Get managed lifecycle status/timestamps/task/error plus native state and progress.
- `analysis.progress`: Get analysis progress snapshot.
- `analysis.update`: Start tracked analysis; returns task_id. Rejects overlapping runs on this session.
- `analysis.update_and_wait`: Wait synchronously until analysis finishes; no timed partial-success response.
- `analysis.abort`: Abort analysis.
- `analysis.set_hold`: Hold/release analysis queue.

### annotation
- `annotation.rename_function`: Rename a function.
- `annotation.rename_symbol`: Rename symbol at address.
- `annotation.undefine_symbol`: Undefine user symbol at address.
- `annotation.define_symbol`: Define symbol at address.
- `annotation.rename_data_var`: Rename data variable.
- `annotation.define_data_var`: Define data variable.
- `annotation.undefine_data_var`: Undefine data variable.
- `annotation.set_comment`: Set comment at address.
- `annotation.get_comment`: Get comment at address.
- `annotation.add_tag`: Add user data tag at address.
- `annotation.get_tags`: Get tags at address.

### arch
- `arch.info`: Get architecture and platform metadata.
- `arch.disasm_bytes`: Disassemble bytes with selected architecture.
- `arch.assemble`: Assemble instruction text with selected architecture.

### baseaddr
- `baseaddr.detect`: Run base-address detection.
- `baseaddr.reasons`: Get base-address detection reasons.
- `baseaddr.abort`: Abort base-address detection.

### binary
- `binary.summary`: Get binary/session summary.
- `binary.save`: Save the current binary view to a file path.
- `binary.functions`: List functions with pagination.
- `binary.strings`: List discovered strings with pagination.
- `binary.search_text`: Search raw text/bytes in a session.
- `binary.sections`: List sections with pagination.
- `binary.segments`: List segments with pagination.
- `binary.symbols`: List symbols with pagination.
- `binary.data_vars`: List data variables with pagination.
- `binary.get_function_at`: Find function by address.
- `binary.get_function_disassembly_at`: Get full disassembly for function containing an address.
- `binary.get_function_il_at`: Get full IL for function containing an address.
- `binary.functions_at`: List functions at an address.
- `binary.basic_blocks_at`: List basic blocks at an address with pagination.

### binja
- `binja.info`: Return Binary Ninja version/install info.
- `binja.call`: Generic API bridge: call `bn.*` or `bv.*` target path.
- `binja.eval`: Evaluate Python code with `bn`, `sessions`, and optional `bv`.

### data
- `data.typed_at`: Get typed data variable at an address.

### database
- `database.create_bndb`: Create .bndb from session.
- `database.save_auto_snapshot`: Save auto snapshot.
- `database.info`: Get database status for session.
- `database.snapshots`: List database snapshots.
- `database.read_global`: Read database global string key.
- `database.write_global`: Write database global string key.

### debug
- `debug.parsers`: List debug info parsers valid for this view.
- `debug.parse_and_apply`: Parse debug info and apply it to the view.

### disasm
- `disasm.linear`: Get linear disassembly lines.
- `disasm.function`: Get full disassembly for function containing an address.
- `disasm.range`: Address-range disassembly lines.

### external
- `external.library_add`: Add external library.
- `external.library_list`: List external libraries.
- `external.library_remove`: Remove external library.
- `external.location_add`: Add external location mapping.
- `external.location_get`: Get external location mapping.
- `external.location_remove`: Remove external location mapping.

### function
- `function.basic_blocks`: List basic blocks in a function with pagination.
- `function.callers`: Callers of a function.
- `function.callees`: Callees of a function.
- `function.variables`: List function variables.
- `function.var_refs`: List variable references in MLIL/HLIL.
- `function.var_refs_from`: List variable references originating from an address.
- `function.ssa_var_def_use`: Get SSA variable definition and uses.
- `function.ssa_memory_def_use`: Get SSA memory definition and uses by memory version.
- `function.metadata_store`: Store function metadata by key.
- `function.metadata_query`: Query function metadata by key.
- `function.metadata_remove`: Remove function metadata by key.

### health
- `health.ping`: Health check.

### il
- `il.function`: IL function listing.
- `il.instruction_by_addr`: Get IL instruction by source address.
- `il.address_to_index`: Map address to IL index/indices.
- `il.index_to_address`: Map IL index to source address.
- `il.rewrite.capabilities`: List IL rewrite support for one function and IL level.
- `il.rewrite.noop_replace`: Perform no-op IL expression replacement.
- `il.rewrite.translate_identity`: Translate IL with identity mapping callback.

### loader
- `loader.rebase`: Rebase BinaryView.
- `loader.load_settings_types`: List loader settings type names.
- `loader.load_settings_get`: Get loader settings values.
- `loader.load_settings_set`: Set one loader setting value.

### memory
- `memory.read`: Read bytes from the view (`length <= 65536`).
- `memory.write`: Write bytes (hex) to the view.
- `memory.insert`: Insert bytes (hex) into the view.
- `memory.remove`: Remove bytes from the view.
- `memory.reader_read`: Read integer values via BinaryReader.
- `memory.writer_write`: Write integer values via BinaryWriter.

### mcp
- `mcp.response_format`: Explain tool result fields (`structuredContent` full payload, `content[0].text` summary).

### metadata
- `metadata.store`: Store metadata by key.
- `metadata.query`: Query metadata by key.
- `metadata.remove`: Remove metadata by key.

### patch
- `patch.assemble`: Assemble and patch instruction bytes at address.
- `patch.status`: Inspect patch availability at address.
- `patch.convert_to_nop`: Patch instruction to NOP when supported.
- `patch.always_branch`: Patch conditional branch to always branch when supported.
- `patch.never_branch`: Patch conditional branch to never branch when supported.
- `patch.invert_branch`: Patch conditional branch by inversion when supported.
- `patch.skip_and_return_value`: Patch instruction to skip and return value when supported.

### plugin
- `plugin.valid_commands`: List context-valid plugin commands.
- `plugin.execute`: Execute a context-valid plugin command.

### plugin_repo
- `plugin_repo.status`: List plugin repositories and plugin states.
- `plugin_repo.check_updates`: Check plugin repository updates.
- `plugin_repo.plugin_action`: Run install/uninstall/enable/disable action on repository plugin.

### project
- `project.create`: Create project.
- `project.open`: Open project.
- `project.close`: Close tracked project.
- `project.list`: List project folders/files.
- `project.create_folder`: Create project folder.
- `project.create_file`: Create project file from base64 data.
- `project.metadata_store`: Store project metadata.
- `project.metadata_query`: Query project metadata.
- `project.metadata_remove`: Remove project metadata.

### search
- `search.data`: Search for raw byte patterns (hex string).
- `search.next_text`: Find next text match.
- `search.all_text`: Find all text matches in range (regex optional).
- `search.next_data`: Find next data/byte-pattern match.
- `search.all_data`: Find all data/byte-pattern matches in range.
- `search.next_constant`: Find next constant occurrence.
- `search.all_constant`: Find all constant occurrences in range.

### section
- `section.add_user`: Add user section.
- `section.remove_user`: Remove user section.

### segment
- `segment.add_user`: Add user segment.
- `segment.remove_user`: Remove user segment.

### session
- `session.open`: Open a binary and create a session.
- `session.open_bytes`: Open a binary session from base64-encoded bytes.
- `session.open_existing`: Open another session from an existing session's file.
- `session.close`: Close one open session.
- `session.list`: List open sessions.
- `session.mode`: Get session safety/determinism mode.
- `session.set_mode`: Update session safety/determinism mode.

### task
- `task.analysis_update`: Alias of analysis.update: start tracked analysis and return task_id.
- `task.search_text`: Start async search task.
- `task.status`: Get task status.
- `task.result`: Get a completed, failed, or cancelled result envelope; pending tasks return an error.
- `task.cancel`: Request cancellation. Terminal tasks are unchanged; running analysis drains before reuse.

### transform
- `transform.inspect`: Inspect/process transform extraction pipeline. For a session input, the root context is retained in the selected contexts so temporary transform cleanup preserves the session's view.

### type
- `type.parse_string`: Parse a single type string.
- `type.parse_declarations`: Parse C declarations for types/variables/functions.
- `type.define_user`: Define user type from type source.
- `type.rename`: Rename a type.
- `type.undefine_user`: Undefine a user type.
- `type.import_library_type`: Import type from type library.
- `type.import_library_object`: Import object type from type library.
- `type.export_to_library`: Export type into a type library.

### type_archive
- `type_archive.create`: Create and optionally attach a type archive.
- `type_archive.open`: Open and optionally attach a type archive.
- `type_archive.list`: List attached type archives.
- `type_archive.get`: Get one tracked type archive.
- `type_archive.pull`: Pull types from a type archive.
- `type_archive.push`: Push types to a type archive.
- `type_archive.references`: Query archive incoming/outgoing references for one type.

### type_library
- `type_library.create`: Create and optionally attach a type library.
- `type_library.load`: Load and optionally attach a type library.
- `type_library.list`: List type libraries attached to the view.
- `type_library.get`: Get one tracked type library.

### uidf
- `uidf.parse_possible_value`: Parse user-informed possible value set string.
- `uidf.set_user_var_value`: Set function user variable value.
- `uidf.clear_user_var_value`: Clear function user variable value.
- `uidf.list_user_var_values`: List all user variable values for a function.

### undo
- `undo.begin`: Begin undo transaction.
- `undo.commit`: Commit undo transaction.
- `undo.revert`: Revert undo transaction.
- `undo.undo`: Perform undo.
- `undo.redo`: Perform redo.

### value
- `value.reg`: Get register value at/after an address.
- `value.stack`: Get stack contents at/after an address.
- `value.possible`: Get IL possible value set at an address.
- `value.flags_at`: Get lifted IL flag read/write state at an address.

### workflow
- `workflow.list`: List registered workflows.
- `workflow.describe`: Describe workflow topology and settings.
- `workflow.clone`: Clone workflow.
- `workflow.insert`: Insert activities before an activity.
- `workflow.insert_after`: Insert activities after an activity.
- `workflow.remove`: Remove workflow activity.
- `workflow.graph`: Summarize workflow graph.
- `workflow.machine.status`: Get workflow machine status.
- `workflow.machine.control`: Control workflow machine runtime.

### xref
- `xref.code_refs_to`: Code references to an address.
- `xref.code_refs_from`: Code references from an address.
- `xref.data_refs_to`: Data references to an address.
- `xref.data_refs_from`: Data references from an address.

## Contact

For more information, contact Tim Blazytko ([@mr_phrazer](https://x.com/mr_phrazer)).
