# Binary Ninja CLI command reference

`binja_cli` (also `binja-cli`) exposes the complete Binary Ninja Headless MCP tool
catalog to shells and agents. Its verbs, schema-derived flags, JSON escapes, output
selection, and persistent-server workflow follow Ghidra's `ghidra_cli`. Calls use
the same `SimpleMcpServer.handle_request` dispatch path as MCP.

The [complete generated tool reference](#tool-reference) includes every input
schema and effective server default. `list` and `describe` work offline without a
Binary Ninja installation or license.

## Installation and invocation

Python 3.11 or newer is required. Install from the repository root:

```bash
python3 -m pip install .
binja_cli --help
binja-cli --version
```

Run directly from a checkout without installing:

```bash
python3 -m binary_ninja_headless_mcp.binja_cli list --names-only
```

Real analysis additionally requires a headless-capable Binary Ninja license and
the `binaryninja` module importable by the same Python interpreter. Use the runtime's
normal Python API/license setup. There is no Ghidra installation argument or JVM.
The existing `binary_ninja_headless_mcp` and `binary-ninja-headless-mcp` launchers
still start the MCP server; they are not aliases for this client.

This discovery and health sequence needs no Binary Ninja runtime:

<!-- smoke: offline -->
```bash
binja_cli list --prefix session. --names-only
binja_cli describe session.open
binja_cli --fake-backend call health.ping
```

The fake backend is for client development and tests. It does not establish that
native analysis, plugins, databases, or other Binary Ninja operations work.

## Transports and session state

An in-process invocation creates its own backend and disposes of it on exit.
A session ID returned by one in-process command cannot be reused by another
process. Use an in-process `batch` for a self-contained sequence, or a persistent
server for interactive work spanning commands.

Transport selection is:

1. Explicit `--in-process` or `--fake-backend` selects local execution, overriding
   environment connection settings. Combining either with explicit `--connect`
   is an error.
2. Otherwise `--connect HOST:PORT`, then `BINJA_CLI_CONNECT`, selects a remote server.
3. Otherwise a verified live managed server is selected automatically.
4. Otherwise a real in-process backend is created.

`list`, `tools`, `describe`, help, and version do not initialize an analysis runtime.
An explicit remote connection failure is reported; it does not silently switch to
a new local backend. The selected backend determines whether analysis is real or fake.
The server's development variable `BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND=1` also
selects fake backend construction; leave it unset for native verification.

### Persistent native workflow

Start the managed server once, then reuse it. Paths are resolved by the server;
use absolute paths when the server's working directory may differ from the client.

```bash
binja_cli server start
SID=$(binja_cli --field session_id call session.open --path /bin/ls)
binja_cli --session-id "$SID" call binary.functions --limit 5
binja_cli call session.close --session-id "$SID"
binja_cli server stop
```

Set `export BINJA_CLI_SESSION="$SID"` to supply a default session to subsequent
calls. A global `--session-id` overrides the environment default; a tool's explicit
`--session-id` or JSON `session_id` overrides both. Session IDs belong to a specific
server lifetime. Reopening a saved database creates a new session ID.

### Existing TCP server

In one terminal start the existing MCP server:

```bash
python3 -m binary_ninja_headless_mcp --transport tcp --host 127.0.0.1 --port 8765
```

In another terminal:

```bash
binja_cli --connect 127.0.0.1:8765 call health.ping
export BINJA_CLI_CONNECT=127.0.0.1:8765
binja_cli call session.list
```

The remote client uses newline-delimited JSON-RPC over TCP. It validates protocol
initialization, server identity, and response IDs. Connection/initialization checks
are bounded; ordinary tool responses wait for completion unless `--timeout` is set.
A client timeout does not imply the server cancelled an operation. Inspect session
or task state before retrying a mutation.

## Global options

Place global options **before the verb**. After `call TOOL`, flags are tool arguments.

| Option | Meaning |
| --- | --- |
| `--connect HOST:PORT` | Connect to an existing TCP MCP server. |
| `--in-process` | Force a fresh local backend for this invocation. |
| `--fake-backend` | Force a local fake backend; also selects a fake managed worker for `server start`. |
| `--timeout SECONDS` | Positive finite remote response timeout; default is unlimited. |
| `--session-id ID` | Default session for tools accepting `session_id`; otherwise `BINJA_CLI_SESSION`. |
| `--raw` | For `call`, print the full tool-result envelope. |
| `--quiet` | For `call`, print only the first summary text. |
| `--field DOTPATH` | For `call`, print one value from `structuredContent`. |
| `--version` | Print the client package version and exit. |
| `--help` | Show command help; each verb also supports `--help`. |

`--raw`, `--quiet`, and `--field` are mutually exclusive. Batch and raw-method
output have their own fixed formats and do not use these output selectors.

## Verbs

### `call TOOL [--parameter VALUE ...]`

Invoke any tool from the catalog. Required fields and flag spellings come from its
schema; omitted optional arguments remain omitted when sent to the server.

```bash
binja_cli --session-id "$SID" call binary.functions --offset 0 --limit 20
binja_cli --raw call health.ping
```

### `list` and `tools`

These aliases list the local catalog. Options: `--prefix PREFIX`, `--query TEXT`
(case-insensitive name/description substring), `--offset N`, `--limit N`, and
`--names-only`. JSON output includes `total`, `offset`, `count`, and `tools`.
`total` counts filtered tools before pagination.

```bash
binja_cli tools --query workflow
binja_cli list --prefix function. --offset 0 --limit 5
```

### `describe TOOL`

Print `name`, `description`, the full `inputSchema`, `required`, `properties`, and
effective `defaults`. These are local definitions; use `raw tools/list` to inspect
the catalog of a separately installed remote server when investigating version skew.

```bash
binja_cli describe workflow.machine.control
```

### `raw METHOD [--params JSON | --params-stdin] [--yes]`

Send an MCP method without schema coercion or session injection. The output is the
method's JSON-RPC **result**, not the outer response envelope. Methods include
`initialize`, `ping`, `tools/list`, `tools/call`, and `shutdown`. Sending `shutdown`
requires `--yes` because it drains a shared backend. Prefer `server stop` for a
managed worker: it also verifies that the owned process and listener terminate.

```bash
binja_cli raw tools/list --params '{"prefix":"memory.","offset":0,"limit":10}'
printf '%s\n' '{"name":"health.ping","arguments":{}}' | binja_cli raw tools/call --params-stdin
```

`raw --params` accepts a literal JSON object; unlike `call --json`, it does not
interpret `@file`. Use `--params-stdin < params.json` for files.

### `batch [FILE|-] [--continue-on-error] [--no-autosession] [--close-after]`

Read one JSON object per nonblank line, in order, using one backend/connection:

```json
{"tool":"session.open","arguments":{"path":"/bin/ls"}}
{"tool":"binary.functions","arguments":{"limit":5}}
```

`name` is an alias for `tool`, and `args` is an alias for `arguments`. Values are
already JSON: there is no flag coercion or `@file` expansion inside a batch object.
The file defaults to stdin (`-`). A successful session result becomes the default
session for subsequent calls that omit `session_id`; explicit IDs take precedence.
`--no-autosession` disables this automatic session injection. An explicit session
close clears that session as the current automatic choice.

The default is fail-fast. `--continue-on-error` continues after line/tool failures
and still returns a nonzero overall status. Each output line includes the input
`line` number and `tool`, plus `isError`/`structuredContent` or an `error` record.
`--close-after` closes sessions successfully opened by the batch, even on a later
failure or with `--no-autosession`. It does not close a session merely borrowed
through a default or explicit ID. Cleanup failures are reported and make the batch fail.

This executable demonstration uses fake analysis and cleans up its own session:

<!-- smoke: fake-batch -->
```bash
printf '%s\n' \
  '{"tool":"session.open","arguments":{"path":"/bin/ls"}}' \
  '{"tool":"binary.functions","arguments":{"limit":5}}' \
  | binja_cli --fake-backend batch - --close-after
```

Remove `--fake-backend` and add `--in-process` to run the same sequence in one
licensed runtime without a persistent server. For native files larger than this
example, analysis can take time; the default waits for it to complete.

### `server start|stop|status|restart [--host HOST] [--port PORT] [--fake-backend]`

Manage one worker per `BINJA_CLI_HOME`. The default address is `127.0.0.1:8766`;
Ghidra and the standalone MCP server commonly use 8765, so these defaults coexist.
The managed implementation requires Linux `/proc` process identity and Unix file
locking. Explicit TCP and in-process use do not require managed process control.

```bash
binja_cli --fake-backend server start --port 8766
binja_cli server status
binja_cli call health.ping
binja_cli server stop
```

`start` is idempotent for an already verified worker. `restart` stops the worker,
then starts it using the supplied host, port, and backend options; repeat custom
options when restarting. Lifecycle operations are locked. State is atomically
written and records process identity, preventing PID reuse from targeting another
process. A listener on the requested port is never adopted as an owned server.

`BINJA_CLI_HOME` overrides the state directory. Otherwise it is
`$XDG_RUNTIME_DIR/binja_cli`, or `~/.cache/binja_cli` if that variable is unset.
The directory must be private to its owner (mode `0700`); its `server.json`,
`server.lock`, and `server.log` hold state, locking, and worker diagnostics.
Use a separate private directory and port for isolated simultaneous workers.
Unverifiable live state and failed cleanup remain visible for inspection/retry.

## Argument syntax and coercion

Tool flags accept `--key value` and `--key=value`. Dashes and underscores are
equivalent in flag names (`--session-id` and `--session_id`); JSON keys must use the
schema's exact spelling. Values beginning with `--` need the equals form.

| Schema type | CLI form | Behavior |
| --- | --- | --- |
| String | `--name main` | Preserve the string. |
| Integer | `--limit 20`, `--limit 0x20` | Decimal unless prefixed with `0x`, `0o`, or `0b`; signed values supported. |
| Number | `--value:float 1.5` | Finite floating point value. |
| Boolean | `--read-only`, `--read-only false` | Bare flag means true; accepts true/false, yes/no, on/off, 1/0. |
| Address union | `--address 0x401000`, `--address 4096` | Preserve text for Binary Ninja's parser: bare digits are **decimal**, unlike Ghidra's CLI. |
| Array | `--names first --names second` | Append one item per occurrence, using the declared item type. |
| Object | `--kwargs '{"key":1}'` | Parse a JSON object. |
| Unconstrained value | `--value 5` | Preserve text; use a typed override for a JSON number/object. |

Typed overrides are `:str`, `:int`, `:float`, `:bool`, `:json`, and `:null`:

```bash
binja_cli --session-id "$SID" call memory.read --address:int 4096 --length 16
binja_cli --session-id "$SID" call binja.call --target bv.read --args:json '[4096,16]'
```

These examples assume address 4096 is mapped in the current view; use addresses
returned by the binary/function tools for other binaries. `--key:null` supplies an
explicit JSON null; use it only where the receiving operation accepts null. A
documented omission default of null does not make null valid for every schema.
Nonfinite numeric values (`NaN`, `Infinity`) are rejected.

`workflow.machine.control.activities` accepts either string or array: one ordinary
`--activities NAME` supplies a string, repeated flags supply an array, and
`--activities:json '["NAME"]'` preserves that exact JSON array. Use `:json` for any
whole-array argument; an ordinary array flag adds a single element.

### Full JSON, files, and stdin

`--json '{...}'`, `--json @args.json`, and `--json-stdin` supply a base argument
object. Individual flags override the corresponding JSON properties regardless
of ordering. Repeated ordinary array flags build their own replacement array;
they do not append to an array in the base JSON object.

```bash
binja_cli --session-id "$SID" call binary.functions --json '{"offset":0,"limit":20}' --limit 5
printf '%s\n' '{"offset":0,"limit":5}' | binja_cli --session-id "$SID" call binary.functions --json-stdin
```

For any flag value, `@PATH` reads a UTF-8 file, and `-` reads stdin. Stdin is read
once and reused if requested again in that invocation. To send a literal value
starting with `@` or equal to `-`, put it inside a full JSON argument object.

### Native Python bridge

`binja.call` invokes a `bn.*` or `bv.*` API target; `binja.eval` evaluates Python
with `bn`, `sessions`, and an optional session's `bv`. The code bridge exposes
capabilities beyond the named tools and runs inside the backend process.

```bash
binja_cli call binja.call --target bn.core_version
binja_cli --session-id "$SID" call binja.eval --code 'len(bv.functions)'
printf '%s\n' 'len(bv.functions)' | binja_cli --session-id "$SID" call binja.eval --code -
```

For a saved script, use `binja_cli --session-id "$SID" call binja.eval --code @inspect.py`.
Inspect returned structured data when using multi-statement code; do not assume
it is formatted like an interactive Python terminal. An expression returns its
value as `result`; multi-statement code returns the value assigned to `_` (or null).
Captured output appears as `stdout`/`stderr` when nonempty.

The Python bridge transitions affected read-only sessions to writable mode before
execution, even for an expression that only reads state. `binja.eval` without a
session can affect all currently open sessions. Inspect `mode_transitioned` and
`transitioned_session_ids` in the response; named read tools avoid this transition.

## Mutation and persistence

Sessions open read-only and deterministic by default. Open with
`--read-only false` for intended edits, or explicitly change the session mode.
Use private binary copies and output paths when preserving the original matters.
Tools enforce their backend's mutation policy; unrestricted Python execution is
not a sandbox and must only receive trusted code.

For multi-step undoable edits, call `undo.begin`, perform the edits, and then
`undo.commit` with the returned transaction ID, or `undo.revert` to discard them.
`undo.undo`/`undo.redo` operate on committed undo history. `binary.save` writes
binary bytes; `database.create_bndb` writes an analysis database. Reopen saved artifacts
and read back the affected bytes/types/names to verify persistence.

### Workflow controls and plugin actions

`workflow.machine.control` dispatches these action strings (case-insensitive):

| Action | Additional arguments and behavior |
| --- | --- |
| `run`, `resume` | Use `advanced` (default true) and `incremental` (default false). |
| `halt`, `reset`, `enable`, `disable` | Control the selected native workflow machine. |
| `dump` | Return diagnostic machine state; inspect the provenance fields described below. |
| `breakpoint_set`, `breakpoint_delete` | `activities` accepts one activity string or an array. |
| `override_set` | Requires `activity` and `enable` (including explicit false). |
| `override_clear` | Requires `activity`. |

Use `workflow.describe` to discover valid activities for the selected workflow and
`workflow.machine.status` to verify state. Unsupported or native-rejected control
actions fail. On runtimes that reject the native `dump` command, the tool instead
returns a diagnostic snapshot assembled from accepted native state queries and
workflow configuration. `dump_source` distinguishes `native_command` from
`native_state_snapshot`; the latter includes `dump_snapshot` and preserves the
original rejected native response in `command_result`. This snapshot is not a
claim that the native dump command was accepted.

`plugin_repo.plugin_action` accepts `install`, `uninstall`, `enable`, and `disable`.
Discover repository/plugin identifiers with `plugin_repo.status` before acting.
Inspect `installed`, `enabled`, `disable_pending`, and `delete_pending` in results:
some changes take effect after restarting the Binary Ninja runtime. The `changed`
field describes the immediate action result, not proof that deferred cleanup has
finished. Repository refresh/update and installation can access the network.

`plugin.execute` needs a registered command and a context valid for that command
(default, address, or range). `executed: true` means native execution returned
without an explicit failure after context validation; verify the command's
intended effect separately. A native API returning Python `None` is normal for
successful command execution.

### Base-address detection

`baseaddr.detect` accepts `--algorithm instruction` (the unchanged default) or
`--algorithm sampling`. Both invoke Binary Ninja's native detector; sampling
requires a runtime exposing `detect_base_address_with_sampling`. An older runtime
without that API returns an error when sampling is explicitly requested.

| Parameters | `instruction` | `sampling` |
| --- | --- | --- |
| `arch_name`, `min_strlen`, `low_boundary`, `high_boundary` | Forwarded to the native detector. | Forwarded to the native sampling detector. |
| `analysis`, `alignment`, `max_pointers` | Forwarded to the native detector. | Instruction-only options; nondefault values are rejected. Omit these for sampling. |

The result identifies the selected `algorithm` and includes `detected`,
`preferred_base_address`, `confidence`, `scores`, `score_count`, and `aborted`.
A successful call does not guarantee that a candidate base was found. Inspect
`detected` and the candidate evidence before applying a rebase. Instruction
analysis can be expensive; sampling is a distinct algorithm, not a timeout or
automatic fallback for instruction analysis.

For a raw AArch64 view containing strings and pointers into an image expected near
`0x400000`, a bounded sampling request is:

```bash
binja_cli --session-id "$SID" call baseaddr.detect --algorithm sampling --arch-name aarch64 --min-strlen 10 --low-boundary 0x400000 --high-boundary 0x410000
binja_cli --session-id "$SID" call baseaddr.reasons --base-address 0x400000
```

Choose architecture and boundaries for the actual input; this example is not a
claim that an arbitrary binary uses that base. `baseaddr.reasons` queries a
candidate from the most recent detection context in the same session.
`baseaddr.abort` targets that detector context. Keep the session on a persistent
server or within one batch so the context remains available.

## Output and exit codes

`call` prints canonical `structuredContent` as JSON by default. `--raw` prints the
tool envelope containing `content`, `structuredContent`, and `isError`; it is
distinct from the `raw` verb. `--quiet` prints the summary. `--field` traverses
dot-separated object keys and numeric array indexes, for example `items.0.name`.
String fields print without JSON quotes; objects/arrays print JSON. Missing fields
are errors, not empty success output. Diagnostics go to stderr.

| Exit status | Meaning |
| --- | --- |
| `0` | Successful invocation. |
| `1` | Tool/backend failure, including a tool result with `isError`. |
| `2` | Usage, protocol, argument parsing, or transport failure. |

In a batch, the overall exit status reflects the most severe encountered failure,
including cleanup. Selecting a field does not turn a tool error into success.

## Security and troubleshooting

The TCP analysis endpoint has **no authentication or encryption**. `binja.eval`,
the API bridge, plugins, and writable operations can execute code or change files
with the backend user's permissions. Bind to loopback (the default) and trust
clients with local access. Changing `--host` to a public interface exposes these
capabilities. Managed lifecycle identity tokens protect ownership checks, not
the general analysis endpoint. Prefer `@file`/stdin for code or secrets that should
not appear in argument listings or shell history.

| Symptom | Check or action |
| --- | --- |
| Missing `binaryninja` or license error | Verify the same Python interpreter can import the API and initialize its licensed core; inspect `server.log`. |
| Session is missing | Confirm the selected server and avoid reusing an in-process or pre-restart ID. |
| Mutation rejected | Inspect `session.mode`; enable writable mode deliberately. |
| Tool or parameter missing remotely | Compare local `describe` with remote `raw tools/list`; install matching client/server versions. |
| Startup says address in use | Use another port or stop the process that owns it; an unrelated listener is not adopted. |
| Managed directory rejected | Set a private owned `BINJA_CLI_HOME` or fix directory mode to `0700`. |
| Corrupt/unverifiable managed state | Inspect the retained state/log and process identity; do not delete state while an owned worker may still be running. |
| Remote timeout | Inspect backend operation/task state before repeating work; increase or omit `--timeout`. |
| A bare numeric address is unexpected | Binary Ninja uses decimal bare digits; use an explicit `0x` prefix for hex. |

## Verification and reference maintenance

Regenerate only the marked tool-reference section from the offline shared catalog:

```bash
python3 -m binary_ninja_headless_mcp.cli_docs
python3 -m binary_ninja_headless_mcp.cli_docs --check
python3 -m pytest tests/test_binja_cli_docs.py
```

`--path PATH` selects a different document. `--check` does not write files and
returns failure when schemas, tool membership, descriptions, or defaults drift.
Documentation tests execute the marked offline/fake examples and verify every
generated schema and default. Native correctness requires a licensed runtime and
the repository's live coverage harness: inspect its actual report, fixture hashes,
runtime version, transport coverage, and readback evidence. Fake success and a
catalog count alone do not establish native feature coverage.

### Native semantic verifier

From a source checkout with a licensed Binary Ninja runtime and a C compiler, run
the complete transport/argument matrix into a new evidence directory:

```bash
python3 -m binary_ninja_headless_mcp.cli_verify --output ./analysis/cli-verification --mode both --argument-style both --tcp-process-mode subprocess
```

The verifier compiles its controlled fixture unless `--binary PATH` supplies a
previously compiled version of that fixture. An arbitrary application is not a
substitute: assertions rely on known fixture functions, strings, and types.
`--compiler COMPILER` selects the compiler. The output directory must be absent or
empty; previous evidence is not overwritten. Each selected matrix cell runs in a
fresh process with an isolated Binary Ninja user directory.

| Option | Use |
| --- | --- |
| `--mode inprocess\|tcp\|both` | Choose backend transport coverage; default `both`. |
| `--argument-style json\|flags\|both` | Choose JSON-object or schema-derived-flag invocation; default `both`. |
| `--tcp-process-mode worker\|subprocess` | Reuse an isolated CLI worker (default) or launch a separate CLI process for each TCP call. Use `subprocess` for per-invocation process coverage. |
| `--timeout SECONDS` | Harness timeout, default 180 seconds; independent of the product CLI's unlimited default tool-response wait. |
| `--groups LIST` | Select diagnostic groups; the full default is `core,reads,mutations,database,rewrites,baseaddr,stateful,special`. |
| `--without-special` | Omit isolated native plugin/repository verification; omitted coverage remains incomplete. |

Inspect top-level `summary.json`, per-cell `coverage.json`, and incremental
invocation/assertion evidence. A tool is verified only when successful calls have
explicit semantic assertions and all required variants are present. The reports
retain missing/failed tools, missing variants, input SHA-256, and source hashes.
The matrix rejects changed source or input identity and missing/duplicate cells.
Exit zero requires the requested matrix to be complete; selecting diagnostic
groups or omitting special fixtures does not turn missing tools into success.

This verifier records a concrete tested runtime, source revision, fixture, and
selected matrix. Its result does not establish compatibility with every Binary
Ninja version, operating system, architecture, plugin, or input binary. Preserve
the report and readback artifacts alongside any claim of coverage.

## Relationship to Ghidra's CLI

The command verbs, global-option placement, schema-derived flags, typed overrides,
JSON/file/stdin input, output selectors, exit statuses, autosession batches, and
managed-server workflow intentionally follow `ghidra_cli`. Binary Ninja uses its
own complete MCP catalog, so tool names and runtime semantics remain native.

| Area | Binary Ninja behavior |
| --- | --- |
| Session tools | `session.open`, `session.open_bytes`, `session.open_existing`, and `session.close`; Ghidra workflows commonly use `program.*`. |
| Address strings | Bare digits are decimal; use `0x` for hex. Ghidra's client documents bare-digit addresses as hexadecimal. |
| Runtime setup | Importable licensed `binaryninja`; no `--ghidra-install-dir` option or JVM. Determinism is a session argument rather than a CLI-wide startup flag. |
| Environment and port | `BINJA_CLI_CONNECT`, `BINJA_CLI_SESSION`, `BINJA_CLI_HOME`; managed default port 8766. |
| Conflicting transport flags | Explicit `--connect` with `--in-process` or `--fake-backend` fails instead of silently selecting one. |
| Native feature surface | Binary Ninja IL, workflows, plugins, archives, and both base-detection algorithms follow their MCP schemas and native API behavior. |
| Managed ownership | Private, locked state and verified Linux process identity; start/stop checks ownership and cleanup completion. |

## Tool reference

<!-- BEGIN GENERATED TOOL REFERENCE -->
The catalog contains **181 tools across 36 groups**.

Every entry is callable with `binja_cli call TOOL`. The full JSON schema below
preserves unions, enums, required fields, and additional schema constraints.
Effective defaults describe server behavior when a property is omitted; the CLI
does not inject these values. An omitted property absent from the defaults map
has no cataloged default. JSON `null` in a defaults map describes omission behavior
and does not imply that explicit null is accepted by the property's schema.

Groups: [analysis](#analysis-tools) · [annotation](#annotation-tools) · [arch](#arch-tools) · [baseaddr](#baseaddr-tools) · [binary](#binary-tools) · [binja](#binja-tools) · [data](#data-tools) · [database](#database-tools) · [debug](#debug-tools) · [disasm](#disasm-tools) · [external](#external-tools) · [function](#function-tools) · [health](#health-tools) · [il](#il-tools) · [loader](#loader-tools) · [mcp](#mcp-tools) · [memory](#memory-tools) · [metadata](#metadata-tools) · [patch](#patch-tools) · [plugin](#plugin-tools) · [plugin_repo](#plugin_repo-tools) · [project](#project-tools) · [search](#search-tools) · [section](#section-tools) · [segment](#segment-tools) · [session](#session-tools) · [task](#task-tools) · [transform](#transform-tools) · [type](#type-tools) · [type_archive](#type_archive-tools) · [type_library](#type_library-tools) · [uidf](#uidf-tools) · [undo](#undo-tools) · [value](#value-tools) · [workflow](#workflow-tools) · [xref](#xref-tools)

### analysis tools

#### `analysis.abort`

Abort analysis.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `analysis.progress`

Get analysis progress snapshot.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `analysis.set_hold`

Hold/release analysis queue.

```json
{
  "properties": {
    "hold": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "hold"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `analysis.status`

Get lifecycle status, timestamps, task and error, plus native state/progress.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `analysis.update`

Start tracked analysis and return task_id; reject overlap on this session.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `analysis.update_and_wait`

Wait synchronously until analysis finishes; no timed partial-success response.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### annotation tools

#### `annotation.add_tag`

Add user data tag at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "data": {
      "type": "string"
    },
    "icon": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "tag_type": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "tag_type",
    "data"
  ],
  "type": "object"
}
```

Effective defaults: `{"icon": "M"}`.

#### `annotation.define_data_var`

Define data variable.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_name": {
      "type": "string"
    },
    "width": {
      "minimum": 1,
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"name": null, "type_name": "char", "width": 1}`.

#### `annotation.define_symbol`

Define symbol at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "symbol_type": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"symbol_type": "FunctionSymbol"}`.

#### `annotation.get_comment`

Get comment at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.get_tags`

Get tags at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.rename_data_var`

Rename data variable.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "new_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "new_name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.rename_function`

Rename a function.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "new_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "new_name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.rename_symbol`

Rename symbol at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "new_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "new_name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.set_comment`

Set comment at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "comment": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "comment"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.undefine_data_var`

Undefine data variable.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `annotation.undefine_symbol`

Undefine user symbol at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### arch tools

#### `arch.assemble`

Assemble instruction text with selected architecture.

```json
{
  "properties": {
    "address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "arch_name": {
      "type": "string"
    },
    "asm": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "asm"
  ],
  "type": "object"
}
```

Effective defaults: `{"address": 0, "arch_name": null}`.

#### `arch.disasm_bytes`

Disassemble bytes with selected architecture.

```json
{
  "properties": {
    "address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "arch_name": {
      "type": "string"
    },
    "data_hex": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{"address": 0, "arch_name": null}`.

#### `arch.info`

Get architecture and platform metadata.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### baseaddr tools

#### `baseaddr.abort`

Abort base-address detection.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `baseaddr.detect`

Run base-address detection.

```json
{
  "properties": {
    "algorithm": {
      "enum": [
        "instruction",
        "sampling"
      ],
      "type": "string"
    },
    "alignment": {
      "type": "integer"
    },
    "analysis": {
      "type": "string"
    },
    "arch_name": {
      "type": "string"
    },
    "high_boundary": {
      "type": "integer"
    },
    "low_boundary": {
      "type": "integer"
    },
    "max_pointers": {
      "type": "integer"
    },
    "min_strlen": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"algorithm": "instruction", "alignment": 1024, "analysis": "full", "arch_name": null, "high_boundary": 18446744073709551615, "low_boundary": 0, "max_pointers": 128, "min_strlen": 10}`.

#### `baseaddr.reasons`

Get base-address detection reasons.

```json
{
  "properties": {
    "base_address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "base_address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### binary tools

#### `binary.basic_blocks_at`

List basic blocks at an address with pagination.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.data_vars`

List data variables with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.functions`

List functions with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.functions_at`

List functions at an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `binary.get_function_at`

Find function by address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `binary.get_function_disassembly_at`

Get full disassembly for the function containing an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `binary.get_function_il_at`

Get full IL for the function containing an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "ssa": false}`.

#### `binary.save`

Save the current binary view to a file path.

```json
{
  "properties": {
    "path": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `binary.search_text`

Search raw text/bytes in a session.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "query": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "query"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 50}`.

#### `binary.sections`

List sections with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.segments`

List segments with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.strings`

List discovered strings with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `binary.summary`

Get binary/session summary.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `binary.symbols`

List symbols with pagination.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.


### binja tools

#### `binja.call`

Generic API bridge: call `bn.*` or `bv.*` target path.

```json
{
  "properties": {
    "args": {
      "items": {},
      "type": "array"
    },
    "kwargs": {
      "type": "object"
    },
    "session_id": {
      "type": "string"
    },
    "target": {
      "type": "string"
    }
  },
  "required": [
    "target"
  ],
  "type": "object"
}
```

Effective defaults: `{"args": [], "kwargs": {}, "session_id": null}`.

#### `binja.eval`

Evaluate Python code with `bn`, `sessions`, and optional `bv`.

```json
{
  "properties": {
    "code": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "code"
  ],
  "type": "object"
}
```

Effective defaults: `{"session_id": null}`.

#### `binja.info`

Return Binary Ninja version/install info.

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.


### data tools

#### `data.typed_at`

Get typed data variable at an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### database tools

#### `database.create_bndb`

Create .bndb from session.

```json
{
  "properties": {
    "path": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `database.info`

Get database status for session.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `database.read_global`

Read database global string key.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `database.save_auto_snapshot`

Save auto snapshot.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `database.snapshots`

List database snapshots.

```json
{
  "properties": {
    "limit": {
      "type": "integer"
    },
    "offset": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `database.write_global`

Write database global string key.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "value": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "key",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### debug tools

#### `debug.parse_and_apply`

Parse debug info and apply it to the view.

```json
{
  "properties": {
    "debug_path": {
      "type": "string"
    },
    "parser_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"debug_path": null, "parser_name": null}`.

#### `debug.parsers`

List debug info parsers valid for this view.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### disasm tools

#### `disasm.function`

Get full disassembly for the function containing an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `disasm.linear`

Get linear disassembly lines.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 200, "offset": 0}`.

#### `disasm.range`

Address-range disassembly lines.

```json
{
  "properties": {
    "length": {
      "minimum": 1,
      "type": "integer"
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "length"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 200}`.


### external tools

#### `external.library_add`

Add external library.

```json
{
  "properties": {
    "auto": {
      "type": "boolean"
    },
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"auto": false}`.

#### `external.library_list`

List external libraries.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `external.library_remove`

Remove external library.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `external.location_add`

Add external location mapping.

```json
{
  "properties": {
    "auto": {
      "type": "boolean"
    },
    "library_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "source_address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "target_address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "target_symbol": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "source_address"
  ],
  "type": "object"
}
```

Effective defaults: `{"auto": false, "library_name": null, "target_address": null, "target_symbol": null}`.

#### `external.location_get`

Get external location mapping.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "source_address": {
      "type": [
        "integer",
        "string"
      ]
    }
  },
  "required": [
    "session_id",
    "source_address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `external.location_remove`

Remove external location mapping.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "source_address": {
      "type": [
        "integer",
        "string"
      ]
    }
  },
  "required": [
    "session_id",
    "source_address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### function tools

#### `function.basic_blocks`

List basic blocks in a function with pagination.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `function.callees`

Callees of a function.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `function.callers`

Callers of a function.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `function.metadata_query`

Query function metadata by key.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `function.metadata_remove`

Remove function metadata by key.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `function.metadata_store`

Store function metadata by key.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "value": {}
  },
  "required": [
    "session_id",
    "function_start",
    "key",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `function.ssa_memory_def_use`

Get SSA memory definition and uses by memory version.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "version": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "version"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil"}`.

#### `function.ssa_var_def_use`

Get SSA variable definition and uses.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "variable_name": {
      "type": "string"
    },
    "version": {
      "minimum": 0,
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "variable_name",
    "version"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil"}`.

#### `function.var_refs`

List variable references in MLIL/HLIL.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "variable_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "variable_name"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil"}`.

#### `function.var_refs_from`

List variable references originating from an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "length": {
      "minimum": 1,
      "type": "integer"
    },
    "level": {
      "enum": [
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"length": null, "level": "mlil"}`.

#### `function.variables`

List function variables.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### health tools

#### `health.ping`

Health check.

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.


### il tools

#### `il.address_to_index`

Map address to IL index/indices.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "ssa": false}`.

#### `il.function`

IL function listing.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "limit": 200, "offset": 0, "ssa": false}`.

#### `il.index_to_address`

Map IL index to source address.

```json
{
  "properties": {
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "index": {
      "minimum": 0,
      "type": "integer"
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "index"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "ssa": false}`.

#### `il.instruction_by_addr`

Get IL instruction by source address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "ssa": false}`.

#### `il.rewrite.capabilities`

List IL rewrite support for one function and IL level.

```json
{
  "properties": {
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "level": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil"}`.

#### `il.rewrite.noop_replace`

Perform no-op IL expression replacement.

```json
{
  "properties": {
    "finalize": {
      "type": "boolean"
    },
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "generate_ssa_form": {
      "type": "boolean"
    },
    "index": {
      "type": "integer"
    },
    "level": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{"finalize": true, "generate_ssa_form": true, "index": null, "level": "mlil"}`.

#### `il.rewrite.translate_identity`

Translate IL with identity mapping callback.

```json
{
  "properties": {
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "level": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil"}`.


### loader tools

#### `loader.load_settings_get`

Get loader settings values.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "type_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `loader.load_settings_set`

Set one loader setting value.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_name": {
      "type": "string"
    },
    "value": {},
    "value_type": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_name",
    "key",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{"value_type": "string"}`.

#### `loader.load_settings_types`

List loader settings type names.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `loader.rebase`

Rebase BinaryView.

```json
{
  "properties": {
    "address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "force": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"force": false}`.


### mcp tools

#### `mcp.response_format`

Explain MCP tool result fields (`structuredContent` full payload, `content[0].text` summary).

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.


### memory tools

#### `memory.insert`

Insert bytes (hex) into the view.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "data_hex": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `memory.read`

Read bytes from the view.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "length": {
      "maximum": 65536,
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "length"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `memory.reader_read`

Read integer values via BinaryReader.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "endian": {
      "enum": [
        "little",
        "big"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "width": {
      "enum": [
        1,
        2,
        4,
        8
      ],
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "address",
    "width"
  ],
  "type": "object"
}
```

Effective defaults: `{"endian": "little"}`.

#### `memory.remove`

Remove bytes from the view.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "length": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "length"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `memory.write`

Write bytes (hex) to the view.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "data_hex": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `memory.writer_write`

Write integer values via BinaryWriter.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "endian": {
      "enum": [
        "little",
        "big"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "value": {
      "type": "integer"
    },
    "width": {
      "enum": [
        1,
        2,
        4,
        8
      ],
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "address",
    "width",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{"endian": "little"}`.


### metadata tools

#### `metadata.query`

Query metadata by key.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `metadata.remove`

Remove metadata by key.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `metadata.store`

Store metadata by key.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "value": {}
  },
  "required": [
    "session_id",
    "key",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### patch tools

#### `patch.always_branch`

Patch conditional branch to always branch when supported.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.assemble`

Assemble and patch instruction bytes at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "asm": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address",
    "asm"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.convert_to_nop`

Patch instruction to NOP when supported.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.invert_branch`

Patch conditional branch by inversion when supported.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.never_branch`

Patch conditional branch to never branch when supported.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.skip_and_return_value`

Patch instruction to skip and return value when supported.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    },
    "value": {
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "address",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `patch.status`

Inspect patch availability at address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### plugin tools

#### `plugin.execute`

Execute a context-valid plugin command.

```json
{
  "properties": {
    "address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "length": {
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "perform": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"address": null, "length": 0, "perform": false}`.

#### `plugin.valid_commands`

List context-valid plugin commands.

```json
{
  "properties": {
    "address": {
      "type": [
        "integer",
        "string"
      ]
    },
    "length": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"address": null, "length": 0}`.


### plugin_repo tools

#### `plugin_repo.check_updates`

Check plugin repository updates.

```json
{
  "properties": {
    "perform": {
      "type": "boolean"
    }
  },
  "type": "object"
}
```

Effective defaults: `{"perform": false}`.

#### `plugin_repo.plugin_action`

Run install/uninstall/enable/disable action on repository plugin.

```json
{
  "properties": {
    "action": {
      "type": "string"
    },
    "plugin_path": {
      "type": "string"
    },
    "repository_path": {
      "type": "string"
    }
  },
  "required": [
    "repository_path",
    "plugin_path",
    "action"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `plugin_repo.status`

List plugin repositories and plugin states.

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.


### project tools

#### `project.close`

Close tracked project.

```json
{
  "properties": {
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.create`

Create project.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "path": {
      "type": "string"
    }
  },
  "required": [
    "path",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.create_file`

Create project file from base64 data.

```json
{
  "properties": {
    "data_base64": {
      "type": "string"
    },
    "description": {
      "type": "string"
    },
    "folder_id": {
      "type": "string"
    },
    "name": {
      "type": "string"
    },
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id",
    "name",
    "data_base64"
  ],
  "type": "object"
}
```

Effective defaults: `{"description": "", "folder_id": null}`.

#### `project.create_folder`

Create project folder.

```json
{
  "properties": {
    "description": {
      "type": "string"
    },
    "name": {
      "type": "string"
    },
    "parent_folder_id": {
      "type": "string"
    },
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"description": "", "parent_folder_id": null}`.

#### `project.list`

List project folders/files.

```json
{
  "properties": {
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.metadata_query`

Query project metadata.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.metadata_remove`

Remove project metadata.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "project_id": {
      "type": "string"
    }
  },
  "required": [
    "project_id",
    "key"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.metadata_store`

Store project metadata.

```json
{
  "properties": {
    "key": {
      "type": "string"
    },
    "project_id": {
      "type": "string"
    },
    "value": {}
  },
  "required": [
    "project_id",
    "key",
    "value"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `project.open`

Open project.

```json
{
  "properties": {
    "path": {
      "type": "string"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### search tools

#### `search.all_constant`

Find all constant occurrences in range.

```json
{
  "properties": {
    "constant": {
      "type": "integer"
    },
    "end": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "end",
    "constant"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100}`.

#### `search.all_data`

Find all data/byte-pattern matches in range.

```json
{
  "properties": {
    "data_hex": {
      "type": "string"
    },
    "end": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "end",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100}`.

#### `search.all_text`

Find all text matches in range (regex optional).

```json
{
  "properties": {
    "end": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "query": {
      "type": "string"
    },
    "regex": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "end",
    "query"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "regex": false}`.

#### `search.data`

Search for raw byte patterns (hex string).

```json
{
  "properties": {
    "data_hex": {
      "type": "string"
    },
    "end": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{"end": null, "limit": 100, "start": null}`.

#### `search.next_constant`

Find next constant occurrence.

```json
{
  "properties": {
    "constant": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "constant"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `search.next_data`

Find next data/byte-pattern match.

```json
{
  "properties": {
    "data_hex": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "data_hex"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `search.next_text`

Find next text match.

```json
{
  "properties": {
    "query": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    }
  },
  "required": [
    "session_id",
    "start",
    "query"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### section tools

#### `section.add_user`

Add user section.

```json
{
  "properties": {
    "align": {
      "type": "integer"
    },
    "entry_size": {
      "type": "integer"
    },
    "length": {
      "type": "integer"
    },
    "name": {
      "type": "string"
    },
    "semantics": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "type_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name",
    "start",
    "length"
  ],
  "type": "object"
}
```

Effective defaults: `{"align": 1, "entry_size": 1, "semantics": "DefaultSectionSemantics", "type_name": ""}`.

#### `section.remove_user`

Remove user section.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### segment tools

#### `segment.add_user`

Add user segment.

```json
{
  "properties": {
    "contains_code": {
      "type": "boolean"
    },
    "contains_data": {
      "type": "boolean"
    },
    "data_length": {
      "type": "integer"
    },
    "data_offset": {
      "type": "integer"
    },
    "executable": {
      "type": "boolean"
    },
    "length": {
      "type": "integer"
    },
    "readable": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "writable": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "start",
    "length"
  ],
  "type": "object"
}
```

Effective defaults: `{"contains_code": false, "contains_data": true, "data_length": 0, "data_offset": 0, "executable": false, "readable": true, "writable": false}`.

#### `segment.remove_user`

Remove user segment.

```json
{
  "properties": {
    "length": {
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    },
    "start": {
      "type": [
        "integer",
        "string"
      ]
    }
  },
  "required": [
    "session_id",
    "start"
  ],
  "type": "object"
}
```

Effective defaults: `{"length": 0}`.


### session tools

#### `session.close`

Close one open session.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `session.list`

List open sessions.

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.

#### `session.mode`

Get session safety/determinism mode.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `session.open`

Open a binary and create a session.

```json
{
  "properties": {
    "deterministic": {
      "type": "boolean"
    },
    "options": {
      "type": "object"
    },
    "path": {
      "type": "string"
    },
    "read_only": {
      "type": "boolean"
    },
    "update_analysis": {
      "type": "boolean"
    }
  },
  "required": [
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{"deterministic": true, "options": {}, "read_only": true, "update_analysis": true}`.

#### `session.open_bytes`

Open a binary session from base64-encoded bytes.

```json
{
  "properties": {
    "data_base64": {
      "type": "string"
    },
    "deterministic": {
      "type": "boolean"
    },
    "filename": {
      "type": "string"
    },
    "options": {
      "type": "object"
    },
    "read_only": {
      "type": "boolean"
    },
    "update_analysis": {
      "type": "boolean"
    }
  },
  "required": [
    "data_base64"
  ],
  "type": "object"
}
```

Effective defaults: `{"deterministic": true, "filename": "binary_ninja_headless_mcp_bytes.bin", "options": {}, "read_only": true, "update_analysis": true}`.

#### `session.open_existing`

Open another session from an existing session's file.

```json
{
  "properties": {
    "deterministic": {
      "type": "boolean"
    },
    "options": {
      "type": "object"
    },
    "read_only": {
      "type": "boolean"
    },
    "source_session_id": {
      "type": "string"
    },
    "update_analysis": {
      "type": "boolean"
    }
  },
  "required": [
    "source_session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"deterministic": true, "options": {}, "read_only": true, "update_analysis": false}`.

#### `session.set_mode`

Update session safety/determinism mode.

```json
{
  "properties": {
    "deterministic": {
      "type": "boolean"
    },
    "read_only": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"deterministic": null, "read_only": null}`.


### task tools

#### `task.analysis_update`

Alias of analysis.update: start tracked analysis and return task_id.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `task.cancel`

Cancel pending/running work. Terminal tasks are unchanged; drain before reuse.

```json
{
  "properties": {
    "task_id": {
      "type": "string"
    }
  },
  "required": [
    "task_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `task.result`

Get terminal result (completed/failed/cancelled); pending tasks return an error.

```json
{
  "properties": {
    "task_id": {
      "type": "string"
    }
  },
  "required": [
    "task_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `task.search_text`

Start async search task.

```json
{
  "properties": {
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "query": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "query"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 50}`.

#### `task.status`

Get task status.

```json
{
  "properties": {
    "task_id": {
      "type": "string"
    }
  },
  "required": [
    "task_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### transform tools

#### `transform.inspect`

Inspect/process transform pipeline. Requires session_id or path.

```json
{
  "properties": {
    "mode": {
      "type": "string"
    },
    "path": {
      "type": "string"
    },
    "process": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "type": "object"
}
```

Effective defaults: `{"mode": "full", "path": null, "process": false, "session_id": null}`.


### type tools

#### `type.define_user`

Define user type from type source.

```json
{
  "properties": {
    "import_dependencies": {
      "type": "boolean"
    },
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_source": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_source"
  ],
  "type": "object"
}
```

Effective defaults: `{"import_dependencies": true, "name": null}`.

#### `type.export_to_library`

Export type into a type library.

```json
{
  "properties": {
    "import_dependencies": {
      "type": "boolean"
    },
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_library_id": {
      "type": "string"
    },
    "type_source": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_library_id",
    "type_source"
  ],
  "type": "object"
}
```

Effective defaults: `{"import_dependencies": true, "name": null}`.

#### `type.import_library_object`

Import object type from type library.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_library_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"type_library_id": null}`.

#### `type.import_library_type`

Import type from type library.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "type_library_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"type_library_id": null}`.

#### `type.parse_declarations`

Parse C declarations for types/variables/functions.

```json
{
  "properties": {
    "declarations": {
      "type": "string"
    },
    "import_dependencies": {
      "type": "boolean"
    },
    "include_dirs": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "options": {
      "items": {
        "type": "string"
      },
      "type": "array"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "declarations"
  ],
  "type": "object"
}
```

Effective defaults: `{"import_dependencies": true, "include_dirs": null, "options": null}`.

#### `type.parse_string`

Parse a single type string.

```json
{
  "properties": {
    "import_dependencies": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "type_source": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_source"
  ],
  "type": "object"
}
```

Effective defaults: `{"import_dependencies": true}`.

#### `type.rename`

Rename a type.

```json
{
  "properties": {
    "new_name": {
      "type": "string"
    },
    "old_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "old_name",
    "new_name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type.undefine_user`

Undefine a user type.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### type_archive tools

#### `type_archive.create`

Create and optionally attach a type archive.

```json
{
  "properties": {
    "attach": {
      "type": "boolean"
    },
    "path": {
      "type": "string"
    },
    "platform_name": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{"attach": true, "platform_name": null}`.

#### `type_archive.get`

Get one tracked type archive.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "type_archive_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_archive_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_archive.list`

List attached type archives.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_archive.open`

Open and optionally attach a type archive.

```json
{
  "properties": {
    "attach": {
      "type": "boolean"
    },
    "path": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{"attach": true}`.

#### `type_archive.pull`

Pull types from a type archive.

```json
{
  "properties": {
    "names": {
      "items": {
        "type": "string"
      },
      "minItems": 1,
      "type": "array"
    },
    "session_id": {
      "type": "string"
    },
    "type_archive_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_archive_id",
    "names"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_archive.push`

Push types to a type archive.

```json
{
  "properties": {
    "names": {
      "items": {
        "type": "string"
      },
      "minItems": 1,
      "type": "array"
    },
    "session_id": {
      "type": "string"
    },
    "type_archive_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_archive_id",
    "names"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_archive.references`

Query archive incoming/outgoing references for one type.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "type_archive_id": {
      "type": "string"
    }
  },
  "required": [
    "type_archive_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### type_library tools

#### `type_library.create`

Create and optionally attach a type library.

```json
{
  "properties": {
    "add_to_view": {
      "type": "boolean"
    },
    "name": {
      "type": "string"
    },
    "path": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"add_to_view": true, "path": null}`.

#### `type_library.get`

Get one tracked type library.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "type_library_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "type_library_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_library.list`

List type libraries attached to the view.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `type_library.load`

Load and optionally attach a type library.

```json
{
  "properties": {
    "add_to_view": {
      "type": "boolean"
    },
    "path": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "path"
  ],
  "type": "object"
}
```

Effective defaults: `{"add_to_view": true}`.


### uidf tools

#### `uidf.clear_user_var_value`

Clear function user variable value.

```json
{
  "properties": {
    "after": {
      "type": "boolean"
    },
    "def_addr": {
      "type": [
        "integer",
        "string"
      ]
    },
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "session_id": {
      "type": "string"
    },
    "variable_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "variable_name",
    "def_addr"
  ],
  "type": "object"
}
```

Effective defaults: `{"after": true}`.

#### `uidf.list_user_var_values`

List all user variable values for a function.

```json
{
  "properties": {
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `uidf.parse_possible_value`

Parse user-informed possible value set string.

```json
{
  "properties": {
    "here": {
      "type": [
        "integer",
        "string"
      ]
    },
    "session_id": {
      "type": "string"
    },
    "state": {
      "type": "string"
    },
    "value": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "value",
    "state"
  ],
  "type": "object"
}
```

Effective defaults: `{"here": null}`.

#### `uidf.set_user_var_value`

Set function user variable value.

```json
{
  "properties": {
    "after": {
      "type": "boolean"
    },
    "def_addr": {
      "type": [
        "integer",
        "string"
      ]
    },
    "function_start": {
      "type": [
        "integer",
        "string"
      ]
    },
    "session_id": {
      "type": "string"
    },
    "state": {
      "type": "string"
    },
    "value": {
      "type": "string"
    },
    "variable_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "variable_name",
    "def_addr",
    "value",
    "state"
  ],
  "type": "object"
}
```

Effective defaults: `{"after": true}`.


### undo tools

#### `undo.begin`

Begin undo transaction.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `undo.commit`

Commit undo transaction.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "transaction_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"transaction_id": null}`.

#### `undo.redo`

Perform redo.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `undo.revert`

Revert undo transaction.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "transaction_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"transaction_id": null}`.

#### `undo.undo`

Perform undo.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.


### value tools

#### `value.flags_at`

Get lifted IL flag read/write state at an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{}`.

#### `value.possible`

Get IL possible value set at an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "level": {
      "enum": [
        "llil",
        "mlil",
        "hlil"
      ],
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "ssa": {
      "type": "boolean"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"level": "mlil", "ssa": false}`.

#### `value.reg`

Get register value at/after an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "after": {
      "type": "boolean"
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "register": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address",
    "register"
  ],
  "type": "object"
}
```

Effective defaults: `{"after": false}`.

#### `value.stack`

Get stack contents at/after an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "after": {
      "type": "boolean"
    },
    "function_start": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "session_id": {
      "type": "string"
    },
    "size": {
      "minimum": 1,
      "type": "integer"
    },
    "stack_offset": {
      "type": "integer"
    }
  },
  "required": [
    "session_id",
    "function_start",
    "address",
    "stack_offset",
    "size"
  ],
  "type": "object"
}
```

Effective defaults: `{"after": false}`.


### workflow tools

#### `workflow.clone`

Clone workflow.

```json
{
  "properties": {
    "name": {
      "type": "string"
    },
    "register": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "name"
  ],
  "type": "object"
}
```

Effective defaults: `{"register": false}`.

#### `workflow.describe`

Describe workflow topology and settings.

```json
{
  "properties": {
    "activity": {
      "type": "string"
    },
    "immediate": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"activity": "", "immediate": true, "workflow_name": null}`.

#### `workflow.graph`

Summarize workflow graph.

```json
{
  "properties": {
    "activity": {
      "type": "string"
    },
    "sequential": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"activity": "", "sequential": false, "workflow_name": null}`.

#### `workflow.insert`

Insert activities before an activity.

```json
{
  "properties": {
    "activities": {
      "items": {
        "type": "string"
      },
      "type": [
        "array",
        "string"
      ]
    },
    "activity": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "activity",
    "activities"
  ],
  "type": "object"
}
```

Effective defaults: `{"workflow_name": null}`.

#### `workflow.insert_after`

Insert activities after an activity.

```json
{
  "properties": {
    "activities": {
      "items": {
        "type": "string"
      },
      "type": [
        "array",
        "string"
      ]
    },
    "activity": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "activity",
    "activities"
  ],
  "type": "object"
}
```

Effective defaults: `{"workflow_name": null}`.

#### `workflow.list`

List registered workflows.

```json
{
  "properties": {},
  "type": "object"
}
```

Effective defaults: `{}`.

#### `workflow.machine.control`

Control workflow machine runtime.

```json
{
  "properties": {
    "action": {
      "type": "string"
    },
    "activities": {
      "items": {
        "type": "string"
      },
      "type": [
        "array",
        "string"
      ]
    },
    "activity": {
      "type": "string"
    },
    "advanced": {
      "type": "boolean"
    },
    "enable": {
      "type": "boolean"
    },
    "incremental": {
      "type": "boolean"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "action"
  ],
  "type": "object"
}
```

Effective defaults: `{"activities": null, "activity": null, "advanced": true, "enable": null, "incremental": false, "workflow_name": null}`.

#### `workflow.machine.status`

Get workflow machine status.

```json
{
  "properties": {
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id"
  ],
  "type": "object"
}
```

Effective defaults: `{"workflow_name": null}`.

#### `workflow.remove`

Remove workflow activity.

```json
{
  "properties": {
    "activity": {
      "type": "string"
    },
    "session_id": {
      "type": "string"
    },
    "workflow_name": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "activity"
  ],
  "type": "object"
}
```

Effective defaults: `{"workflow_name": null}`.


### xref tools

#### `xref.code_refs_from`

Code references from an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "length": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"length": null}`.

#### `xref.code_refs_to`

Code references to an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "offset": {
      "minimum": 0,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100, "offset": 0}`.

#### `xref.data_refs_from`

Data references from an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "length": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"length": null}`.

#### `xref.data_refs_to`

Data references to an address.

```json
{
  "properties": {
    "address": {
      "oneOf": [
        {
          "type": "integer"
        },
        {
          "type": "string"
        }
      ]
    },
    "limit": {
      "minimum": 1,
      "type": "integer"
    },
    "session_id": {
      "type": "string"
    }
  },
  "required": [
    "session_id",
    "address"
  ],
  "type": "object"
}
```

Effective defaults: `{"limit": 100}`.

<!-- END GENERATED TOOL REFERENCE -->
