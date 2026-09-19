# Binary Ninja CLI verification report

This report records finite, reproducible verification of `binja_cli` / `binja-cli`
and the shared MCP backend. Usage and the complete 181-tool reference are in
[BINJA_CLI.md](BINJA_CLI.md). Native results below apply to **Binary Ninja
6.0.10601 Ultimate, Linux on an AArch64 host, and Python 3.14.7**. Both AArch64 and
x86-64 input binaries are included; x86-64 input analysis on this host is not a
claim of testing an x86-64 host installation.

**Both full native matrices passed and received independent approval:** every
registered tool is verified in all eight architecture/transport/argument cells,
with 5,303 exact native request/response parity checks. The recorded regression,
packaging, documentation, and lifecycle gates also passed within the scope
described below. Results come from completed artifacts, not planned coverage.

## Evidence and current results

The absolute links in this section identify artifacts in this analysis
environment; they are not files shipped by the Python package. Portable
reproduction commands follow below. Source identity is recorded in the
[final source checkpoint](/agent/analysis/binja-cli/checkpoints/final-source.json),
and each native cell independently records starting/ending source hashes and its
input SHA-256. The durable analysis handoff is
[analysis README](/agent/analysis/binja-cli/README.md).

| Verification | Current result | Evidence |
| --- | --- | --- |
| AArch64 `-O0 -g`, in-process, JSON arguments | 181/181 tools verified; 663 exact native MCP parity checks; source/input unchanged. | [Coverage](/agent/analysis/binja-cli/results/native-matrix-final-01/cell-inprocess-json/inprocess-json/coverage.json) |
| AArch64 `-O0 -g`, in-process, flags | 181/181 tools verified; 664 parity checks; source/input unchanged. | [Coverage](/agent/analysis/binja-cli/results/native-matrix-final-01/cell-inprocess-flags/inprocess-flags/coverage.json) |
| AArch64 `-O0 -g`, TCP, JSON arguments | 181/181 tools verified; 662 parity checks; source/input unchanged. | [Coverage](/agent/analysis/binja-cli/results/native-matrix-final-01/cell-tcp-json/tcp-json/coverage.json) |
| AArch64 `-O0 -g`, TCP, flags | 181/181 tools verified; 662 parity checks; source/input unchanged. | [Coverage](/agent/analysis/binja-cli/results/native-matrix-final-01/cell-tcp-flags/tcp-flags/coverage.json) |
| AArch64 aggregate matrix | Passed all four cells with no errors: 2,651 exact native parity checks. | [Final summary](/agent/analysis/binja-cli/results/native-matrix-final-01/summary.json) |
| x86-64 `-O0 -g`, four-cell matrix | Passed 181/181 tools in each cell, all required variants, no errors: 2,652 exact native parity checks. | [Final summary](/agent/analysis/binja-cli/results/native-matrix-x86-final-01/summary.json) |
| Combined native matrices | All eight cells passed against the same frozen source, with original inputs preserved. | [Combined report](/agent/analysis/binja-cli/results/native-cli-final-combined.json) |
| AArch64/x86-64 optimized and stripped inputs | Four focused cases passed, 60 semantic assertions. This is supplementary coverage, not another full 181-tool matrix. | [Summary](/agent/analysis/binja-cli/results/fixture-variants/summary.json), [fixture identities and commands](/agent/analysis/binja-cli/results/fixture-variants/README.md) |
| Installed wheel and entry points | Passed 19 commands; 21 installed source/fixture entries match checkout hashes. | [Report](/agent/analysis/binja-cli/results/installed-package-final/report.json) |
| Documented native examples | All 14 commands completed successfully on the controlled fixture. | [Commands/results](/agent/analysis/binja-cli/results/docs-native-fixture.json) |
| Source-frozen repository regression run | 883 passed, 1 wrapper deselected, one four-case native wrapper module excluded; actual native helpers run in the complete matrices (details below). | [Final output](/agent/analysis/binja-cli/results/source-frozen-regressions.txt) |
| Source-frozen lifecycle corpus | All 15 runs passed: seeds 0/1/1337, 100 transitions per run, 1,500 transitions total. Inputs/checkpoint databases preserved; executed runtime modules unchanged. | [Summary](/agent/analysis/binja-cli/results/cli-lifecycle-final/summary.json), [exact commands and reports](/agent/analysis/binja-cli/results/cli-lifecycle-final/matrix.json) |
| Independent native matrix review | Both architectures approved: all cells, variants, native parity, source/input identity, and cleanup verified. | [AArch64 audit](/agent/analysis/binja-cli/results/independent-cli/final-matrix-audit.json), [x86-64 audit](/agent/analysis/binja-cli/results/independent-cli/final-matrix-x86-audit.json) |
| Final combined acceptance | Passed: native matrices, regressions, lifecycle, supplementary fixtures, installed package, documentation examples, identity checks, and cleanup. Independent approval includes the 15 lifecycle runs. | [Acceptance report](/agent/analysis/binja-cli/results/final-acceptance.json), [independent final approval](/agent/analysis/binja-cli/results/independent-cli/final-approval.md) |

The primary AArch64 fixture SHA-256 is
`6bb7ef1e1ac70a49efa62d181f8c1df9bf8a70ff031ae8e744a94450a4952b38`.
The x86-64 fixture SHA-256 is
`781bf6142e9b2605bd9bbc7632345fba92dad1c09f6c1749999b285f3391a709`.
The verified wheel SHA-256 is
`f9ed87d325d1c1095d15696641ef7ee826e719cb66ae1fa972855426902ecf1b`.
These identities identify these particular artifacts; rebuilding may produce a
different binary or wheel while remaining a valid new verification run.

## What native coverage establishes

The catalog supplies the complete tool inventory, but a catalog entry or successful
exit alone does not count as verified. Each tool needs a successful native CLI
invocation tied to an explicit semantic assertion. Tools with required variants
also need every variant. The coverage ledger retains failed assertions, missing
variants, input identity, and source identity; source changes or an incomplete
matrix prevent success.

Each audited cell contains 433 ledger assertions, of which the independent audit
counts 432 linked semantic assertions covering 422 distinct tool/variant pairs,
including 162 explicitly required variants. The remaining assertion is a fixture
precondition and is not counted as successful tool coverage. Cells repeat that inventory across
architecture/transport/argument combinations; these counts should not be read as
different tool catalogs.

The four cells exercise in-process and TCP dispatch using both complete JSON
argument objects and schema-derived flags, including typed compound arguments.
In-process verification runs the actual CLI entry function in an isolated native
worker process. TCP verification uses a separate CLI worker process and a real
managed native MCP server, recording the server's requests and responses through
a transparent wire recorder. Each invocation's actual argument vector and worker
process identity are saved. The default worker mode reuses that CLI process
within a cell; `--tcp-process-mode subprocess` additionally starts a fresh CLI
process for each TCP call.

Native parity compares the CLI payload with the actual corresponding MCP
response and verifies the request arguments. Semantic assertions independently
check known fixture facts and effects: recovered functions/strings/IL, byte
changes, readback, undo/redo, persisted databases and types after reopening,
project associations, task/control states, workflow edits, and native plugin
effects. Special fixtures include separate DWARF files, native command contexts,
an isolated localhost plugin repository, and restart checks for deferred plugin
state. These use the genuine Binary Ninja runtime.

Base-address evidence distinguishes the algorithms. The controlled raw firmware
sampling case finds the independently known `0x400000` base and 64 pointer/string
reasons. The instruction algorithm remains the unchanged default; its recorded
`detected: false` outcome on this fixture is not relabeled as successful candidate
recovery. Native workflow `dump` rejection likewise remains visible: a successful
diagnostic snapshot identifies `dump_source: native_state_snapshot` and preserves
the rejected native response. See the actual assertions for each outcome.

Fake backends, recording doubles, malformed-server simulations, parser tests,
catalog/envelope parity, and injected lifecycle faults test client behavior and
failure handling. They supplement native evidence and are **not counted as native
tool success**. Do not add overlapping test counts from separate suites into a
single purported count of distinct scenarios.

The final pytest run excludes `tests/test_native_cli_special.py` (four parameterized
wrapper cases) and deselects `test_complete_native_cli_matrix` (one opt-in wrapper).
The standalone eight-cell native matrices execute the same special-feature helper
paths and provide the stronger two-architecture matrix evidence. A separate
focused native check also covers all 12 command contexts. These wrapper exclusions
are reported explicitly; they are neither passing pytest cases nor omitted native
feature coverage.

## Reproduce in another checkout

Prerequisites: Python 3.11 or newer, a licensed/importable Binary Ninja runtime,
a C compiler compatible with the included fixture, and the repository's test
dependencies (`pytest`, `ruff`, and the wheel build requirements). The tested
runtime version is stated above; another runtime produces a separate compatibility
result. Managed process control requires Linux `/proc` and Unix file locking.
Do not select `BINARY_NINJA_HEADLESS_MCP_FAKE_BACKEND=1` for native verification.

From the repository root, this default command builds a controlled host-architecture
fixture and runs all four native transport/argument cells in fresh processes:

```bash
python3 -m binary_ninja_headless_mcp.cli_verify --output ./analysis/native-cli-matrix
```

The output directory must be new or empty. The full defaults include native
special-feature checks. Do not use `--without-special` or a partial `--groups`
selection for an acceptance run: the report correctly remains incomplete.
The default `--timeout 180` is a verifier deadline, independent of the product
CLI's unlimited default tool-response wait. Avoid resource-heavy concurrent native
runs; retain timeout evidence and rerun in a new directory after fixing its cause.

To select compiler architecture explicitly on a Linux cross-toolchain host:

```bash
python3 -m binary_ninja_headless_mcp.cli_verify --output ./analysis/native-aarch64 --compiler aarch64-linux-gnu-gcc
python3 -m binary_ninja_headless_mcp.cli_verify --output ./analysis/native-x86-64 --compiler x86_64-linux-gnu-gcc
```

Alternatively, `--binary PATH` reuses a previously compiled copy of the included
`binary_ninja_headless_mcp/fixtures/binja_cli_native.c` fixture. Arbitrary binaries
do not satisfy its fixture-specific assertions. Use the original compiled input;
the verifier creates private working copies for mutations.

For the additional per-call TCP process boundary:

```bash
python3 -m binary_ninja_headless_mcp.cli_verify --output ./analysis/native-tcp-subprocess --mode tcp --argument-style both --tcp-process-mode subprocess
```

Inspect top-level `summary.json` and every cell's `coverage.json`,
`assertions.jsonl`, `trace.jsonl`, native-wire evidence, and saved artifacts. Require
`complete: true`, no aggregate errors, 181 verified tools in every requested cell,
no missing required variants, matching source/input identity, and completed cleanup.
Exit zero without the corresponding retained evidence is insufficient for this
report's acceptance claim.

Run repository checks separately:

```bash
python3 -m pytest
ruff check .
ruff format --check .
python3 -m binary_ninja_headless_mcp.cli_docs --check
```

For repeatable lifecycle testing on an input you own, use the real backend and
retain every run's output directory:

```bash
python3 -m binary_ninja_headless_mcp.lifecycle_fuzzer --binary ./sample --output-dir ./analysis/lifecycle-seed-0 --seed 0 --transitions 100
python3 -m binary_ninja_headless_mcp.lifecycle_fuzzer --binary ./sample --output-dir ./analysis/lifecycle-seed-1 --seed 1 --transitions 100
python3 -m binary_ninja_headless_mcp.lifecycle_fuzzer --binary ./sample --output-dir ./analysis/lifecycle-seed-1337 --seed 1337 --transitions 100
```

Large corpus runs in this environment reuse previously analyzed databases and
record their exact loader options; the local runner below preserves those
prerequisites. A quick run on another `./sample` is not equivalent corpus coverage.
Lifecycle source identity is checked against the nine modules actually executed
by its server/fuzzer (`__init__`, `__main__`, `backend`, `catalog`, `cli`, `server`,
`lifecycle`, `lifecycle_fuzzer`, and `fake_binja`). Earlier lifecycle reports also
record unrelated package files, including an earlier unused `cli_verify.py` hash;
the lifecycle claim is the unchanged executed module set, not identical hashes
for every package file throughout that run.

To check installed entry points from a newly built wheel in your own virtual
environment, build with `python3 -m pip wheel . --no-deps --wheel-dir ./dist`,
install that wheel into a fresh virtual environment, change to a directory outside
the checkout, and run both `binja_cli --version` and `binja-cli --version`, offline
`list`/`describe`, and a native open/read/close workflow from [the guide](BINJA_CLI.md).
Ensure `binaryninja` remains importable in that environment and confirm the
imported package path is the installed package, not the checkout.

## Exact local reproduction and retained limitations

These commands intentionally reference the paths used for this report. Use fresh
output names instead of overwriting completed evidence:

```bash
python3 -m binary_ninja_headless_mcp.cli_verify --output /agent/analysis/binja-cli/results/native-matrix-reproduction --binary /agent/analysis/binja_cli_native/binja_cli_native
BINJA_NATIVE_TEST_BINARY=/agent/analysis/ls-3d9ac2ff/inputs/ls python3 -m pytest -q -o addopts='' --ignore=tests/test_native_cli_special.py -k 'not test_complete_native_cli_matrix'
python3 /agent/analysis/binja-cli/scripts/verify_fixture_variants.py run
python3 /agent/analysis/binja-cli/scripts/verify_package.py --output /agent/analysis/binja-cli/results/installed-package-reproduction --binary /agent/analysis/binja_cli_native/binja_cli_native
python3 /agent/analysis/binja-cli/scripts/verify_docs_examples.py --binary /agent/analysis/binja_cli_native/binja_cli_native --output /agent/analysis/binja-cli/results/docs-native-reproduction.json
python3 /agent/analysis/binja-cli/scripts/run_lifecycle_matrix.py --label cli-lifecycle-reproduction
```

The supplementary fixture runner currently uses its fixed analysis workspace;
read its case README before rerunning so existing evidence is preserved. The
package/docs/lifecycle helper scripts above are analysis artifacts, not installed
CLI entry points. Source, commands, hashes, intermediate failures, and final
reports remain under `/agent/analysis/binja-cli` and the linked binary cases.

Earlier `/bin/ls` documentation and smoke experiments exceeded bounded harness
deadlines under native workload contention. Those runs are retained as incomplete
experiments, not passing results. A later controlled-fixture documentation run
completed all 14 commands. Final large-binary lifecycle runs passed on preserved
`ls`, `bash`, Python 3.14, and two libc inputs; their reports retain all database
checkpoints, per-input analysis options, and source identities.

This report makes no claim of universal perfection, exhaustive coverage of all
possible inputs, or compatibility with every Binary Ninja release or platform.
Its acceptance claim is limited to every
registered tool and enumerated required variant on the recorded native fixtures,
transports, argument styles, runtime, and exact delivered source.
