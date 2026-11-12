# Exhaustive package and module test partitions

`plan9asmtest` runs one exact Go package in fresh, owned child processes. It
discovers the complete current `Test`, runnable `Example` and `Fuzz` inventory
with actual `go test -list=.`; no checked-in test list is used. Go's separately
listed benchmarks are retained in the report but not run, matching ordinary
`go test` without `-bench`. Fuzz targets run their normal seed corpus, not a
fuzzing campaign. Every emitted subtest and seed must also terminate.

From the repository root, select the required Go/LLVM tools described in
[validation](../../docs/development/validation.md), then use a new output path:

```sh
mkdir -p _out
GOFLAGS= go run ./cmd/plan9asmtest \
  -out _out/root-partitions-current -shards 32 -timeout 45m
```

Ordinary mode is serial by default. Add `-workers 2` for bounded parallel
partitions; the allowed range is 1..32 and cannot exceed `-shards`. Start small
because each process owns its own LLVM objects and compiler children. The
report records the actual worker limit. Parallelism does not alter the actual
inventory, deterministic assignment, build flags, per-child timeout or coverage checks.
Only one collector publishes reports and counts. A failed shard remains failed
while other shards run; a failed publication cancels and waits for active owners.
Selected cross-runtime CI owners remain serial and reject `-workers` above one.

## Complete main-module CI suites

Unix test/race/coverage CI uses `scripts/test-module-ci.sh`. Its three package
owners share the complete actual `go list -json ./...` package inventory:
owner zero runs the root, owner one runs `gotoolprofile` and `internal/sdkfrontend`,
and owner two runs every other package. The two owner-one packages run serially;
each uses the same exhaustive root partitions and at most two active commands.
Independent SDK source captures retain their own original budgets and lifetimes,
while no longer accumulating in a single unfiltered race command.
CI splits only owner zero into sixteen jobs for test/
coverage and 32 for race. Part `p` owns global shard indices `i` where
`i % parts == p`. Test/coverage keep 32 shards; race uses 64 shards. Every
root owner executes exactly two shards in one two-worker wave. Test/coverage
retain 45-minute command and 60-minute job budgets; race retains 60-minute
commands and 75-minute jobs. Shared-profile and other packages execute once;
they are not repeated for each root part. Only explicit owner two overlaps at
most `-workers` complete package commands; each package keeps one shard/worker.
Its single collector retains inventory order, records failures without stopping
other packages, and joins active commands on cancellation without dispatching
the remaining packages. The worker and command/job budgets are unchanged.
Every other package runs complete ordinary `go test` without `-run`, including packages
with no tests or only benchmarks/TestMain. Every package has its own actual
`-list=.` receipt, including runnable examples/fuzz targets and separately
recorded benchmarks. Nested CLI modules are not main-module packages; their
independent complete-module workflows remain required. Windows uses the same
strict module protocol with sixteen root parts for the main module and four for
each CLI, preserving profile/rest ownership and the thirty-minute command budget.
Linux CLI test and coverage jobs use `scripts/test-linux-cli-module-ci.sh` with
the same complete eight-shard/four-part layout, two workers and thirty-minute
commands. Each root part has its own sixty-minute job. Part zero also executes
the actual profile/rest owners into separate reports; both CLI inventories
currently contain only their root package, so these roles execute zero tests,
not additional passing roots. The independent aggregate requires all four root
fragments and both role reports, including fresh inventory and raw terminals.
Only complete coverage aggregation creates each CLI's original profile and
summary; CLI profiles are not merged into main-module coverage.
The Windows driver selects a minimal Go/LLVM22/Node/Python/jq/Git/system PATH
before either execution or verification; unrelated hosted-image search paths
cannot change the cross-owner plan. Raw and normalized environment equality
remains strict, including PATH.

```sh
# Each command is a separate CI job, not concurrent local invocations.
bash scripts/test-module-ci.sh race execute 0 0
# Run race root parts 1..31 as separate jobs with owner 0 and their exact number.
bash scripts/test-module-ci.sh race execute 1 -1
bash scripts/test-module-ci.sh race execute 2 -1
# Download root-p artifacts into owner-0000/part-000p, and profile/rest into
# owner-0001 and owner-0002. All 34 race roles are required for completion;
# test/coverage require their sixteen root parts plus profile/rest.
bash scripts/test-module-ci.sh race complete
```

Root fragments use schema 2 `partition.json` and the distinct
`actual_go_complete_module_root_parts_v2` module protocol. They retain the
complete root list and all 32 (64 for race) global shard entries. Unassigned shards are
`not_owned`, with no command, terminal or coverage artifact. A fragment is
`completed_owned` or `completed_empty`, never a complete package pass. Empty
assigned shards likewise do not receive executing-test credit.

The completion job uses fresh source/SDK/tool/full-environment, package and
complete root `-list=.` observations, then rereads every package's original
inventory, exact command, raw JSON root/child terminals and coverage. It
recomputes global ownership and requires the complete disjoint 32- or 64-shard union;
paired report/log deletions cannot shrink the fresh denominator. Artifact directories
may move; executable/tool/source identities and environment semantics may not.
Unknown, duplicate, missing, partial or foreign results fail. Tests that skip
remain explicit skip counters and `completed_with_skips`, never passed roots.
Any package failure is sticky while all other packages continue. Cancellation
retains pending/missing entries and owned subprocess cleanup.

A root with no tests or only benchmarks has one actual unfiltered execution,
owned only by part zero; other parts retain their actual listing observations
but execute no shard. These package executions do not invent named test passes.
Go's listing command itself enters package initialization and `TestMain` when
present, so this is not a claim that `TestMain` runs only once across jobs.
Benchmarks remain listed but are never executed without `-bench`.

Module scope also binds the actual Node interpreter, independently selected
LLVM 22 wasm linker, selected SDK's complete wasm runtime directory, and
`llvm-config --libfiles --link-shared` library files. When the actual selected
package graph contains the native Go LLVM binding, its selected source files
and an owned loader query bind the library actually providing
`LLVMContextCreate`. These are dependency observations, not runtime-test passes.
Missing dependencies fail. Nonempty `NODE_OPTIONS`, `NODE_PATH` and
`NODE_ICU_DATA` remain unsupported because their delegated runtime inputs are
not captured; their absent/empty values are recorded in the environment scope.

Coverage combines the checked profiles of **all** main-module packages, not
just the root. Mode, statement counts, overlaps and counter overflow are
validated. Owners never publish the uploadable module coverage file. Each root
fragment checks its own raw profiles into `partition.cover`; only successful
complete aggregation checks the full root profile union, combines all packages
and creates the uploadable module file. The original 45m test/coverage
and 60m race per-command budgets are unchanged, as are race/coverage flags.
Independent owners avoid sharing a single job's wall-clock budget. This is
not evidence that any particular giant test completes within that budget.

For a single local invocation use `-module` without `-module-owner`; it runs
the same complete inventory serially across packages. Select explicit
`GOENV=off GOWORK=off GOTOOLCHAIN=local GOFLAGS=` and the required LLVM 22 tools.
Use a clean checkout, new artifact/coverage paths, and an artifact directory
outside a nongit first-party fixture's source tree. Source-changing compiler
flags (`-overlay`, `-modfile`, `-gcflags`, `-asmflags`, `-ldflags`) remain
available in ordinary package mode but are not source-indexed by module mode.

The large shared-profile test package can use the same complete mechanism:

```sh
GOFLAGS= go run ./cmd/plan9asmtest \
  -package github.com/xgo-dev/plan9asm/gotoolprofile \
  -out _out/profile-test-partitions -shards 32 -workers 2 -timeout 45m -- -race -p=1
```

This runs the shared-profile package's Go tests, not the discovered-library corpus.

Ordinary single-package mode covers **only its selected package**, not root
`./...`, the nested CLI modules, strict stdlib/object gates or cross-runtime
jobs. Module mode covers all main-module packages, but the other independent
gates remain required. Without module mode, run every other main-module package
without repeating the root:

```sh
go list ./... > _out/non-root-packages.txt || exit 1
suite_status=0
while IFS= read -r pkg; do
  if [ "$pkg" != github.com/xgo-dev/plan9asm ]; then
    go test "$pkg" -count=1 -timeout=45m || suite_status=1
  fi
done < _out/non-root-packages.txt
test "$suite_status" -eq 0
```

Use the same race/coverage/build flags for those other packages when required.
Ordinary mode's coverage profile is root-package
coverage only, not a replacement for the original module-wide profile.

Build/instrumentation flags follow `--`, for example:

```sh
GOFLAGS= go run ./cmd/plan9asmtest \
  -out _out/root-partitions-race-cover -shards 64 -timeout 60m -- \
  -race -covermode=atomic -coverprofile=coverage-root.out -p=1
```

The tool can be built/run from a separate tool checkout while targeting a
clean frozen source checkout through `-dir /path/to/frozen-source`. Neither
checkout is edited. An absolute `-out` separates tool evidence from source.

The actual list and every execution use identical build flags. Each nonempty
partition has an independently generated coverage profile. Only after all
children and JSON validations succeed are the profiles merged into a **new**
destination, checking identical block/statement inventories and modes. `set`
counters combine by OR; `count`/`atomic` combine by checked uint64 addition.
Failed runs retain their separate profiles, not a misleading merged result.

Supported flags are `-race`, `-cover`, `-covermode`, `-coverpkg`, `-tags`, `-p`,
`-gcflags`, `-asmflags`, `-ldflags`, `-mod`, `-modfile`, `-overlay`, `-trimpath`,
`-asan`, `-msan` and `-work`. Filters, `-count`, `-fuzz`, benchmarks, custom
executors and test arguments are rejected. `GOFLAGS` must be empty, except that
Windows may inherit exactly `-tags=byollvm` when the same tag is explicitly
passed after `--`. This preserves the LLVM binding selection in nested Go
commands. Missing, conflicting or duplicate tags fail before execution; no
other inherited flags are accepted. Module scope retains the actual environment.
The runner forces `-count=1`; successful cached runs cannot replace execution.

## Proof and failure behavior

The sorted inventory hashes newline-separated names with SHA-256. Ordinary
roots retain the first eight bytes of their name's SHA-256, interpreted
big-endian modulo the shard count. In every instrumentation mode, complete
fixed-local object families use fixed semantic ordinals modulo that same count:
conversion target/batches
0–35, packed target/batches 36–47, CMOV target/batches 48–59, readonly targets
60–62, wide Translate/Module/GoModule object owners 63–65, and native-wide
whole-source batches 66–71, and native-conversion whole-source batches 72–78. Targets keep
Linux/Darwin/Windows order (CMOV has Linux/Darwin), and batches keep numerical
order. These roles distribute complete costly sources without moving ordinary
roots or changing ownership when input order, unrelated roots or a subset
changes. Plain and coverage runs need the same protection against cumulative
heavy-family collisions as race runs. Instrumentation flags remain strictly
validated and recorded; they never change ownership. Execution and both
independent receipt readers derive the same plan, never an implicit
host/environment setting.
An independent source-AST check retains all 79 roles. This is a
scheduling rule, not runtime qualification: exact current-head execution must
still fit its original deadlines. No role creates a missing listed test.
Sorting/sharding never deletes a name. Empty
partitions are explicitly recorded; an entirely empty inventory fails.
The exact escaped alternation selects every planned root in its partition.
A pattern over 16,000 bytes fails and asks for more shards; it is never cut to
fit command-line limits.

`report.json` retains the complete plan, commands, per-root/subtest/seed
outcomes, elapsed times, incomplete counts and errors. Raw actual inventory,
Go version, JSON and stderr logs remain alongside it. Each root must have one
actual run and one terminal pass/fail/skip; unknown, missing or repeated roots,
unterminated seeds, malformed JSON, failed package/child exits and timeouts
fail. Other partitions are still attempted after a failure. Existing Go skips
are counted separately from assertions passed; they do not prove execution of
the skipped semantics. Required cross/native counterpart jobs remain required.

The wall deadline also covers compilation; Go receives the same test timeout.
Combined stdout/stderr capture is bounded at 64 MiB per command. On Unix every
child owns a process group, terminated on cancellation **and ordinary exit**,
with a bounded output-pipe wait. Interrupt, TERM and HUP cancel owned groups.
This releases LLVM contexts between shards on Linux and Darwin.
Windows ordinary package partitions use a private non-breakaway Job Object.
The leader starts suspended and joins that job before its initial thread runs;
cancellation and ordinary exit terminate all descendants, including inherited
output-pipe holders. Cleanup waits for the actual Job's completion-port exit
notification, not merely accounting zero, and retains cleanup errors. Unrelated
processes never belong to that job. Other non-Unix systems still fail explicitly.
Windows module scope observes the real Go LLVM consumer's imported DLL, exact
LLVM 22 tools, source inventory and inherited/explicit `byollvm` selection. Only
the independent complete-module aggregate publishes coverage; partial root
ownership is `completed_owned`, never a whole-module pass.

Freeze source, environment and tools throughout a real suite run. Reports
describe the invoked Go tests, not assembly-ledger or external-module coverage.
The runner never deletes caller caches or modifies baseline/scan inputs.

## Selected cross-runtime CI owners

The required cross-runtime job uses a separate
`actual_go_selected_ci_partitions_v1` protocol. Its original complete five-prefix
selector is applied to the complete actual `-list=.` inventory and checked
against a second actual Go `-list=<selector>` observation with identical build
flags. Nonselected roots remain in the full inventory; benchmarks remain listed,
not executed. Ordinary schema-1 reports and full-root behavior are unchanged.

Sixteen jobs own the selected roots exhaustively and disjointly. The exact
`TestCrossLinuxRuntimeMatrix` root alone belongs to owner zero; the first eight
SHA-256 bytes of every other selected name, big-endian modulo fifteen plus one,
assign owners one through fifteen. There is no concurrency cap or fail-fast
matrix cancellation. Each owned root runs in a fresh bounded child with the
existing **20-minute** deadline and `-count=1`. Failures stay sticky while later
roots are attempted. Empty owners are explicitly receipted, not credited as
executing semantics. This mechanism does not prove the giant root itself fits
its unchanged deadline.

For example, with the required SDK/LLVM/cross tools already installed:

```sh
GOFLAGS= GOENV=off GOWORK=off GOTOOLCHAIN=local PLAN9ASM_CROSS_EXEC=1 \
  go run ./cmd/plan9asmtest -out _out/cross-runtime-owner \
  -ci-selector '^(TestCrossLinuxRuntimeMatrix|TestARM64Conformance|TestARM64RawSQSHLURuntimeSemantics|TestARMIntegerMemoryRuntimeCross|TestARMRawSaturationRuntimeCross)' \
  -ci-isolate-root TestCrossLinuxRuntimeMatrix -ci-owner 0 -shards 16 -timeout 20m
```

All sixteen artifacts are required by `-verify-ci-partitions <directory>`, with
the identical selector/isolate/shard/timeout/build configuration. It independently
recaptures both actual inventories and source/SDK/tool/environment scope,
recomputes ownership, and reads every root's bounded raw Go JSON and actual exit.
Missing, duplicated, foreign, incomplete, failed or skipped roots/subtests/seeds
fail completion. Paired plan/receipt deletion cannot shrink the denominator.
It also checks raw inventory/environment/version/tool-origin observations and
before/after guards. The required native tool names and bytes are retained;
cache and workspace spelling are not cross-job source identity. Inherited
`GOFLAGS`, user `GOENV`, workspace switching and toolchain fallback are forbidden.

The environment scope retains **every actual `go env -json` field**, including
unknown future fields and the complete compiler flags. Only explicitly named
SDK/source/storage roots and the Go-generated prefix-map temporary nonce are
normalized. That nonce must be a direct `go-build<decimal>` child of the observed
temporary root mapped to exactly `/tmp/go-build`; all other flag bytes, ordering
and quote spelling stay exact. Raw physical observations remain in artifacts
and the aggregate reconstructs this comparison independently. Lazy SDK tools
are resolved with the selected driver's actual `go tool -n`, not guessed paths.

Process controls are a separate explicit boundary: all `PLAN9ASM_*` and
`QEMU_*` variables, `SELF_BL_SINK`, LLVM/tool search, Go runtime, compiler include,
loader and sanitizer controls are retained. This does not claim complete ambient
machine/ISA/sysroot/library identity or copy unrelated CI credentials. Required
original/native preflights and runtime comparisons still determine those
semantics; hosted-runner labels are not ISA certificates.

Worker artifacts retain physical paths, failures and logs; matching source and
SDK content hashes permit separate checkout locations, not different source or
compiler versions. Test completion is not an assembly-ledger, external-library
runtime, or unexecuted architecture claim. Coverage-profile merging remains an
ordinary full-root feature rather than a selected-CI waiver.
External compiler-input flags (`-overlay`, `-modfile`, `-gcflags`, `-asmflags`,
`-ldflags`) are not registered in this initial CI protocol: its source guard
cannot silently authenticate files supplied outside the checkout. Ordinary
mode keeps its existing support for those flags.
External cache/package drivers and compound compiler-wrapper commands likewise
remain unregistered. The native scope binds the actual `CC`, `CXX`, `AR` and
`PKG_CONFIG` executable bytes as well as the required LLVM/cross/QEMU tools.
