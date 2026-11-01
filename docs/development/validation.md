# Validation and contribution completion

## Toolchain

Develop with current Go 1.27 and LLVM 22 exactly. The official compatibility
matrix retains Go 1.20–1.27. Put the selected Go binary on PATH: subprocesses
deliberately use `GOTOOLCHAIN=local`.

```sh
go127_root=$(GOTOOLCHAIN=go1.27.3 go env GOROOT)
export PATH="$go127_root/bin:$PATH"
export GOTOOLCHAIN=local
source scripts/llvm22.sh
llc_cmd=$(find_llvm22_llc)
"$llc_cmd" --version
```

The helper accepts `llc-22`, an unversioned `llc` reporting version 22, or
`LLVM_CONFIG` pointing to LLVM 22. On Homebrew hosts:

```sh
llvm22_root=$(brew --prefix llvm@22)
export PATH="$llvm22_root/bin:$PATH"
export LLVM_CONFIG="$llvm22_root/bin/llvm-config"
```

Missing required LLVM tools, linkers or backends fail, never skip.
Host-inapplicable execution requires its cross-runtime CI counterpart.

RCP14/RSQRT14 original-Go bit, MXCSR and masked native-memory execution has
explicit hardware qualification owners. On direct Linux/amd64 with enabled
AVX512F register state, use the F owner; packed X/Y additionally require VL:

```sh
PLAN9ASM_AVX512_RUNTIME=required go test . -tags=plan9asm_native_avx512 \
  -run '^TestX86Reciprocal14Native(F|VL)AMD64$' -count=1 -timeout=20m
```

The tag does not affect ordinary source/trace/actual-Go/three-API object tests.
Darwin and native Linux/amd64 additionally compile and link the C fixtures
without executing them; their receipts identify the actual x86_64 target.
Default CI does not execute these two native owners. Missing hardware, tools or
CPU/OS-state proof fails explicit qualification; `auto` cannot turn it into a
passing skip. Until successful original-Go and every native pipeline/fault
receipt exists, native RCP14 acceptance remains pending. These owners do not
certify native386, AC-enabled faults, raw continuations or the two Context-only
repeated opaque-pointer-index address constructions.

CI also verifies the actual installed Go against the installer's resolved
version and uses the shared exact Node22.23.4 action. A successful installer
outcome without its version output is not a valid tool observation.

The rich CLI's complete ARM64 fallback-frame oracle runs natively on supported
ARM64 hosts and under pinned QEMU in the required Linux cross job. One outer
owner runs its exact nested-module root; a fresh strict reader verifies both
logical partitions and all four required children. Cross scopes bind the actual
Node auditor through the shared tool observer. Object-only Windows skips do not
establish execution of its 512 input rows.

Darwin native C oracles query the actual selected macOS SDK with bounded, owned
`xcrun --sdk macosx --show-sdk-path`, require one complete absolute existing
directory, and pass `--no-default-config -isysroot` to the independently checked
LLVM 22 clang. `DEVELOPER_DIR` selects the actual developer tools; `SDKROOT` and
CGO flags alone cannot override a hard-coded clang default configuration. Do not
edit global clang configurations, guess an SDK version or substitute another
LLVM. Missing SDK selection fails. The shared `internal/nativeoracle` helper is
test-driver configuration, not source/ABI authority; exact downloaded-source
oracles retain their additional live SDK/tool/file identity observations.

## Local and CI gates

Run focused RED/GREEN tests first; preserve failures under ignored `_out/`.
Before choosing a family selector, enumerate its canonical row/object roots and
all changed regression owners. Check every name against the selector and the
actual JSON RUN/terminal inventory; a broad-looking prefix can omit legacy
owners. When width or alias semantics change, also audit rejection assertions
in indirect consumers, such as masked broadcasts seeded by KMOV. Keep source-row,
witness, module-object and executed-case counts separate.
An object helper's O0 pass does not establish O2: verify the actual compiler
options for each API/module before reporting either level.

Freeze each qualification snapshot. When only one test owner is strengthened,
unaffected evidence may be inherited through explicit file/function and tool
identity; rerun the changed owner and any omitted roots. Identify both revisions
and never describe inherited evidence as a fresh execution. Preserve erroneous
scope reports alongside their corrections.

Then run the relevant complete gates:

```sh
go test ./... -count=1 -timeout=45m
(cd cmd/plan9asm && go test ./... -count=1 -timeout=30m)
(cd cmd/plan9asmll && go test ./... -count=1 -timeout=30m)
go vet ./...
go build ./...
test -z "$(git ls-files -z -- '*.go' | xargs -0 gofmt -l)"
git diff --check
node --test .github/scripts/priority-*.test.cjs

scripts/check-go-asm-coverage.sh
scripts/check-arm64-plan9-corpus.sh
scripts/check-stdlib-corpus.sh --instructions-only
```

Changes to test helpers, resource ownership or workflows require the complete
Node policy suite above and the exact Go selector in the `ci_policy` job of
[go-ci.yml](../../.github/workflows/go-ci.yml) before publication. Use Node22.23.4;
focused instruction or lifecycle tests do not check these static contracts.

The [exhaustive runner](../../cmd/plan9asmtest/README.md) can partition expensive
first-party tests without sampling. Its actual inventory, disjoint ownership,
raw outcomes and strict complete-module aggregate remain required. Owner 0 owns
the root package, owner 1 `gotoolprofile` and `internal/sdkfrontend`, owner 2
all remaining packages. The SDK frontend's independent original-source roots
use the same exhaustive partitions and two-worker bound as the profile package,
so their repeated captures do not accumulate in one unfiltered race command.
Both owner-1 packages run serially, with no nested package-worker pool.
Only explicit owner 2 uses the existing worker limit across whole packages.
Each package remains an unfiltered one-shard/one-worker command, and the single
collector preserves inventory order and joins active processes on cancellation.
Ordinary suites may use `-workers 2`; one collector owns report/coverage writes.
The runner's own complete regression suite can use the same exhaustive mechanism:

```sh
go run ./cmd/plan9asmtest -dir=cmd/plan9asmtest -shards=8 -workers=2 \
  -timeout=15m -out=_out/runner-suite
```

Require its fresh complete inventory, unique root/child terminals and no failed,
skipped or incomplete tests. This is a separate partitioned qualification, not
a pass for a previously timed-out single-binary command. Formal main-module
ordinary/coverage commands retain45m and race commands60m.

Root scheduling parts do not change the test denominator.
Unix normal and coverage suites use sixteen root parts over the same32 global
shards; race uses32 parts over64 shards. Each Unix root job owns exactly two
whole shards in one two-worker wave, avoiding cumulative multi-wave job limits.
Command and job budgets are unchanged, and fresh completion requires every
part plus the original profile/rest owners. Windows keeps all
three modules independent: sixteen root parts for the main module over
64 hash shards (four shards per part), four parts per CLI, and one profile/rest
owner each. Every command retains the thirty-minute budget;
only complete cross-owner verification publishes the module's coverage. The
Windows driver binds inherited and explicit `-tags=byollvm` without fallback.
It selects Go, LLVM22, Node, Python and jq before freezing a minimal tool PATH
for both execution and aggregation. Ambient hosted Git runtime-bank and WSL
entries are not inherited. Complete environment equality remains strict; never
remove PATH from the verifier to accept unrelated execution environments.
The readonly DATA consumer matrix has three complete target roots, placed in
different Windows scheduling owners. Each retains all119 operations, all three
APIs and O0/O2 objects; root splitting is not a reduced test denominator.
The two current-Go bytealg CLI object owners likewise keep complete Count and
IndexByte files in separate scheduling owners, each with its own original
five-minute context. A previous root shared that context across both files;
the second file's cancellation was a real failure, not source rejection.

Repeated ARM64 byte-carrier matrices share only a parent-test-owned `GOCACHE`.
Recent Go distributions build builtin observers such as `objdump` there;
recreating an empty cache for each row repeats that build and can exhaust the
unchanged one-minute command limit. Each case still captures independent
original sources, outputs, leases and revocable owners. Do not share those
mutable observations or increase command budgets to hide cache setup costs.

Static-storage capture retains its actual forced stock-Go compiler prior and
original command report. Every live Verify still runs a real owned selection
and export query with the same scope, environment and deadline, but omits only
the repeated `-a` rebuild. Complete source, tool and archive bytes remain
checked before and after that command; selected exports and unknown JSON fields
must still match. This is reuse of Go's compiler cache, never a cached mutable
observation or capability. Run actual SDKCPU and SDKGlobals target controls,
source/command mutation, final callback revocation and concurrent Close tests,
then measure the complete original CLI source before claiming a speedup.

Fixed-local conversion objects keep all741 independent forms on each of three
AMD64 targets. Twelve top-level batches per target retain64 functions each
(37 in the last batch), captured as two sources of at most32 functions with
separate five-minute leases for every API. They retain all three APIs and both
IR levels. Native execution independently owns all336 cases in seven48-case
top-level roots with original Go, CPU/OS checks and LLVM O0/O2 execution.
The inventory policy
requires every target/batch exactly once and at most three such owners per
Windows hash shard. A passing batch is not a complete-target receipt: require
the exact union of all twelve, without skipped or unfinished children.

Each fixed-local API captures, preprocesses, binds and consumes its own complete
source within the original five-minute stage context, then closes that owner.
Never reuse another API's lease or cache a mutable Verify result. Wide packed
objects retain all340 kernels in six complete source packages per API, all three
optimization paths and independent top-level API owners. Only compiler artifacts
share a disposable test-process-owned cache; initialize it even when ambient
GOCACHE is unset. Object-only tool selection checks LLVM22 and the actual
target SDK/headers without requiring Rosetta, QEMU or a host ISA preflight.
Original Go compilation, C compilation/linking and native execution remain
distinct claims; the original native owners keep their real CPU/OS checks.

This lifetime rule also covers complete readonly DATA, AES, transport and
non-temporal consumers. Keep DATA/GLOBL in the exact preprocessed GoModule input;
reconstructing only function instructions loses part of that source. Extend the
existing complete-consumer lease checks when adding a family. Negative tests for
expired, mutated or closed observations must retain their original binding,
not silently capture a replacement.

The complete native-wide packed matrix has six required top-level source owners,
not six children under one shard deadline. Batch selection accepts either no
selector (the unchanged compile-only/SSE path) or one valid whole source batch;
empty inventories, invalid indices and multiple selectors fail closed. Keep the
340-kernel source/C union, original whole Go execution, six values/masks, all64
result bits, three APIs and three LLVM pipelines. Splitting ownership does not
raise an API, command or job deadline and is not local native execution proof.

CMOV fixed-local objects likewise retain all384 original kernels per Linux and
Darwin target in six independently scheduled batches. Runtime keeps all387
CMOV/GP/SIMD kernels in seven batches, their three optimization paths and actual
original-Go execution. Require every batch exactly once; a single passing
batch or structural partition check is not a complete-family runtime receipt.

```sh
go run ./cmd/plan9asmtest -module -out _out/module-suite \
  -shards 32 -workers 2 -timeout 45m
```

Run race tests for changed concurrent code and actual Go 1.20 checks for changed
root-module code. Current-SDK producer fixtures use explicit `go1.27` build
roles; historical lanes still test their portable framework. Do not add runtime
skips or `!llgo` tags to hide incomplete compiler support.
The rich CLI's separate `cmd/plan9asmll` module declares Go1.24 as its minimum.
The root's Go1.20 checks and eight-SDK assembler-table audit do not imply that
this nested module builds with Go1.20; test its declared minimum independently.
Run the formatting check with the selected current Go toolchain. Limit it to
tracked sources: ignored `_out/` holds deliberately unchanged historical failures
and generated observation inputs, not repository formatting targets.

## Native and cross-runtime semantics

The original scalar-precision, unsigned-scalar, FMA-caller and packed-ABS/sign
native tests support `PLAN9ASM_AVX512_RUNTIME=required|auto`. The default is
`required`: missing CPU/OS capabilities fail. Windows CI explicitly uses `auto`
for all execution and completion owners. Only a complete, matching CPUID/XCR0
receipt with an ordinary capability-unavailable exit78 becomes a reported SKIP.
Capable hosts still execute the original runtime test. Invalid configuration,
missing tools, compilation errors, crashes, timeouts, cleanup errors and opcode
or numerical failures remain failures. Other runtime owners are unchanged.

Instruction-generation, LLVM22 objects and backend-ISA checks stay mandatory
on every host, independent of this setting. Reports retain skipped roots and
`completed_with_skips`; object success never certifies skipped native execution.
Use `PLAN9ASM_AVX512_RUNTIME=required` on a suitable machine for native acceptance.

```sh
go test . -run '^(TestAMD64ConformanceNativeGo|TestAMD64ConformanceLLVMRuntime)$' -count=1 -v
PLAN9ASM_CROSS_EXEC=1 go test . \
  -run '^(TestCrossLinuxRuntimeMatrix|TestARM64Conformance|TestARMIntegerMemoryRuntimeCross)' \
  -count=1 -v
```

The cross driver runs on Linux/amd64 with matching cross compilers. Install
checksum-pinned QEMU 10.2.3 using `bash scripts/install-ci-qemu.sh`, then prepend
`$PWD/_out/qemu-10.2.3-linux-amd64` to PATH. Ubuntu 24.04's QEMU 8.2 has an SVE
indexed dot-product bug. For i386 also install `gcc-i686-linux-gnu` and
`libc6-dev-i386-cross`. Missing tools must fail. Containers need executable
temporary storage for Go test binaries.

## Official forms and benchmark

An ordinary Go assembler rejection requires actual exit 1 plus a concrete,
fixture-bound diagnostic. Panic, timeout, signal, unknown output or cleanup
failure is not rejection evidence. `TestGoAssemblerKnownMalformedInputDefects`
separately observes known Go assembler bugs without treating them as successful
form coverage or external-library applicability evidence.

The official gate checks classifications, parse failures and versioned form
fingerprints. Inspect differences before changing
`testdata/coverage/go-asm-baseline.json`. Opcode names, observed corpus forms,
encoder rules, LLVM objects and runtime semantics are distinct coverage claims.

To retry the complete x86 mask-logical family with explicit initialized inputs:

```sh
go run ./cmd/plan9asmscan -corpus=go-asm -goos=linux -goarch=amd64 \
  -initialized-context-reprobe=mask-logical -llc="$llc_cmd" -format=json \
  -out=_out/initialized-mask-logical.json
```

This opt-in report retains every actual instruction occurrence and its source,
keeps the original classifications/fingerprint unchanged, and records separate
IR and LLVM22 object outcomes in batches of at most32 functions. Missing/wrong
LLVM, failed compilation or missing/wrong-target objects fail the command.
Synthetic initialized inputs are not original-source or runtime evidence;
unregistered families and runtime remain explicitly untested. The same profile
accepts `-goarch=386`, but cannot invent forms absent from that SDK's corpus.

The strict benchmark compiles standard-library assembly for
`linux/{386,amd64,arm,arm64}` and `js/wasm`. Failures, skips and N/A fail the
job. Schema-2 summaries retain failed and unattempted counts; missing reports
remain unknown. Reports under `_out/compile-benchmark/` are never overwritten.
Default budgets are 300 seconds per target and 900 seconds total. Diagnostic
overrides use `PLAN9ASM_BENCHMARK_TARGETS`,
`PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS`,
`PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS` and `PLAN9ASM_BENCHMARK_REPORT_DIR`.
Measure before claiming a speedup or changing budgets.

PR Go CI runs `check-stdlib-corpus.sh --instructions-only` with the complete
SDK/target/profile matrix and official instruction fingerprints. WASM retains
complete source translation and every LLVM object because its typed stack and
control flow cannot be checked as isolated instructions. Other architectures
stop after successful instruction scanning in this mode. Default
`check-stdlib-corpus.sh` still translates complete source and compiles LLVM
objects. That same complete matrix and the unchanged strict benchmark run in
the separate manual/weekly `SDK/runtime integration` workflow. Its failures
remain failures; this responsibility split does not qualify historical failed
reports. Required instruction, CLI/object, native, race and coverage owners stay
in PR CI.

## Frozen verification and PRs

Commit first and keep a tested snapshot unchanged, including documentation.
Develop in another existing idle worktree while a frozen suite runs. A partial
suite or older-source pass cannot certify current-head success.

Inspect remotes and upstream divergence before publishing. Push only to the
allowed fork, create/update the contribution PR, and never directly push,
merge, approve or close upstream PRs. Batch updates so active frozen runs can
finish. Keep PRs draft until current-head CI, review and coverage pass.

External scanning, ledgers, exception policies and third-party compatibility
CI are now owned by [llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm).
Do not restore them here or gate instruction tests on their historical pending
inventory. Independent instruction regressions and required first-party source
proof tests remain in this repository; moving a workload is not a test pass.
