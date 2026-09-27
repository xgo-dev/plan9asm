# Validation and contribution completion

## Toolchain

Develop and test external libraries with the current Go 1.27 patch. Put that
Go binary in `PATH`: setting only `GOTOOLCHAIN` is insufficient because corpus
subprocesses deliberately use `GOTOOLCHAIN=local`. The separate official
compatibility matrix retains Go 1.20–1.27.

```sh
go127_root=$(GOTOOLCHAIN=go1.27.1 go env GOROOT)
export PATH="$go127_root/bin:$PATH"
export GOTOOLCHAIN=local

go version
source scripts/llvm22.sh
llc_cmd=$(find_llvm22_llc)
"$llc_cmd" --version
```

Use LLVM 22 exactly. `scripts/llvm22.sh` accepts `llc-22`, an unversioned `llc`
reporting version 22, or `LLVM_CONFIG` pointing to LLVM 22. On Homebrew hosts:

```sh
llvm22_root=$(brew --prefix llvm@22)
export PATH="$llvm22_root/bin:$PATH"
export LLVM_CONFIG="$llvm22_root/bin/llvm-config"
```

Missing required LLVM tools, linkers or supported backends fail, never skip.
Host-inapplicable execution belongs in the required cross-runtime CI job;
object tests must still cover affected architectures.

## Local gates

Run focused red/green tests first, then the relevant full gates. Capture logs
under ignored `_out/`; a nonzero exit remains a failure. The full root suite
can exceed Go's default ten-minute timeout, so give it an explicit limit.

```sh
go test ./... -count=1 -timeout=20m
(cd cmd/plan9asm && go test ./... -count=1)
(cd cmd/plan9asmll && go test ./... -count=1)

test -z "$(gofmt -l .)"
git diff --check
go vet ./...
go build ./...
(cd cmd/plan9asm && go build ./...)
(cd cmd/plan9asmll && go build ./...)

scripts/check-go-asm-coverage.sh
scripts/check-arm64-plan9-corpus.sh
scripts/check-stdlib-corpus.sh
scripts/benchmark-compile.sh

scripts/check-reported-library-corpus.sh all
PLAN9ASM_DISCOVERY_PARALLELISM=4 \
  scripts/check-discovered-library-corpus.sh all 32
```

Run race tests for changed concurrent code and focused Go 1.20 compatibility
checks for root-module code. Do not expand external-module tests into the
whole compatibility matrix.

```sh
go test . -run '^(TestAMD64ConformanceNativeGo|TestAMD64ConformanceLLVMRuntime)$' -count=1 -v
PLAN9ASM_CROSS_EXEC=1 go test . \
  -run '^(TestCrossLinuxRuntimeMatrix|TestARM64Conformance|TestARMIntegerMemoryRuntimeCross)' \
  -count=1 -v
```

The cross driver runs on Linux/amd64 with matching cross compilers and QEMU.
Install the pinned QEMU 10.2.3 user-mode tools with
`bash scripts/install-ci-qemu.sh`, then prepend
`$PWD/_out/qemu-10.2.3-linux-amd64` to `PATH`. The script checks the release
SHA-256 before installation and updates `GITHUB_PATH` in CI. It does not
register kernel binfmt handlers or replace system packages. Ubuntu 24.04's
QEMU 8.2 has an indexed SVE dot-product correctness/overflow bug fixed by
[QEMU e6b2fa1](https://github.com/qemu/qemu/commit/e6b2fa1b81ac6b05c4397237c846a295a9857920).
For i386, also install `gcc-i686-linux-gnu` and `libc6-dev-i386-cross`;
missing tools must fail. Use disposable containers/caches, not the remote
inventory server, to compile or execute external code.
When the container's temporary directory is tmpfs-backed, enable execution
(for example `--tmpfs /tmp:rw,exec,size=2g`); Go test binaries must run there.

## Official coverage and benchmark

The official gate checks classifications, parse errors and versioned form
fingerprints. Inspect form-level differences before changing
`testdata/coverage/go-asm-baseline.json`; never bless a fingerprint just to
make CI green. Observed-corpus forms, all encoder-table rows and runtime
semantics are different coverage measures. Preserve explicit historical
compatibility exceptions instead of silently relabeling them.

The strict benchmark compiles standard-library assembly for
`linux/{386,amd64,arm,arm64}` and `js/wasm`. Every applicable file must translate
and compile: failures, skips and N/A fail the job. Reports live under
`_out/compile-benchmark/`; CI detail logs use collapsible groups.

Default budgets are 300 seconds per target and 900 seconds total. Diagnostic
overrides are `PLAN9ASM_BENCHMARK_TARGETS`,
`PLAN9ASM_BENCHMARK_MAX_TARGET_SECONDS`,
`PLAN9ASM_BENCHMARK_MAX_TOTAL_SECONDS` and `PLAN9ASM_BENCHMARK_REPORT_DIR`.
Measure before changing budgets or claiming a performance improvement.

## Frozen verification

Commit first, rebuild tools with VCS stamping, and keep the checkout and ledger
unchanged until corpus verification finishes. A separate persistent worktree
allows development to continue. Reports under `_out/` may be written without
changing tracked source.

The aggregate requires all 32 schema-6 reports, exact candidate ownership and
one identical source/ledger/tool provenance. Never mix revisions, dirty builds,
tool binaries or partial CI artifact sets. Even documentation changes alter the
source fingerprint: old reports prove only their exact revision, not current-
head success. See [discovery verification](discovery-verification.md).

## PR completion

- Fetch upstream and inspect divergence before final verification; do not
  rebase or rewrite a running frozen snapshot. Inspect the push remote.
- Push only to the allowed contribution fork. Update the contribution PR;
  never merge/approve/close the upstream PR.
- Keep the PR draft until current-head local tests, CI, review and required
  coverage pass. Function-level coverage is not Codecov patch approval.
- Distinguish actual failures from runner/proxy/timeout failures. Neither may
  become success/N/A. Inspect logs/annotations before attributing a cause.
- Put scan/coverage funnel tables in the PR body, derived from validated
  manifest/reports. Include index entries, exact versions, unique modules,
  assembly versions, retries, passing/N/A/failing candidates, instruction-family
  changes, and whether processing is complete.
- State denominator and cutoff for ecosystem percentages. Independent inventory
  is a pending test queue, not committed or tested coverage.
- Verify issue libraries were found independently by Discovery, not only added
  to the curated manifest. Report exact versions and outcomes.
- Preserve failed evidence. Never hand-upgrade reports or hide unfinished work
  behind aggregate counts or object-compilation success.
- Keep obsolete compressed/run records out of contribution history as well as
  the final tree. A necessary rewrite uses `--force-with-lease` only on the
  allowed fork after checking for remote changes.
