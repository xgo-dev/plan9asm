# PR40 closeout

Updated 2026-11-04. Finish AMD64 correctness, typed-family convergence and
translation efficiency while preserving the 386, ARM, ARM64 and WASM gates.
Read [architecture](architecture.md), [instruction families](instructions.md),
[convergence](x86-convergence.md) and [validation](validation.md).

The [contribution description](https://github.com/xgo-dev/plan9asm/pull/40)
records the latest staged revision, CI and remaining work. Check actual Git
status and contribution heads before continuing; a dated local result cannot
certify a later head. Run new CI in the allowed fork and prioritize affected
complete owners before the remaining source/CLI owners.

## Accepted baseline

Product `940dbf7ecef9b32ab6bc96e8fb42519430c45171` completed
[49/49 fork jobs](https://github.com/cpunion/plan9asm/actions/runs/41794972485),
with all 56 required artifacts validated. Ordinary source/CLI reports contain
441,520 PASS and 307 explicit SKIP, zero FAIL. The separate forced-runtime
component has 535 root and 3,954 child PASS, zero SKIP/FAIL; five required
rich-CLI ARM64 nodes also RUN/PASS. Node policy 579 and Go policy 484 pass.
Statement coverage is 88.5% main and 70.5% / 79.1% CLI.

This baseline changes only two consumer-order assertions from `c395df92b7ac`;
all production blobs remain identical. Its complete SDK declaration, physical
frame, source-selected native component and Go-funcval contracts remain
separate from numerical instruction forms. Later local changes need their own
qualification; baseline results are not silently inherited.

## Tail and syscall batch

External validation exposed two source-contract classes in a complete x/sys
assembly file. Keep that source unchanged and independently reproduce each
class in this repository.

- Imported ordinary ABI0 tail stubs join actual caller/import declarations and
  exact frame layouts through the existing direct-tail graph. Preserve the old
  same-package path. Check only selected function types with Go's type checker
  and target sizes; body-only imports absent from export data grant nothing and
  must not reject an otherwise identical signature. Recheck after resolver
  callbacks. Manual signatures alone do not supply the imported source role.
- Named Linux AMD64 `SYSCALL` shares one target/form/effect descriptor with its
  raw-kernel emitter. Preserve raw negative errno and DX; never substitute
  libc's errno-changing wrapper. Seven complete numerical inputs are required;
  logical/private frame addresses, old CX/R11 and FLAGS do not acquire roles.
- Existing elided scheduler hooks must use the same finite semantic predicate
  in emission and paired auditing. They do not provide an ordinary Go-call
  prototype or implement a complete runtime scheduler contract.

Focused regressions live in `x86_go_imported_tail_test.go` and
`x86_linux_syscall_test.go`. The default Linux/amd64
`TestCrossLinuxRuntimeMatrixAMD64LinuxRawSyscall` executes original Go plus all
three translated APIs, both IR optimization levels and both backend levels,
against the independent C errno/DX/I/O/canary oracle. Other hosts' object or IR
success does not count as execution of this owner. Qualification requires the
complete affected current/minimum-SDK union and publication policies, then the
final fork source/CLI owners and actual LLGo program validation.

## Separate integration boundaries

[LLGo PR2694](https://github.com/xgo-dev/llgo/pull/2694) owns the compiler-side
adaptation. Its staged `7a956ca4` completed all three adapter/build/CL jobs:
4,928 PASS, 60 explicit SKIP, zero FAIL. Reported-library full-program checks
and the next dependency pin retain separate exact source/compiler identities.
An official fixed upstream plan9asm tag is still required before LLGo merges;
a public fork pseudo-version does not close that review condition.

The 65 tagged AVX512 owners remain hardware pending. Strict SDK/runtime history
remains 41/55 PASS and 14 separate gaps in
[issue47](https://github.com/xgo-dev/plan9asm/issues/47). Do not promote these
boundaries, classified context forms or cancelled jobs into successful runtime
coverage. Keep contributions draft until their current tests, CI and review pass.

External scanning, ledgers and compatibility batches belong to
[llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm). No inventory job
runs locally. Never restore those workloads to the translator's PR CI.
