# PR40 closeout

Updated 2026-11-03. Finish AMD64 correctness, typed-family convergence and
translation efficiency first. Preserve the 386, ARM, ARM64 and WASM gates.
Use the [architecture](architecture.md), [family guide](instructions.md),
[convergence notes](x86-convergence.md) and [validation](validation.md).
External compatibility discovery belongs to
[llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm).

## Published evidence

The accepted fork head is `f32575c824b2a8759fcf1941b7a47e6b35e047b8`.
Its [own complete CI](https://github.com/cpunion/plan9asm/actions/runs/41451548879)
finished **325/325 SUCCESS**, attempt one, without reruns or cancellations.
Independent acceptance binds the actual merge checkout and all 286 source
artifacts, 240 partitions, 23 groups and three required aggregates.
Windows and race each retain 22 packages and 168 raw streams; original SKIPs
remain distinct from passes. Sixteen cross-runtime owners and their fresh
collector join 531 roots / 3,897 children, all PASS without SKIPs.

The 22 fresh main-module profiles report **88.4% statement coverage**.
Codecov patch coverage is **91.39% >= 86.86%**; project coverage is 89.16%.
All 327 exact-head checks succeed, including the two Codecov checks.
This is fork CI evidence: upstream [PR40](https://github.com/xgo-dev/plan9asm/pull/40)
still has published head `b531c83c7c810640cd6e04ab70e6422e440fd5d4`.
Neither that older head nor the accepted f325 round certifies a later candidate.
Both contribution PRs remain draft; no formal approval is recorded.

## Source coverage and boundaries

The independently joined AMD64 source union retains 67 overlapping views per
SDK and 64 canonical snapshot files across both SDKs:

| SDK | AVX | optab | ymovtab | Joined source identities |
|---|---:|---:|---:|---:|
| Current | 3,568 | 1,306 | 112 | 4,986 / 4,986 |
| Minimum | 3,568 | 1,305 | 112 | 4,985 / 4,985 |

Thirteen Zpseudo and four Zbyte rows, plus the ymovtab sentinel, stay separate.
Preserve overlapping rows, first-match selection, frontend refusals,
backend-only observations and physical-mode restrictions.
**Source identity is not IR, LLVM-object or runtime evidence.** A complete row
union does not prove complete functions, whole-library translation or execution.
All five architectures retain their own grammar, source, object and runtime
owners; no AMD64 count is a denominator for another architecture.

## Candidate after f325

The instruction follow-ups through `3c05ab50b` are published at fork head
`deb6157f4`. Its [own CI](https://github.com/cpunion/plan9asm/actions/runs/41506944925)
finished with source-contract failures. All 202 failed source jobs and eleven
derived collector failures were independently audited; their 8,123 failed case
identities belong to the repaired local scope. One runner-acquisition
cancellation remains an infrastructure outcome. Local follow-ups
retain the original cases, add genuine unknown/partial-address negatives and
check accepted numerical native accesses through LLVM objects. The local repair
union passes 110 roots / 40,747 nodes on both endpoint SDKs without FAIL/SKIP.
The minimum SDK is a fresh complete run; the current SDK combines the unchanged
production snapshot with all affected shared-helper consumers. The later
`3c460f567` candidate has its own
[focused fork CI](https://github.com/cpunion/plan9asm/actions/runs/41571716829):
eight jobs pass, with 110 roots / 40,747 nodes per SDK and zero FAIL/SKIP.
Actual raw lifecycle records include all eleven scanner roots. The first
diagnostic attempt passed the root package but invoked the scanner from the
wrong module directory; its failure records remain separate. This focused
acceptance does not certify the complete 325-job matrix or a later candidate.
Upstream task CI is stopped; stage subsequent verification in the fork.
The bounded follow-ups cover CPUID leaf/subleaf input dependencies, initialized
NUM addresses only in paired native read/store consumers, movemask dependency
continuation, selected same-module CPP inputs and function-local proof budgets.
Standalone pointer/caller permissions and source ownership remain independent.

The partial-result candidate separates ordinary mixed-bool code generation
from the strict numerical output-initialization audit. Inputs, CFG, stack,
canonical bools and source replay still pass their existing checks; the actual
strict error remains cached and cannot grant complete-proof storage permission.
The final adjacent suite passes **46 roots / 2,352 nodes per SDK** with zero
FAIL/SKIP and identical case IDs. Each SDK executes 72 portable caller pipelines
and 288 values at LLVM 22 O0/O2, including low/interior-byte observations. The
complete type matrix has O0 objects; this is not native386 qualification. The
movemask union separately passes 6,618 nodes per SDK and 108 portable executions
per SDK. The three-target dependency/export role union passes 72 nodes on the
current SDK. Final combined policy and CLI gates remain required.

Ordinary module capture now uses the same actual-package boundary as SDK
capture, rather than recursively retaining unimported descendants. The source
change removes four net production lines without raising the 128 MiB limit.
Both endpoint SDKs pass 24 roots / 116 nodes, with the original over-budget and
source-mutation controls retained. Real compress qualification needs a rerun.

The independent frame factory now retains direct child-directory identities
without recursively reading unrelated contents. Its 256-member / 16 MiB bounds
are unchanged. Fresh complete frame suites pass 27 roots / 305 nodes on the
current SDK and 26 roots / 220 nodes on the minimum SDK; the current-only mixed
data test accounts for the difference. Ten downloaded-frame owners pass 121
nodes. Final Node and Go policy suites pass 574 and 484 nodes, without skips.

Unmasked scalar SQRT now preserves ordinary native memory reads through LLVM
optimization, using the existing observable reader. Previously a literal-null
read could disappear and leave a register SQRT operating on `undef`. Independent
SS/SD regressions pass 161 nodes per SDK; the adjacent union passes 41 roots /
1,474 nodes per SDK. Linux/amd64 emulation reproduces the old fault mismatch and
passes all 12 fixed executable pipelines, with 288 memory outcomes and 60 fault
classifier controls. This is actual emulated execution, not physical-hardware
acceptance. Required Node and Go policies pass 574 and 484 nodes at `55b480d6f`.

The local fixed-frame follow-up admits initialized numerical addresses through
the existing native-access path, without creating private-frame or pointee
permissions. Its production change adds twelve lines. Current and minimum SDK
adjacent suites pass 489 and 399 nodes respectively; SDK-specific source owners
account for the difference. Linux/amd64 emulation passes twenty nodes, including
288 numerical-address fault observations and independent valid-store redzones.
This component still needs the combined candidate's gates and fork CI.

Ordinary ABI0 vector scratch may use the emitter's existing zeroed X/Y/Z
allocation widths for code generation. This declaration-level refinement does
not initialize physical entry registers or any GP, mask, flag, frame or pointer
state. The strict audit error stays cached. Standalone source observers retain
their original result, and instruction probes reuse the paired audit without
an emitter allocation plan. Both SDKs retain all five official-form baselines
unchanged; no Context forms are promoted by the scratch choice.

The original four GoHex assembly functions pass 54,176 original-Go calls and
650,112 translated calls across twelve LLVM execution pipelines under explicit
Linux/amd64 emulation. The source/tool identity bridge preserves those results
through the later allocation-plan guard and probe changes. These executions
do not certify the complete GoHex package or canonical target matrix.

The combined follow-up needs its own source-bound final gates and coverage.
Do not copy f325 coverage or successful checks onto it. External canonical
module qualification for the latest two-candidate batch is **0/2 PASS**; two compress object
logs are object observations only. Rerun the complete canonical batch at the
new head before claiming library-level progress.

## Remaining qualification

The 65 tagged native AVX512 owners remain **hardware pending**. Default grammar,
original Go bytes, LLVM 22 objects and retained SSE/VEX owners stay required.
Tagged compilation or absent hardware never counts as native execution.
Native386, ER/BF16/FP16 and other separate runtime boundaries retain their own
requirements. The historical strict SDK/runtime result remains **41/55 PASS,
14 FAIL**, tracked in [issue47](https://github.com/xgo-dev/plan9asm/issues/47).
No newer instruction-only result relabels or closes those failures.

[LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) is published through the
fork at `d72552acccab2be347eff6d57fd5d1c0211565d3`, rebased on upstream
`043c98b0f6636de5cb2380fc0955399f7133ad0f` and pinned to `3c460f567` through
normal module authentication. Its fresh adapter/build suite passes 218 nodes
and all five policy scopes pass 228 nodes, without FAIL/SKIP. Actual Linux/amd64
emulation compiled, linked and ran the reported CRC32 and libc ABI0 probes at
the final pin; an explicit compiler-source identity bridge covers the later
tool/documentation-only rebase. This is not complete SQLite or purego runtime
acceptance. The current native ARM64 function-value round-trip builds but still
fails during execution; its one-word unsafe storage assumptions need separate
LLGo compatibility work. Preserve that failure instead of calling libc wrapper
success a complete library pass.
The P1 requires an official upstream fix **and tagged release before merge**;
a fork pin or successful CI does not resolve it. Keep draft status and record
zero formal approvals until an actual review changes that state.

Detailed earlier components, failures and measurements remain in the
[immutable history](https://github.com/cpunion/plan9asm/blob/dfab0bf818b9e09eacbd8a1a2b8df7b8fc5227be/docs/development/current-work.md).
Use Go 1.27, immutable Go 1.20.14 and LLVM 22; missing tools fail.
Keep one heavy owner, a 20 GiB reserve and reusable global caches. Release owned
objects/processes promptly; preserve raw failures and exact inputs under `_out`.
