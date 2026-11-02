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
is running and has failed source-contract tests under repair. Local follow-ups
retain the original cases, add genuine unknown/partial-address negatives and
check accepted numerical native accesses through LLVM objects. These repairs
still need the complete affected suite; f325 does not certify them.
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

The follow-up batch needs its own source-bound final gates and published CI.
Do not copy f325 coverage or successful checks onto it. External canonical
module qualification currently has **0 module PASS**; two compress object
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

[LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) remains published at
`7be828f55b9005f13f768b4a8a07aae4c57e6798`. The unpublished rebased candidate
`5feac7a70` is based on upstream `983465e779527ff496857a9a1915c1b57131091f`
and pins deb6157. Its fresh local adapter/build suite passes 218 nodes with
zero FAIL/SKIP. Fresh Linux compilation, final linking and execution are pending;
the older 08e/f325 runtime records do not qualify this candidate.
The P1 requires an official upstream fix **and tagged release before merge**;
a fork pin or successful CI does not resolve it. Keep draft status and record
zero formal approvals until an actual review changes that state.

Detailed earlier components, failures and measurements remain in the
[immutable history](https://github.com/cpunion/plan9asm/blob/dfab0bf818b9e09eacbd8a1a2b8df7b8fc5227be/docs/development/current-work.md).
Use Go 1.27, immutable Go 1.20.14 and LLVM 22; missing tools fail.
Keep one heavy owner, a 20 GiB reserve and reusable global caches. Release owned
objects/processes promptly; preserve raw failures and exact inputs under `_out`.
