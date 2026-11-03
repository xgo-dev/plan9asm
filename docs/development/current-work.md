# PR40 closeout

Updated 2026-11-04. Finish AMD64 correctness, typed-family convergence and
translation efficiency first; preserve the 386, ARM, ARM64 and WASM gates.
Start with the [architecture](architecture.md), [family workflow](instructions.md),
[convergence notes](x86-convergence.md) and [validation](validation.md).
External discovery, ledgers and compatibility batches belong to
[llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm).

## Published CI and contribution state

Upstream [PR40](https://github.com/xgo-dev/plan9asm/pull/40) remains draft at
`b531c83c7c810640cd6e04ab70e6422e440fd5d4`.
The fork contribution [PR6](https://github.com/cpunion/plan9asm/pull/6) remains
draft at `cf4ac631ab00739da2da9ed2081b85b66f7c32e8`.
No formal approval is recorded. Related upstream CI is stopped; run subsequent
validation in the allowed fork.

| Snapshot | Actual result | Limit |
|---|---|---|
| Historical `f32575c824b2a8759fcf1941b7a47e6b35e047b8` | [Complete CI](https://github.com/cpunion/plan9asm/actions/runs/41451548879): 325/325 SUCCESS, first attempt | Does not certify later changes |
| Product `cf4ac631a`, diagnostic `0ec1ed29c` | [Staged CI](https://github.com/cpunion/plan9asm/actions/runs/41605057011): 32/32 SUCCESS; 10,530 root and 429,875 child PASS | Linux ordinary coverage and source/compiler gates; separate 299 root and eight child SKIPs are not passes |
| Product `cf4ac631a` | [Full round](https://github.com/cpunion/plan9asm/actions/runs/41612231250): 110 SUCCESS, 206 CANCELLED | Cancelled to conserve resources; complete 325-job acceptance was not obtained |
| SDK-pin product `b1fbc7db7`, diagnostic `324911934` | [Focused CI](https://github.com/cpunion/plan9asm/actions/runs/41621190680): 6/6 SUCCESS; installer 10/10, CLI 31 root and 29 child PASS | Complete Go 1.26 CLI group plus installer regression; not full CI |

The cancelled round exposed a real group-contract failure: runners resolved
`1.26.x` to both Go 1.26.9 and 1.26.10. The fix freezes all eight compatibility
aliases to exact SDK patches. The focused group independently confirms Go
1.26.10 and equal SDK source identity across every producer and fresh collector.
Keep the old failure; do not weaken scope equality or reuse a cancelled collector.

## Current local source batch

The verified instruction/source-contract snapshot is
`7259fd6ff0d9923a7d2c1b3a32313b14a49e9c1d`.
It includes the SDK-pin fix. It is not yet published or covered by a complete
current-head fork round. Local component gates below retain their own source
snapshots; their totals must not be added into a fictitious whole-suite result.

| Component | Mechanism | Actual local qualification |
|---|---|---|
| `bb43d1990` | Observe the requested assembly member while retaining complete sibling/source guards; distinguish ordinary call formatting from private-call authority | Current SDK 90 roots / 1,053 nodes; minimum 55 / 469; all PASS |
| `9a1aa9d2e` | Preserve omitted TEXT argument size as Go's unknown-size sentinel; observe declared Windows frameless leaves without private-entry promotion | Current 97 / 1,278; minimum 62 / 694; all PASS; Windows leaf controls also pass on each intermediate SDK |
| `0c2cf492a` | Omit only authenticated, structurally unreachable ordinary fixed-frame blocks; retain full grammar and live access checks | Current 80 / 1,629; minimum 65 / 1,482; all PASS |
| `7259fd6ff` | Share ordinary typed scalar-tuple shape and cached validation; allow only the exact partial-output audit outcome for code generation | Current and minimum each 35 / 2,794; all PASS; 48 portable executables and 576 defined-only observations per SDK |

Each final component also passes the complete Node policy suite (579 tests) and
Go policy suite (484 nodes), without FAIL or SKIP. The numeric-tuple change
preserves pointer, nested aggregate and custom-register return paths. A broader
candidate actually regressed the 386 pointer tuple; its failure is retained and
the final entry check is restricted to flat scalar numerical/bool tuples.

The strict result-initialization audit still reports unwritten output bytes.
Only code generation may consume that exact output-only outcome. Undefined
inputs, unwritten-result reads, wrong layouts, wrapped/joined failures and
canonical bool requirements retain their checks. Runtime callers observe payload
only on paths which write it; incidental zero initialization proves nothing.

The dead-block change currently adds one complete result replay per function
with unreachable blocks. Actual S2 counts show two such result checks in
`encodeBlockAsm4MB` during translation, including the existing scalar check.
This is a measured efficiency follow-up, not a claimed speed improvement.
Investigate reuse of the existing translation-local check before adding state
or caches; keep source mutation, closure and ownership guards.

## External and LLGo evidence

| Source | Verified scope | Remaining boundary |
|---|---|---|
| Exact GoHex version, core `cf4ac631a` | Both original assembly files translate and compile to objects on all three applicable AMD64 targets | Complete Go-plus-assembly program and ledger publication are separate |
| compress v1.20.1 S2, core `7259fd6ff` | Original `encodeblock_amd64.s`: all 32 TEXT functions captured, bound, translated and compiled by LLVM 22 at O0 and O2 | `decode_amd64.s` remains Context at an ordinary Go ABI0 CALL; whole compress is not PASS |
| LLGo function-descriptor component `138fe6ef2` | Native ARM64 Go/LLGo function-value round trip and complete SQLite v1.58.0/libc v1.75.7 query/rollback/captured-callback/GC execution | These results predate the latest main rebase; Linux purego, Turso and remaining reported programs need fresh qualification |
| LLGo rebased local candidate, downloader commit `def9687b4` | Download cancellation/atomicity: actual RED then 17/17 PASS; existing preservation 66/66 PASS. Fourteen original fixture programs and FileCheck: 31 PASS; six-optimization DWARF suite: seven PASS | Larger owner gate still fails at test-layout assumptions and a real Go/C variadic signature-cache collision; not a whole-package acceptance |

[LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) remains draft at its published
`d72552acc` head. Its local contribution stack has been rebased onto upstream
`fe431355cb7a494865c600b374c151dbfb7c41f8`; rebase and new source repairs need
fresh package, policy, GC/runtime and reported-library gates. Keep the rejected
SSA-shape matcher out of its ancestry. Use coherent function-descriptor storage,
typed call roles and independent original-source/runtime oracles.

The unresolved review requirement is an official fixed plan9asm release before
LLGo merge. A fork pin is useful for validation and does not resolve that
requirement. Do not publish an upstream tag/release or mark review approval.

## Coverage and remaining work

The recorded AMD64 source-table union retains 67 overlapping views per SDK and
64 canonical snapshot files across both endpoint SDKs:

| SDK | AVX | optab | ymovtab | Joined source identities |
|---|---:|---:|---:|---:|
| Current snapshot | 3,568 | 1,306 | 112 | 4,986 / 4,986 |
| Minimum snapshot | 3,568 | 1,305 | 112 | 4,985 / 4,985 |

Thirteen Zpseudo and four Zbyte rows, plus the ymovtab sentinel, remain separate.
These are source identities, not IR/object/runtime coverage. Preserve all five
architectures' independent owners; an AMD64 denominator does not describe them.

Next, qualify the combined source batch in the fork, prioritizing repaired
owners before broader jobs. Finish ordinary Go ABI0 calls without promoting
callees into private leaves. Resolve LLGo signature-role collisions and retained
closure-call/defer allocation costs through source-level typed mechanisms, then
rerun complete package/policy gates and reported programs at the final core pin.
Update compatibility ledgers only from their actual complete qualification.

The 65 native AVX512 owners remain hardware pending. Historical strict
SDK/runtime integration remains 41/55 PASS and 14 FAIL, tracked in
[issue47](https://github.com/xgo-dev/plan9asm/issues/47). Preserve those boundaries;
instruction-only or object-only success does not close them. Publish verified
batches only to an allowed fork, keep contribution PRs draft until their
current-head CI/review/coverage requirements pass, and preserve every failed
attempt alongside its correction.
