# PR40 closeout

Updated 2026-11-01. Finish amd64 typed instruction families, correctness and
translation efficiency before generalizing to another architecture. Retain the
386, ARM, ARM64 and WASM gates. Read [architecture](architecture.md),
[family development](instructions.md), [convergence](x86-convergence.md) and
[validation](validation.md). External scanning and ledgers belong to
[llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm); do not run local
inventory processes.

## Accepted publications

[PR40](https://github.com/xgo-dev/plan9asm/pull/40) remains draft at
`9285ff89ab60cb7500481e233effdae8e61e5af3`. Its own
[CI round](https://github.com/xgo-dev/plan9asm/actions/runs/41232208183)
completed **325/325 SUCCESS**, attempt one, without reruns or cancellations.
Official function coverage is **88.1%**; Codecov patch coverage is
**91.80% >= 87.83%**. Independent acceptance joins 286 source artifacts,
240 partitions, 23 groups and all 22 Windows/race packages with 168 raw streams
each. Host-inapplicable skips remain distinct from passes. Two historical
inline threads are resolved; no formal approval is recorded.

[LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) remains draft at
`7be828f55b9005f13f768b4a8a07aae4c57e6798`, based on
`610075be034817b0f386d109926fd9a93db41a48` and pinning the accepted translator
head above through the allowed fork. Its own thirteen workflows completed
**140 SUCCESS + two conditional publisher SKIPs**, with no failures, reruns or
cancellations. Patch coverage is **97.06% >= 95.82%**.
Independent acceptance includes all eight native profiles, 612 stages and
six actual Windows installation profiles. Firmware build success does not
establish device execution.

The unresolved LLGo P1 requires an official tagged upstream plan9asm release
containing these changes. The latest observed release, v0.6.2, does not contain
them; a fork replacement does not satisfy that review. Do not merge, tag or
release upstream, or mark this P1 resolved on the basis of fork CI.

[Earlier component history](https://github.com/cpunion/plan9asm/blob/9285ff89ab60cb7500481e233effdae8e61e5af3/docs/development/current-work.md)
retains detailed qualifications and historical failures. They remain attached
to their original inputs; a later passing round does not relabel a failed one.

## Source inventory and its limits

The accepted source union has 67 overlapping views per SDK and 64 canonical
snapshot files across both SDKs:

| SDK | AVX | optab | ymovtab | Joined / denominator | Unjoined |
|---|---:|---:|---:|---:|---:|
| Current | 3,568 | 1,306 | 112 | 4,986 / 4,986 | 0 |
| Minimum | 3,568 | 1,305 | 112 | 4,985 / 4,985 | 0 |

These are independently joined source identities, not IR, LLVM-object or
executed instruction counts. Exactly thirteen Zpseudo and four Zbyte rows
are excluded from this denominator and retained separately. The ymovtab
sentinel is separate from its 112 encoding rows. Preserve overlapping rows,
first-match selection, frontend refusals, backend-only observations and actual
mode restrictions. Parsing grants no initialized values, pointer extent,
machine-state permission or source lease.

The typed migration shares legal format groups, widths, aliases, effects and
lowering within each family. Production line reductions and rejected slower
abstractions are recorded in [convergence](x86-convergence.md). Source inventory
completion does not establish whole-architecture semantic completion or a
measured translation speedup.

## MIN/MAX follow-up

Test commit `849c517531f746c0bd195ce1a78c042f86c252a3` adds a shared
native oracle for 32 legacy SSE/SSE2 and 96 VEX floating MIN/MAX kernels.
The isolated [fork qualification](https://github.com/cpunion/plan9asm/actions/runs/41286911744)
at `ed7d96e6189e64a710f481e99c080e3551f41ebb` passed on native Linux/amd64
with Go 1.27.3 and Go 1.20.14, LLVM 22.1.8. Each SDK has exactly twenty roots
and 713 unique RUN/PASS nodes, zero FAIL/SKIP. Source hashes match the test
commit. The fork-only diagnostic workflow must not enter the contribution.

All three public APIs execute at O0 and LLVM-optimized O2 against original Go
assembler bytes and an integer-only IEEE oracle. Each SDK retains 3,145,728
numerical comparisons, 3,120 fault observations and 6,144 exception observations.
The cases include register/base aliases, scalar passthrough, signed zero,
NaN payloads, denormals, MXCSR, preserved FLAGS, exact memory widths, alignment,
dead-result faults and unmasked exceptions. Existing complete family tests and
five-target object gates run alongside the native owners. A separate full
128-kernel C compile/link gate makes no execution claim.

Local ARM64 has no x86 execution environment that qualified these assertions.
The recorded guest attempts lack AVX and fail the independent pre-instruction
FLAGS check. Their failures remain failures; native CI supplies fresh execution
evidence. This batch does not establish EVEX/AVX512, raw-decoder runtime,
Go ABI0 wrapper execution or other floating-point families.

## Remaining work

1. Integrate this verified test batch without the fork-only workflow. Accept
   the contribution head's own complete CI, coverage and review; the accepted
   9285 round does not certify a later head.
2. Continue initialized functions, LLVM 22 objects and independent semantics
   family by family. Preserve native 386, AVX512/AVX512ER, reciprocal/MXCSR,
   extended80/BCD, MMX-state and BF16 fault gaps until separately qualified.
   Context, unavailable hardware and unfinished tests are never passes.
3. Converge shared typed consumers and remove replaced selectors in the same
   batch. Keep element, carrier, active/result and memory widths, direction,
   masks, aliases, FLAGS and fault/order effects separate. Measure retained
   allocations and complete translation time; do not count faster rejection
   or reduced scope as acceleration.
4. Preserve the historical strict amd64 SDK/runtime result of 41/55 PASS and
   fourteen FAIL, all attempted. Track individual source and runtime causes in
   [issue47](https://github.com/xgo-dev/plan9asm/issues/47). The instruction-only
   PR gates do not close these integration failures.
5. After upstream publishes an appropriate release, replace LLGo's fork pin,
   rerun its integration checks and address the remaining review. Keep broader
   runtime contracts separate from instruction translation.

Use current Go 1.27, an immutable Go 1.20.14 SDK and LLVM 22 only. Keep one
heavy local Go/LLVM/Node owner, a 20 GiB disk reserve and reusable compiler
caches. Never clear the global cache. Dispose owned modules, contexts,
executables and subprocesses promptly. Keep exact source/tool provenance and
failed reports under ignored `_out/`.
