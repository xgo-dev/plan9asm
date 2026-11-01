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
`c3a3fb8e74804558e9dd3e8fadfeadf4c7e5d2f3`. Its own
[CI round](https://github.com/xgo-dev/plan9asm/actions/runs/41297943259)
completed **325/325 SUCCESS**, attempt one, without reruns or cancellations.
Official function coverage is **88.2%**; Codecov patch coverage is
**92.48% >= 87.83%**. Independent acceptance joins 286 source artifacts,
240 partitions, 23 groups and all 22 Windows/race packages with 168 raw streams
each. Host-inapplicable skips remain distinct from passes. Two historical
inline threads are resolved; no formal approval is recorded.

[LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) remains draft at
`7be828f55b9005f13f768b4a8a07aae4c57e6798`, based on
`610075be034817b0f386d109926fd9a93db41a48` and pinning the earlier accepted
translator `9285ff89a` through the allowed fork. The subsequent translator
follow-ups have separate qualifications; they are not execution evidence for
this older LLGo pin. LLGo's own thirteen workflows completed
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

## Current MIN/MAX and convergence follow-up

Product code `3c05d6dfb` removes 43 superseded production lines and extends the
shared MIN/MAX oracle: 128 named kernels plus 256 raw kernels. Element width,
instruction width, observed carrier and register bank are separate axes.
Original Go objects independently retain low/REX, VEX2 and VEX3 encodings,
including high registers and R9 memory. Raw legacy uses an AVX carrier to
observe preserved Y upper bytes; the named SSE owner remains SSE-only.

The isolated [fork qualification](https://github.com/cpunion/plan9asm/actions/runs/41296064081)
at `31985333cf239ea4a03c2a8753bcdc53f91494c7` passed on native Linux/amd64
with Go 1.27.3 and Go 1.20.14, LLVM 22.1.8. Each SDK has exactly 23 roots,
746 unique RUN/PASS nodes and 24 native summaries, zero FAIL/SKIP. Source
hashes match product code; only the fork diagnostic workflow differs. That
workflow must not enter the contribution.

All three public APIs execute at O0 and LLVM-optimized O2 against original Go
assembler bytes and an integer-only IEEE oracle. Each SDK retains 9,437,184
numerical comparisons, 9,360 fault observations and 18,432 exception observations.
Cases cover aliases, scalar passthrough, signed zero, NaN payloads, denormals,
MXCSR, FLAGS, exact memory widths, alignment and live/dead-result faults and
exceptions. Complete earlier family tests and object gates remain. The separate
128-kernel C compile/link gate makes no execution claim.

Both SDKs pass nineteen family/object roots and 706 nodes locally. An initial
VEX length-oracle error and a minimum-SDK disk-guard interruption remain failed
reports. The corrected oracle uses original NOSPLIT|NOFRAME objects; the
interrupted SDK was separately retried. Local ARM64 guest attempts are not
native acceptance. This batch does not certify EVEX/AVX512, Go ABI0 wrapper
execution or other floating-point families.

## Floating arithmetic grammar follow-up

`dc2936489` joins all 48 named ADD/SUB, MUL/DIV and MIN/MAX opcodes in one
typed catalog and operand parser. Three dispatchers, caller syntax and memory
shape queries now consume that grammar. Separate numerical lowerers retain
rounding, source-order NaNs, machine state, raw-source verification and faults.
The residual binary catalog owns FP16 and SCALEF only. Production shrinks by
87 lines, including the replacement catalog.

Both SDK endpoints retain exactly the same 74 roots and 2,183 unique PASS
nodes before and after the change, with no failures or skips. An interrupted
disk-guard attempt remains separate. Ten ABBA benchmark samples per revision
and SDK retain the same allocation count: 12,106 current, 12,217 minimum.
Median complete-translation time changes by -0.13% and +1.03% respectively;
these observations establish no speedup. Additional official-row and consumer
tests bring each SDK's local union to 92 roots and 2,417 PASS nodes. This retains
132 AVX encoding rows / 684 witnesses and both legacy source modes.

The isolated [floating arithmetic qualification](https://github.com/cpunion/plan9asm/actions/runs/41310855146)
at `cc196e8b1` completed both native Linux/amd64 jobs with LLVM 22.1.8. Each SDK
has exactly 36 roots and 774 unique RUN/PASS nodes, zero FAIL/SKIP. Its complete
5,489-file product manifest matches `899f2ba2a`; only the diagnostic workflow
differs. The 24 MIN/MAX numerical/fault/exception summaries retain the counts
above. ADD/SUB and MUL/DIV owners execute as additional checks, not additional
MIN/MAX observations. Later documentation edits do not represent another native
execution. The contribution head's own complete CI remains required.

## CI fixture and physical mode32 repair

The `2c033f894` round exposed two isolated CLI extraction fixtures which still
copied the superseded family files. The actual repository scanner finds the
canonical catalog. Shared fixtures now retain all three original family roots,
all 48 names, isolated checks on five architectures and complete-repository
checks on both x86 modes. The complete extraction suite passes 74 roots / 222
nodes on Go 1.27.3 and the CLI minimum Go 1.24.11, with no failures/skips.
ARM's independent MULSD spelling remains present in complete-repository scans.

The shared grammar also applies the existing physical mode32 boundary to
ADD/SUB. An independent 108-case operation/width/register-role test first
reproduced 36 missing checks, then passed on both endpoint SDKs. These are
grammar controls, not native386 execution. The historical complete-source
fixture retains identical original Go source hashes on all five targets;
its 386 partition now explicitly retains 44 physical-bank Context rows
(sixteen MIN/MAX and twenty-eight ADD/SUB). No row is removed or counted as an
executed instruction. Initialized low-bank objects retain their separate owners.

`a9ec02fb5` passes the complete local union: 93 roots / 2,526 unique PASS nodes
per SDK, zero FAIL/SKIP. Combined production reduction is 99 lines relative to
C3a, excluding tests/documentation. Final paired ABBA medians change by -0.23%
on current Go and -0.73% on minimum Go, with essentially unchanged allocations;
no speedup is claimed. The repair still needs fresh native qualification and
its own complete contribution CI. Let the existing round finish before pushing
the repair batch; preserve its failures and all RED/GREEN reports.

## Remaining work

1. Finish qualification of the CLI/mode32 repair and publish the verified batch
   without the fork-only workflow. Accept its own complete CI,
   coverage and review; the accepted C3a round does not certify a later head.
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
