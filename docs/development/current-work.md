# PR40 closeout

Updated 2026-11-01. Finish amd64 correctness, typed instruction families and
translation efficiency before expanding another architecture. Retain the
386, ARM, ARM64 and WASM gates. Read [architecture](architecture.md),
[family development](instructions.md), [convergence](x86-convergence.md)
and [validation](validation.md). External scanning and ledgers belong to
[llgo-compat/plan9asm](https://github.com/llgo-compat/plan9asm); do not run
local inventory processes.

## Last accepted publication

[PR40](https://github.com/xgo-dev/plan9asm/pull/40) remains draft.
Head `2356e4291` completes its own
[CI round](https://github.com/xgo-dev/plan9asm/actions/runs/41215084598):
**325/325 successful checks**, comprising 314 retained first-attempt executions
and eleven second-attempt executions. The first attempt naturally completed
with 323 successes and two failures: an Ubuntu APT TLS failure before Go tests
and its dependent module collector. Those failures remain recorded. Only failed
work was rerun, after the whole first attempt ended.
Independent checks join all 286 source artifacts to actual attempts, 240 partitions,
23 groups and all 22 Windows/race packages with 168 raw streams each.
Host-inapplicable test skips remain separate from passes.

Official function coverage is 120,674 / 136,909 = **88.1%**.
The 22-profile raw block union is 120,774 / 137,009 = 88.1504%.
Exactly 100 covered initializer statements in 82 blocks outside function
declarations explain the denominator difference. An independent Go AST
observer reproduces the official algorithm; the original failed equality
check remains recorded. Codecov patch coverage is **93.73% >= 87.83%**.

The fifteen-kernel native scalar-move owner actually runs on current
Go 1.27.2 and minimum Go 1.20.14 Linux CI: ten RUN/PASS nodes per SDK,
with six exact summaries of 15 kernels, 1,920 numerical comparisons,
180 faults and two tripwires, without failures or skips.
These observations do not qualify every native instruction or ABI entry.

Both historical review threads are resolved; no formal approval is recorded.
Earlier `e04799ae8` remains a failed round: 302 successful and 23 failed jobs
from two reproduced fixture defects and their dependent collectors.
The accepted repairs have fresh evidence; they do not relabel that old run.
[Earlier component history](https://github.com/cpunion/plan9asm/blob/2356e4291451c4f7a822a55bb35eb77b720a03af/docs/development/current-work.md)
retains prior qualifications and failures.

## Current integrated batch

The code snapshot is `20279acda`, combining the following qualified components.
A later publication needs its own complete gates and CI; an older accepted
head does not certify these changes.

- GP data/FLAGS/CPU source grammar retains 100 current / 99 minimum rows,
  including 62 existing identities. It shares the scalar transport, complete
  operand schemas, prefix handling and opcode spans. Captured enum/name
  contradictions and BSWAP padding are rejected; valid implicit zero cells
  remain accepted. Go-accepted CPU-invalid forms are source observations only.
- MOVQL and MOVLQZX use opposite directional 32-bit move forms and actual
  source mode. Shared effects and local dispatch copies preserve original
  Op/Raw/operand identity. MOVQL reuses MOVL lowering; 386 MOVLQZX preserves
  a complete ordinary word while amd64 keeps its existing extension path.
  Existing raw NUM, pointer, caller, frame and native-memory boundaries remain.
- Remaining media/x87 source grammar retains 31 rows across twelve complete
  tables: nine existing identities and 22 new ones. Old conversion/horizontal
  public views and the new view share complete encoding validation. The 95
  original malformed-metadata counterexamples still exercise the old consumers.
  New and old paths share carrier construction; MMX admission remains unchanged.
- Non-TLS ymovtab grammar joins 92 more source identities using five shared
  encoding cases. Literal, prefix and ModRM transport and complete-table
  structure validation are shared with existing consumers. The eighteen
  double-shift rows stay unchanged.
- CMOV runtime fixtures prepare their process-owned tool cache before source
  capture. The immutable reader still rejects files that change while read.
  Resource/lifecycle regressions pass on both SDKs. All seven native batches
  actually pass in accepted Linux CI; local host skips do not certify them.
- State/system/memory grammar joins 94 additional source identities through
  complete captured tables and shared encoding transport. Original enum, name,
  operand classes and payload are validated before mode classification.
  FLDENV's stock frontend rejection remains separate from its original-backend
  encoding; external XBEGIN frontend and backend observations also stay distinct.
- Stack/control grammar joins forty identities through five format groups:
  register opcode, directional ModRM, immediate/literal, PC-relative and
  symbol-indirect relocation. Thirty-eight stock-assembler rows and two DUFF
  backend rows have separate original-source observations. Actual Go 1.20
  frame-wrapper bytes and relocation offsets are preserved. This implementation
  adds 321 net production lines and reuses the captured-member serializer.
- Two contextual TLS fallback rows use real Linux/386 non-shared and
  Linux/amd64 shared assembler outputs. Direct-TLS NOP and shared386 controls
  grant neither fallback identity. Actual source/object/listing, SDK, profile,
  bytes and relocations are joined. Canonical source identity omits only
  path-dependent object/listing hashes; complete original dynamic artifacts
  and their hashes remain retained. This completion is test-only and grants
  no translator NUM, stack, caller, native or live TLS permission.

Both SDKs pass the new alias grammar/effect tests (125 nodes and thirty
five-target, three-API O0/O2 object modules each). Portable execution passes
27 nodes and eighteen backend/link/execute leaves per SDK, checking 20,736
numerical/memory observations. An independent seed makes ZF checks orthogonal
to the copied value. The earlier correlated-ZF oracle is retained separately.
This is host execution of translated IR, not original x86 execution, complete
native FLAGS acceptance or 386 native-memory execution.

The shared old semantic set passes 141 roots / 8,264 nodes per SDK.
The old alias/object join passes nine roots / 244 nodes on current Go and
seven / 166 on minimum; two Go1.27-only source owners are not compiled on
minimum and are not counted as skips or passes.

Media/x87 focused tests pass 126 nodes per SDK; the complete rule package
passes 18,618 / 18,635 across 176 roots. Existing hooks pass 107 nodes and
input restrictions 604 per SDK. All results have zero failures/skips.
The old 54 identity snapshots remain byte-exact; two new snapshots retain
the new view. One snapshot wrapper failed its post-command disk guard after
fourteen genuine passing roots. Exact source/tool/provider identity retains
those executions; the remaining three commands ran separately. The original
resource failure remains failed and is not described as a successful wrapper.

The fallback batch passes nine roots / 489 nodes on each SDK. Complete rules
pass 182 roots / 18,908 and 18,925 nodes; thirteen existing hooks pass 112 each.
All previous 56 source snapshots remain byte-exact. Existing TLS, machine and
segment boundaries pass 17 / 13 roots and 21,432 / 21,406 nodes respectively;
these historical checks did not close the two contextual TLS encoding rows.

The final combined source scope passes 242 roots / 41,562 nodes on current
Go 1.27.3 and 238 roots / 41,550 nodes on minimum Go 1.20.14, without failures
or skips. Prior thirty-row consumers pass fifteen roots per SDK. The TLS scope
independently passes seven roots / 34 nodes per SDK. All 62 prior source
snapshots are freshly byte-exact; repeated real TLS captures have identical
canonical identities and retain distinct original objects/listings. Both SDKs
pass vet and build, plus formatting and diff checks. Default vet stays enabled:
Go 1.20 vets the physical original SDK test file; the appended owned backend
fixture executes but legacy vet cannot see its overlay text. No SDK
implementation file is replaced or modified.

## Source inventory and limits

The final source union has 67 overlapping views per SDK and 64 canonical
snapshot files across both SDKs:

| SDK | AVX | optab | ymovtab | Joined / denominator | Unjoined |
|---|---:|---:|---:|---:|---:|
| Current | 3,568 | 1,306 | 112 | 4,986 / 4,986 | 0 |
| Minimum | 3,568 | 1,305 | 112 | 4,985 / 4,985 | 0 |

These are independently joined source identities, not IR, LLVM-object or
executed instruction counts. The denominator excludes exactly thirteen Zpseudo and
four Zbyte rows; their identities remain retained. The ymovtab sentinel
remains separate from its 112 encoding rows. Preserve overlapping rows,
first-match selection, frontend refusals, backend-only observations and actual
mode restrictions. A complete source join does not establish initialized forms,
successful LLVM compilation or numerical/native semantics.

Source grammar grants no NUM, pointer extent, machine state or source lease.
The newly observed MMX conversions and status forms still need their separate
initialized/object/semantic qualifications. Context, hardware exclusions and
unexecuted forms never count as passing instruction coverage.

## Next work

1. Run final combined policies and all five architectures on both SDKs.
   The accepted controlled Translate comparison at `f0a64c2e3` retains all
   original 29 cases, MOV-dense cases, three ABBA blocks and actual outliers.
   Subsequent source-table tooling remains outside the translator dependency
   graph; the new source views are exercised by source tests. Keep this identity bridge
   separate from fresh execution or scanner performance measurements.
2. Publish the completed source inventory only after those frozen integrated
   gates pass, then accept the new head's own CI, raw artifacts and coverage.
   The accepted `2356e4291` round does not certify a later revision.
3. Continue initialized forms and semantic families alongside the inventory.
   Keep element, carrier, active/result and memory widths, operand direction,
   masks, alias writes, FLAGS and fault/order effects distinct. Reuse typed
   forms across consumers and remove replaced selectors in the same batch.
4. Preserve explicit native386, AVX512/AVX512ER, reciprocal/MXCSR,
   extended80/BCD, MMX-state, BF16 fault and floating MIN/MAX execution gaps.
   The last strict SDK integration at D6 remains 41/55 PASS / 14 FAIL, all
   attempted; track individual source and runtime causes in
   [issue47](https://github.com/xgo-dev/plan9asm/issues/47).
5. [LLGo2694](https://github.com/xgo-dev/llgo/pull/2694) remains
   `f1c1571a1`, based on `277e5b280`, pinning accepted D905. Its own CI
   passes 140 jobs plus two conditional publisher skips, with 97.06% patch
   against 95.84%. A local rebase onto main `9c7bf2197` is prepared; it needs
   a verified translator pin and fresh integration checks before publishing.
   The unresolved P1 requires a tagged upstream translator
   release; a fork replacement does not satisfy it.

Use current Go 1.27, a complete immutable Go 1.20.14 SDK and LLVM 22 only.
Keep one heavy local Go/LLVM/Node owner. Reuse existing compiler caches;
do not clear the global cache or accumulate a cold cache for every attempt.
Dispose owned modules/contexts and temporary executables promptly. Keep
failed reports and source/tool provenance under ignored `_out/`.
