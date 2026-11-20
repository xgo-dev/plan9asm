# x86 architecture convergence

The current priority is to finish **amd64** architecture, correctness and
efficiency before expanding another architecture. Changes to shared x86 code
must retain 386 regressions. Existing ARM, ARM64 and WASM gates remain enabled;
this ordering does not remove supported targets or their tests.

## Acceptance, not an opcode-count target

The review of `728520def` found 33/55 selected Linux/amd64 standard-library
files produced LLVM 22 objects, versus 55/55 at `e2164ac0`. These are historical
Go 1.27.2 observations, not execution certificates. Retain the original failures
and repair ordinary-source regressions before declaring this work complete.
Runtime entry contracts remain a separate integration responsibility; a source
failure must not be assigned there without identifying its actual cause.

Completion requires all of the following:

- An independent inventory of the selected Go assembler's legacy, AVX and
  special encoding rows, with their order, attributes and mode restrictions.
  Opcode names, operand-class buckets and corpus occurrences are different
  denominators. Neither the production registry nor a changed baseline may
  define away an unimplemented official row.
- Explicit ownership of every row: a validated concrete form, an independently
  observed frontend refusal for that mode, or an unresolved gap. Preserve
  overlapping rows. A syntax witness alone does not identify its actual VEX or
  EVEX encoding; compare original bytes when claiming that encoding's coverage.
- Initialized complete functions through the public APIs, LLVM 22 objects and
  independent semantic tests. Keep those evidence levels separate. Context,
  unavailable hardware and unfinished tests never count as successful execution.
- Whole-source standard-library and independent regression gates alongside
  family tests. External libraries remain independent checks, not the source
  from which we enumerate instruction formats.
- Measured code reduction and translation efficiency for each migrated family,
  without decreasing its retained format, target or regression inventory.

## Architecture boundary

Normalize named and decoded instructions into architecture-local typed forms.
Keep encoding identity and original operand roles. Reuse the validated form
for numerical dependencies, register/FLAGS effects and lowering; do not make
each consumer rediscover the family and parse its operands again.

Separate the following axes, constraining their legal combinations with the
official rules rather than constructing an unrestricted Cartesian product:

- Operation and arithmetic mode, including signedness and saturation.
- Register carrier, active vector, element, source/result and memory widths.
- Explicit/implicit input roles and old-destination dependencies.
- Encoding, masks, broadcast and preserved/zeroed register aliases.
- Memory alignment, access/fault suppression, ordering and machine-state effects.
- Source mode and the features required by the chosen lowering route.

Portable arithmetic does not automatically require the source opcode's ISA.
Native memory and floating-point paths may need exact instructions to preserve
faults, rounding or exceptions. Keep those deliberate exceptions visible.

Grammar and numerical effects describe requirements; they do not establish
pointer extent, initialized bytes, frame ownership or caller authority. Evolve
the existing analyses toward shared typed effects with separate numerical and
address-origin domains. Do not add another instruction whitelist to each proof.
Physical indexed SP scratch cannot be relabeled as named logical AUTO storage.

Prefer small concrete descriptors and direct dispatch. Avoid a runtime grammar
interpreter, reflection-based dispatch, or a universal struct of unrelated
optional fields. Common lowering pipelines retain family-specific operations
and explicit memory contracts. Delete replaced code in the same coherent batch.

## Work order and measurements

1. Reproduce and repair ordinary-source regressions with independent tests.
2. Pilot shared packed add/subtract/low-multiply lowering, retaining the complete
   widths, masks, memory behavior and aliases. Extend only after the pilot
   demonstrates a smaller implementation and unchanged observations.
3. Complete the independent rule inventory and initialized-form joins; migrate
   registration, feature inference and effect consumers family by family.
4. Move repeated source/tool capture out of numerical lowering using explicitly
   owned immutable inputs. Do not cache mutable verification results or weaken
   mutation, expiry, cancellation and Close checks.
5. Finish all amd64 families and whole-source gates before generalizing the
   architecture to ARM, ARM64 or WASM.

The first normalization batch covers four existing packed binary families:
average, word multiply, multiply-add and dword product (20 names). One typed
spec/form now feeds effects, memory queries, result routing and lowering;
the replaced consumer selectors are removed. Lowering retains the parsed form,
while separate analysis invocations still normalize independently. No cache is
attached to mutable instructions. Input/result widths, pair reductions and
even-lane products remain explicit: DQ arithmetic uses 32-bit inputs but 64-bit
memory granules; MADD retains full-tuple reads, distinct from E4 mask suppression.
Average and word multiply reuse the existing E4 pipeline. Production shrinks by
65 lines. Both endpoint SDKs pass 101 roots / 10,098 children without skips.
Paired benchmarks under unrelated host load do not establish acceleration.
Do not call this whole-translation parse-once completion. A subsequent
function-local full-form table increased retained memory and slowed the short
translation comparison, so it was withdrawn before integration. The accepted
follow-up shares the feature projection without a cache and removes another
11 production lines. Cross-stage reuse must reduce total complexity and cost;
do not expand the family scope to justify retaining an unsuccessful abstraction.

The legacy floating dispatcher now loses another 121 unreachable lines after
its typed owners; FP16 portable lowering remains live and unchanged. Current
and minimum SDKs pass 168/167 roots and 5,173 children without failures/skips,
with the Linux/amd64 software-alias runtime owner retained separately. A proposed
26-line result-routing cleanup regressed paired minimum-SDK measurements and
was withdrawn. Smaller source alone does not establish faster translation.

The residual binary-floating helpers also drop 43 production lines of obsolete
f32/f64 input loading. Those families return through their typed owners; the
remaining portable FP16 and SCALEF paths retain their existing loads and effects.
Both endpoint SDKs pass all fifty related portable/object roots and 2,183 nodes;
the current SDK retains the exact executed baseline case IDs. The two original
host-inapplicable native owners remain separate, without counting their local
skips as passes. This cleanup adds no registry or cache and claims no speedup.

The next floating normalization joins all 48 named ADD/SUB, MUL/DIV and MIN/MAX
operations in one typed catalog. Encoding, precision and scalar/packed shape
select the shared operand grammar; the operation tag selects the existing
numerical lowerer. Caller admission, operand effects and memory shape consume
that form. MIN/MAX source identity and guarded result transfer remain distinct
from numerical arithmetic authority. Three dispatcher chains and the superseded
f32/f64 binary entries are removed, for a net reduction of 87 production lines.
Both SDK endpoints retain all 74 local roots and 2,183 case IDs. Paired ABBA
complete-translation measurements retain allocation counts; median time differs
by -0.13% on current Go and +1.03% on minimum Go. This is code convergence,
not an observed speedup. The separate native Linux/amd64 qualification retains
36 roots / 774 PASS nodes per SDK, with no failures/skips. Full-head CI remains
a separate gate; native386 and AVX512/ER acceptance are not implied.

The physical mode32 boundary subsequently converges too: ADD/SUB now uses the
same high-register check as MUL/DIV and MIN/MAX, removing another twelve
production lines. Independent original-Go spelling and AMD64 positive controls
cover all 108 operation/width/register-role cases; source acceptance does not
grant physical IA32 high registers. The original complete-source fixture keeps
every source row and explicitly partitions 44 contextual high-bank rows on 386.
The local union passes 93 roots / 2,526 nodes per SDK. Final paired ABBA timing
changes by -0.23%/-0.73%, with essentially unchanged allocation counts. This
does not certify native386 execution or establish a measured speedup.
The separate repair qualification at `a824274f3` retains the same 36 native
Linux/amd64 roots / 774 PASS nodes per SDK, zero FAIL/SKIP, with the complete
product source manifest bound to `e97ae1d32`.

For each batch record the exact revision, SDK, LLVM version, source fixture,
successful/failed counts, production/test line delta and retained case IDs.
Measure parsing, analysis, feature inference, IR generation and public
translation separately, including allocations and resource release. Keep
external commands out of microbenchmarks; measure their cost in the complete
source/object workload as well. Never report early rejection as a speedup.

Benchmark identical inputs before and after, with repeated samples and unchanged
tools. Preserve vector IR and independently check generated-program performance.
Do not clear global compiler caches. Batch LLVM tests with bounded modules and
prompt disposal; batching must preserve every test case, not sample the suite.

The next packed arithmetic batch joins all 36 add/subtract/D-Q low-product
spellings (35 canonical opcodes) in one typed catalog. The existing binary
grammar continues to own operand formats; operation, element width, saturation,
encoding and broadcast remain separate fields. Add/subtract effects and result
queries normalize once per invocation instead of probing two family parsers.
Private wrapping-add admission, legacy MMX projection and raw mode32 low-product
adaptation retain their separate contracts. Numerical lowerers, E4 handling and
the base binary grammar are byte-identical to `ab900f0c0`. Replaced catalogs,
switches and selectors are removed in the same batch: 80 fewer production lines.

Read-only legacy queries avoid a redundant operand copy, and physical GP-to-MMX
bank projection uses constant register names. TDD first reproduces redundant
allocations and three query-boundary defects; the corrected queries return empty
metadata on family misses, preserve bare-name compatibility and reject mismatched
source identities. Both Go 1.27.3 and Go 1.20.14 retain all 5,751 original local
case IDs and pass the full 66-root / 5,791-node scope. Native PADDD execution is
not counted as a local pass. Complete extraction and five-target gates remain.

Three ABBA blocks give six samples per revision and SDK for each of 49 unchanged
benchmarks: 31 complete translations and 18 feature queries. Across the complete
translation cases, the geometric mean of median timing ratios changes by -0.58%
on current Go and -0.07% on minimum Go. Two legacy arithmetic kernels remove
about 320 allocations per translation; the other translation allocation counts
remain stable. The twenty neighboring translation cases change by -0.20%/+0.25%.
These observations support code convergence and lower allocation cost, not a
statistically established translation speedup or native execution improvement.

The subsequent internal-dispatch cleanup removes 389 more production lines:
seven vector arms (200 lines) and the old ADC/SBB arms (189). Their complete
typed owners already intercept success and recognized errors inside the same
function, including direct private-helper calls. All handler/effect/native code
and entry prefixes are unchanged. The remaining private-entry duplicates are
handled by the separate callback migration described below.

Before and after deletion, both endpoint SDKs pass the same 26 local roots /
357 case IDs. The original wider attempt retains its host-native preflight skip
separately. Complete CLI extraction retains all 74 roots / 222 nodes; scanner
context controls pass four roots / 628 nodes on each endpoint. All 574 Node
policies, 31 preflight roots / 484 nodes and both five-target gates pass.
This is removal of duplicate code, not a new numerical implementation, native
execution certificate or measured translation speedup.

Scalar shift/rotate lowering now consumes the existing validated form's width,
count, source and operand indices through both ordinary and double shifts.
It removes 49 production lines of repeated mode, arity and operand validation.
The early Group2 membership gate still excludes every BMI2 spelling, including
malformed or mismatched instructions, before any value or memory emission.
The numerical and FLAGS emitters retain count0, carry rotation, W double-shift
count16 and the finite choice for undefined counts17–31. The existing 32 Group2
names / 120 rows and six double-shift names / eighteen rows remain unchanged.

Both endpoint SDKs retain every original local case ID and pass 43 roots /
10,890 nodes, including 49 new family-boundary nodes. Complete CLI extraction
passes on current Go and its Go1.24.11 minimum; the additional Go1.27 SDK math
owner is available only on current Go. Node, preflight and five-target gates pass.
Seven Group2 and one BMI2 benchmark kernels return actual I64 ABI0 results;
the separate existing GP control retains its Void/control-flow workload.
The initial local paired rounds disagree, including unchanged controls; retain
them as inconclusive observations. A subsequent controlled Ubuntu/amd64
comparison completes three ABBA blocks on both SDKs, six samples per revision
and kernel. The seven Group2 kernels have a geometric mean of median timing
ratios of 0.99735 on current Go and 1.00027 on minimum Go, with unchanged
allocation counts. The BMI2 and GP controls retain their separate workloads.
These 216 samples observe no material timing change within this narrow scope,
not a speedup or whole-source/native performance certificate.

The following private-entry cleanup deletes 599 more production lines of
duplicated INC/DEC, conditional SET/MOVE and Group2 lowering, including the
superseded double-shift helper. The public dispatcher already reaches the
complete typed owners first. Five fragment-test callbacks now call those same
owners; every original operand, signature and numerical/error assertion is
retained. The only other production entry into the residual arithmetic helper
is the unchanged LEA projection. No compatibility dispatcher, registry or cache
is added. Both endpoint SDKs retain the exact 125-root / 22,100-node inventory:
22,093 PASS and seven host-native SKIPs each. Two additional Linux/amd64 owners
are outside the local build. These remain separate from execution acceptance.
The inherited minimum-SDK unsupported form also remains explicit.

## Independent rule inventory

The official scanner includes the selected SDK's ordered `asm6.go` `optab` and
`ymovtab` under `legacy_encoder` for both amd64 and 386. It retains duplicate
operand rows, nil-ytab special entries, sentinels, full opcode payloads and
symbolic attributes separately from the existing AVX inventory. This is a
declaration inventory, not proof of mode applicability or selected encoding.

```sh
go run ./cmd/plan9asmscan -corpus=go-asm -goos=linux -goarch=amd64 \
  -format=json -out=_out/amd64-official-rules.json
```

`table_row_fingerprint` hashes normalized retained table rows. It deliberately
does not claim to hash constant definitions or all assembler selection logic.
No original corpus classifications or AVX fingerprints change when this
inventory is added. Row-to-initialized-form joins and original-byte selection
witnesses remain separate work; do not count inventory rows as passing tests.

## First pipeline pilot and next gate

The shared E4 pipeline retains family-specific parsing and storage checks, then
handles operand reads, arithmetic, masking and encoding-aware writeback once.
Legacy memory still uses its original faulting opcode. MMX and word low-product
multiplication retain separate owners. The three migrated lowering files plus
their helper shrink from 403 to 346 lines; this is not the whole PR's line delta.
The subsequent cleanup removes another 143 lines of unreachable packed
arithmetic from the residual vector dispatcher. Its original fixtures now call
the same typed owners as public lowering; 66 roots / 4,506 children passed with
no skips at `481291b93`. This is code reduction, not a measured speedup.

Integer min/max now reuses that E4 pipeline and removes another 39 production
lines. Both endpoint SDKs retain all 34 original owners / 743 children and the
full rule suite. The initial eager mnemonic conversion added allocations and
was withdrawn; the accepted version converts only actual legacy memory forms.
Paired timing directions remain mixed, so no acceleration is claimed.

Uniform and per-128-bit byte shifts extend the existing byte grammar with two
transport axes: immediate opcode-extension literals use vvvv for destination,
while uniform counts keep X/m128 independent of data width. The immediate
rotate family reuses that transport without gaining uniform-count forms. All
bytes still derive from original SDK payloads; numerical lowerers and memory
permissions do not follow from these test-format capabilities. Duplicate moves
reuse the unary transport, preserving DDUP.X's m64 tuple separately from the
full-width SHDUP/SLDUP tuples. Immediate word/dword shuffle uses the distinct
`i_rm_r` role format: destination in ModRM.reg, reserved vvvv, and an imm8 tail.
It cannot inherit the shift/rotate opcode-extension operand role or their
mandatory prefix. PSHUFL and PSHUFD retain distinct original Go table rows;
neither spelling is silently deduplicated. Only the dword shuffle admits its
official broadcast forms. These two additions change no numerical lowerer or
input initializer. Reciprocal14 then reuses the existing typed native floating
helper: packed/scalar shape, precision, mask, copied upper bytes and old low
bytes remain separate fields. The original opcode preserves approximation,
ambient MXCSR and native fault semantics. Its actual O2 objects retain both
ordered estimates and dead-result native memory operations; a pure numeric
intrinsic with an ordinary load did not. The core removes 176 implementation
lines including format changes; 45 further lines add private boundary and frame
transfer support, leaving a net reduction of 131 without a new interpreter.
The boundary-only adapter validates lengths and reserved fields but returns no
semantic instruction. Frame permissions still require the original envelope,
byte initialization and owner. Sixty ordinary and six original SP/BP statements
have actual three-API objects; two pointer-as-index forms retain explicit Context.
Native numerical/fault
execution still lacks an independent RCP14 owner and hardware acceptance.
The unique local union reaches 2,073 rows / 7,758 witnesses,
with overlapping rotate views
deduplicated. This is initialized-source/object ownership, not complete amd64
implementation or native execution coverage.

The selected Go 1.27.2 tables contain the following independent pilot rows:

| Family | Legacy XMM | AVX | Total |
|---|---:|---:|---:|
| Wrapping/saturating add | 8 | 64 | 72 |
| Wrapping/saturating subtract | 8 | 64 | 72 |
| D/Q low product | 1 | 14 | 15 |
| Pilot | 17 | 142 | 159 |

Seven PADD MMX rows and ten PMULLW/VPMULLW rows are outside this migration,
not unsupported or newly verified. PADDD's frontend alias adds no encoder row.
The initialized join now retains row identity, not deduplicated instruction
text. High AMD64 registers force EVEX X/Y encoding; the independent original
Go bytes must match the selected official row. The shared encoder and public
three-API harness use bounded batches of 32 functions. Current Go 1.27.3 and
minimum Go 1.20.14 both pass the following Linux/amd64 LLVM22 object scopes:

| Scope | Official rows | Concrete format witnesses |
|---|---:|---:|
| Add/subtract/D-Q low product | 159 | 480 |
| Signed/unsigned integer min/max | 132 | 432 |
| Rounded average, products and multiply-add | 90 | 258 |
| Integer and PS/PD logical | 132 | 504 |
| Integer and PS/PD unpack, low/high | 108 | 360 |
| Signed/unsigned saturating pack | 36 | 114 |
| Per-lane logical/arithmetic shifts | 64 | 236 |
| Conditional sign, B/W/D | 9 | 18 |
| Packed absolute value, B/W/D/Q | 33 | 108 |
| Byte-indexed shuffle | 9 | 24 |
| Integer EQ/GT compare | 72 | 168 |
| Mask blend | 36 | 144 |
| Horizontal integer add/subtract | 18 | 36 |
| FMA3 | 360 | 2,028 |
| AVX whole-vector moves | 144 | 306 |
| Ordinary AVX floating binary | 132 | 684 |
| Local total | 1,534 | 5,900 |

Published `1c54c530e` contains 865 rows / 2,774 witnesses, including all eighteen
horizontal integer rows. Its complete CI now passes 325/325 jobs and Codecov,
with 88.0% main statement coverage. The combined local batch adds ABS
and FMA3 without changing translator production code. Both endpoint SDKs pass
all prior joins, existing initialized/negative owners and the new complete-row
objects: current 112 roots / 9,018 children, minimum 111 / 9,018, no failures/skips.
Previous witness fields and initialized FMA axis sources remain identical.
See [current work](current-work.md) for exact revisions, native boundaries and
publication status.

The subsequent AVX move join adds 144 ordered rows and 306 witnesses: 276
ordinary initialized forms and 30 early terminal faults. Both endpoint SDKs
pass 114 host-applicable roots / 1,765 children without failures/skips. The
102 load-register alternatives shadowed by preceding store rows retain explicit
selection mappings; they reference existing regcopy byte checks and are not
double-counted. Legacy moves and native execution remain separate owners.

The ordinary AVX floating join at `ff2f14caa` adds all 24 PS/PD/SS/SD
ADD/SUB/MUL/DIV/MIN/MAX members through the same initializer and object driver.
It adds 18 shared harness lines for scalar prefixes and register-only SAE;
no translator rule or native framework changes. Both SDKs pass the complete
affected scope, 114 roots / 2,004 children, without failures/skips. Previous
row fields remain identical. Original MIN/MAX NaN, signed-zero, MXCSR and fault
execution remains separate unfinished work.

Two PADDD alias witnesses are separate from the canonical counts. Min/max
includes 48 non-Q, unmasked, narrow EVEX forms; low-register VEX objects cannot
substitute for them. These are initialized named-source/object checks, not raw
decoder or executed-semantic coverage of every row. Complete legacy/AVX mode
applicability and remaining family joins are still required; do not divide this
pilot by unfiltered encoding-table rows to claim an architecture percentage.

The logical join shares the existing row grammar, original-byte verifier and
three-API object driver. Prefix, carrier width and VEX/EVEX identity are
orthogonal encoding axes; impossible VEX512 and conflicting prefix forms fail.
Its 32 names need 19 additional implementation lines, not 504 separate rules.
The seven average/product and four logical MMX rows keep separate region owners.
The residual dword-product dispatcher also loses 40 unreachable production lines;
its original direct fixtures now invoke the same typed owner as public lowering.

The unpack join covers 24 names through the same row grammar and driver, adding
ten scope-selection lines and no translator rule. All original Go bytes and
initialized objects pass on both supported endpoint SDKs. Six MMX rows retain
their independent region owner; this join does not expand native execution
claims or weaken low-MMX m32 versus high-MMX m64 memory-width distinctions.

Saturating pack reuses that same grammar and driver for eight names, 36 rows
and 114 witnesses, adding seven scope-selection lines. Dword inputs alone
admit its 18 broadcast witnesses; three MMX rows remain independent. Both
endpoint SDKs pass the complete initialized join and rule-reader regression
at `d17e46d5d`, without expanding the translator or native execution claims.

The pack parser at `25555b5f0` also shares physical normalization with the four
average/product families, removing 20 production lines. It preserves mode32
error classification, MMX operand ownership and E4NF memory behavior. Current
and minimum SDKs each pass 33 roots / 1,211 children; sixteen parser benchmarks
each remove one allocation and show 9–31% lower median time over five samples.
This measures parsing, not complete-source translation or native instruction speed.

The per-lane shift join at `376a9f4d0` adds nine names, 64 rows and 236 witnesses
through the existing binary grammar and object driver, with no translator rule.
Both endpoint SDKs pass 30 roots / 394 children. A shared test inventory removes
repeated family loops while preserving independent official membership, literal
encoding anchors, unique row IDs, width/encoding axes and separate MMX owners.
The complete batch removes 126 net lines. Its 54 broadcast witnesses and narrow
EVEX forms are object evidence, not new native execution acceptance.

Conditional sign at `2c2c98295` adds all six B/W/D names: three legacy and six
VEX rows, 18 register/memory witnesses and six independent byte anchors. Go has
no MMX, EVEX or broadcast row for this family. Sharing the anchor assertion loop
with UNPACK and per-lane shifts preserves their original 19 byte anchors. The
complete rule reader, new object owner and listing-identity negative pass on
both endpoint SDKs: 25 roots / 88 children each. This adds 17 net lines across
six files, with no translator rule or new native execution claim.

Packed ABS adds all seven named members, 33 original rows and 108 witnesses.
The unary adapter retains reserved VEX.vvvv/EVEX.V', width, broadcast, masks and
zeroing, while typed effects retain the independent old-destination reads.
It reuses the original ABS/sign initialized source and the bounded byte/API/
object driver, without changing translator production code or native fixtures.
At `b5ca7da71`, the full affected scope passes 60 roots / 1,048 children on
Go1.27.3 and 59 / 1,048 on Go1.20.14, zero failures/skips. The syntax-metadata
follow-up `65ef2b9bf` passes 4 roots / 43 children on each endpoint SDK and the
complete Node/Go preflight. Every field of the previous 865 rows / 2,774
witnesses and the two PADDD aliases remains identical on both SDKs. Existing
portable numerical execution remains separate from original x86 native evidence.

Fixed-frame GP analysis now consumes the existing typed byte/FLAGS effects
instead of a second arithmetic opcode list. Its bounded worklist intersects
numerical definedness across loops while retaining exact address identities.
All eight original SP residues and the independent final replay remain checked;
provisional loop accesses are published only after convergence. Numerical LEA
and sized NOP addresses are not mislabeled as actual memory accesses. Ordinary
typed-input base/displacement reads now compose with private scratch through
the existing exact-width faulting scalar path. Full-word affine operations can
now retain that input's origin without converting its representation to NUM or
granting a pointee extent. Indexed private scratch retains its separate limits.
BP/R14 entry bytes stay unknown; a defined value may use the complete GP bank.
Named LEA and scalar MOV share machine grammar with ordinary consumers, while
source-role filtering stays separate. An exact native-input access selects the
fault-preserving scalar emitter even through BP; it is never a private-frame
certificate. Full-source and native tests remain separate gates.

Fixed-local result consumers now share a call-local independently parsed
original file and complete ordered feature index. Public module entry/exit
still perform live source verification; standalone internal consumers retain
their original guards. This reduces repeated source/tool work without caching
mutable verification or removing per-function proof replay. The measured
one/four-function API fixtures keep exactly two verification rounds; complete
standard-library translation has not yet shown a speedup.

The new result-mask helper emits five vector IR instructions instead of a
lane-wise sequence. This is not a five-machine-instruction or constant-runtime
claim: LLVM may split its predicate vectors. Shared splat formatting has constant
allocation count but necessarily linear output size. Keep the independent
runtime oracles and measure generated-program performance on actual AMD64
hardware before claiming that whole-axis improvement.

The scalar CMP/TEST join now selects the complete semantic family before
formatting official rows. This restores four TESTB rows that used the shared
`yxorb` table and were silently excluded by a format-table-name filter. All
eight B/W/L/Q members retain 35 ordered rows, 54 AMD64 witnesses and 40 mode386
witnesses; nine original mode386 frontend refusals remain distinct. Independent
literal TESTB encoding anchors and missing-input controls do not repeat the
production selection predicate. Both endpoint SDKs pass 32 roots / 3,470 nodes
through the original-byte checks, three public APIs and five-target O0/O2
objects. This changes row projection, not numerical lowering.

Read-only BTW/BTL/BTQ uses the same family-first selection and initialized object
driver. Six ordered rows produce twelve AMD64 witnesses; mode386 admits four
rows / eight witnesses and retains the two actual BTQ frontend refusals. The
initializer preserves old ZF and the original data operand while exposing CF;
undefined AF is not asserted. Twelve independent encoding anchors keep the
syntax and object checks separate. The complete affected union passes 3,181
nodes on current Go and 3,178 on minimum Go; the difference is the original
SDK-dependent RDPID reader scope. Each SDK also executes all twelve existing
portable C-oracle pipelines.

The separate Linux/AMD64 qualification of `f0d322e5` runs all six original
CMP/TEST/BT numerical and fault roots on both endpoint SDKs: twelve root
executions and 140 child executions, all 152 PASS with zero FAIL/SKIP. Source,
LLVM 22 tools, full Go JSON and both actual artifacts are checked independently.
This closes those native owners; it does not certify every encoding row's
semantics, native386, AVX512 hardware or whole-source performance.
