# Instruction-family development

Read the repository [rules](../../AGENTS.md) first. This guide describes the
workflow, not a list of already completed instruction families.
The [architecture guide](architecture.md) defines the pipeline, evidence levels
and terms used below, including raw continuation, producer replay and native backing.

## Sources of truth

- Use the supported Go toolchain's assembler tables under
  `$(go env GOROOT)/src/cmd/internal/obj/<arch>` as the authority for opcode,
  operand, register, suffix, masking, broadcast, and rounding forms.
- For x86 AVX/EVEX instructions, inspect both the referenced `ytab` and every
  opcode attribute in `avx_optabs.go`. A shared `ytab` does not imply that
  rounding, SAE, broadcast, or zeroing flags are identical.
- Confirm uncertain forms with the Go assembler. Do not infer a form solely
  from Intel syntax or from a third-party source file.
- Treat `386`, `amd64`, `arm`, `arm64`, and `wasm` as supported architectures.
  A form must not be classified as unsupported merely because the host has a
  different architecture.

## Instruction-family workflow

XCHG B/W/L/Q uses the emitter's complete exchange grammar in fixed-frame,
caller-origin and canonical-byte observers. Scalar MOV and XCHG share value
reads and writes: snapshot both inputs, preserve full-word pointer identities,
constants and ranges, and never reinterpret a pointer as NUM. Memory exchanges
write their original address before changing an aliased base register; private
RMW requires initialized bytes or an exact pointer spill. Native memory retains
the existing implicit-lock emitter, faults and ordering, without new extent or
alignment permission. Narrow writes revoke whole-word facts, while Go's AX/AX
opcode 90 remains a true NOP. Keep independent original-Go execution alongside
width/alias proofs and objects; object success alone is not execution evidence.
CMOV reuses the same scalar values and complete conditional-move grammar.
Both alternatives and the unconditional memory read remain required. Selection
preserves identical pointer identities and constants, intersects canonical bytes,
and takes the hull of known numerical ranges; differing origins stay Context.
W/L writes retain their architectural upper-byte rules and preserve FLAGS.

ANDNL/Q and PDEPL/Q/PEXTL/Q share Go's complete `_yandnl` operand grammar
and ordered two-input/one-output byte effect, not their numerical or FLAGS
operation. Mode32 ignores VEX.W, including Q memory widths. ANDN defines only
CF/OF/SF/ZF and kills AF/PF knowledge; PDEP/PEXT preserve FLAGS. MULX's
different input/output roles do not inherit this registration. Lowering shares
exact-width native GP read emission with ADX, not its carry obligation or memory
permission. Keep ordinary named register/logical storage in the strict transfer;
the special adapter consumes only an exact raw origin or independently paired
native read. Preserve original Go/emitter format objects and public Context,
initialized objects, original portable values/aliases and live/dead NULL/page
fault controls. Infrastructure errors are not Go assembler rejection witnesses.

ADCXL/Q and ADOXL/Q share the complete `yml_rl` grammar, encoder offset and
ordered source/old-destination byte effect. Only the selected CF or OF chain
is read and written; all other FLAGS and unrelated storage stay unchanged.
Exact raw opcode, operands and original default address size permit only a
paired numerical projection. Overrides, physical segments, raw entry and
caller/frame roles remain independent. Native reads retain their exact width,
unaligned volatile effect and input requirements even for dead results.
Keep original uninitialized formats as Go/emitter objects plus public Context;
initialized public objects and portable carry-chain values are separate from
required original native execution. The raw continuation guard belongs after
authenticated numerical readers, not in the physical MMX ownership scan.

The eight BMI2 L/Q shifts and rotates share their complete opcode table,
source grammar, physical-mode width and count masking with lowering. Exact
decoded operands permit only a paired numerical continuation. Native sources
retain their exact volatile reads; no caller, frame or later-read fact follows.
The existing closed nontrapping GP domain may keep a dead result unknown.
Do not confuse that with initialized bytes: result, address, store and control
uses still require their actual numerical inputs. Keep original source replay,
every-byte/alias negatives, five-target objects and portable value/FLAGS tests.

VZEROUPPER/VZEROALL compose with named native reads only after exact decoded
zero-operand identity checks. Share that identity check with implicit GP
extensions, not their distinct effects. Mode32 writes only banks 0-7, amd64
0-15; upper banks and preserved low bytes retain their original knowledge.
Full-bank portable execution is separate from native opcode/MXCSR execution.

Raw scalar counts and X/Y move-mask sources compose with native output only
after their complete existing grammar and exact original operands validate.
Keep count input widths, W preservation, L zero extension and CF/ZF versus
all-status availability distinct. Move-mask preserves vector aliases and FLAGS.
Both reuse existing typed effects; neither grants memory backing or physical
MMX/x87 state. A numerical address is not an incoming pointer. Preserve exact
original Void/native-output counterexamples as well as register-return objects;
the latter alone did not find this routing defect. Original named text flags
require their real header in the independent Go object, never a rejection guess.

The six implicit accumulator sign extensions share one complete `ynone`
grammar with lowering and exact GP effects. Zero source operands do not mean
zero AX inputs: require the actual byte/word/dword/qword source even for Void.
Word writes preserve unknown upper destination bytes; dword writes zero-extend.
Named and exact decoded forms preserve FLAGS. Only the lowering continuation
consumes raw origin; public queries gain no native entry or frame permission.
Keep isolated named/raw negatives, initialized five-target objects, every-bit
portable values and original native FLAGS execution as separate axes.

DWORD-to-qword products consume the existing complete binary grammar and
shared numerical input model. Masks and merge bytes remain required, including
Void; raw continuations bind their original operands and complete physical mode.
Original uninitialized format/disp32 probes retain Go/emitter objects plus
three-API Context controls. Independent initialized objects own public success;
neither a direct emitter nor a classification change grants caller memory.

The two IFMA names share their complete six-row EVEX grammar and ordered
numerical inputs. Each qword consumes source bits 51:0 and every accumulator
byte, even with zero masking. Unknown register results may stay unknown; masks
and every observable byte remain actual inputs. Memory retains the full E4
tuple or eight-byte broadcast with guarded volatile reads. Physical mode32
mask encodings do not inherit Go's named four-operand cap; exact source identity
and all remaining bank/address checks still apply. Encoding-aware writeback
clears wider aliases. Preserve independent full Go attributes, every-byte and
nonzero-upper controls, original unbound formats and initialized public objects.
Portable integer LLVM execution does not qualify original AVX512 execution.

Qword bit lookup shares complete binary/K-result grammars and EVEX field
decoding with IFMA, not its numerical or access policy. VPMULTISHIFTQB retains
the full E4NF tuple or m64 broadcast even with a zero mask; VPSHUFBITQMB uses
byte-granular E4 suppression and a write-only K result. Bind all Go rows and
attributes independently. Source data, masks and merging bytes remain required,
and encoding-aware vector writeback clears wider aliases. See Intel's
[E4NF reference](https://cdrdv2-public.intel.com/843829/325383-sdm-vol-2abcd-dec-24.pdf)
and [BITALG encoding/access metadata](https://github.com/intelxed/xed/blob/main/datafiles/bitalg/bitalg-isa.xed.txt).

All eight raw immediate packed compares reuse their existing typed shape and
numerical transfer. Bind the full original selector and operand identity before
selecting source index one. Capture the physical form before a lowering-local
provenance projection: reparsing it afterward must not reapply named mode32
arity limits. Complete incoming-pointer and E4 input obligations remain; no
standalone query, caller, physical entry or frame authority follows. Preserve
original unbound format objects plus Context separately from initialized
five-target public objects, every predicate and missing-input mutations.

VPERMILPS/PD share all eighteen Go rows with lowering and result definedness.
Immediate selectors consume only selected bytes within each 128-bit lane;
variable selectors require the actual data and low control byte for each
element. Unknown result bytes stay unknown. Masks and merging bytes remain
inputs; zeroing does not supply a missing pointer or selector. E4NF memory
reads retain the entire volatile tuple, or exact m32/m64 broadcast, even for
Void and zero masks. Encoding-aware writeback clears wider aliases while
preserving independent GP, FLAGS and private state. Complete sealed raw
producer replay remains a restriction even when only origin metadata is erased;
neither decoder identity nor private format objects authorize named inputs,
native memory or raw entry. Keep original unbound Go/public Context controls
separate from initialized public objects and required runtime execution.

MULXL/Q has its own complete source/implicit-DX/two-output form, not ANDN's
read/write roles. Capture both inputs before either output, zero-extend L
results, and preserve FLAGS/DF and unrelated private/caller state. Native
reads retain exact volatile widths even for Void. Exact raw continuations
require complete immutable producer replay; a decoder origin is not NUM or
backing. Physical SP/AMD64 BP outputs and effective memory base/index sources
need their separate whole-source role; virtual stack storage is not native
backing. Go386's ignored static-SB base annotation remains a different role.
Preserve ordinary owned-DATA dead-register controls. Mode32 WIG observation
does not grant an ordinary qword entry. Keep uninitialized original formats
as actual Go/LLVM objects plus public Context, separately from initialized
public programs. Private format units call the same pure emitter after shape
validation; never set a cached proof flag or invent input/pointer authority.

Conditional moves retain the old destination and actual predicate dependencies;
their native source read is unconditional, including false predicates and Void.
The existing nontrapping GP domain may leave a dead named-register result
unknown, but no later result, address, store or control use may consume it as
initialized. Exact raw identity permits a lowering-local numerical view, not
a pointer, frame, standalone-query or native-entry fact.

AES/VAES share complete round, inverse-mix and key-assist forms and byte
dependencies. Immediate-first key assist selects its data source through the
typed operand index; bind every original operand, including the selector,
before using that index. Memory retains its complete physical envelope even
when only selected register subwords contribute numerically. Preserve original
legacy alignment faults, VEX/EVEX upper-zeroing, and independent FLAGS/DF/ID.
The existing nontrapping register domain may propagate unknown result bytes;
accepting that transfer never initializes them. Later observable data/control
uses still require their exact bytes. Native reads retain their complete input
and access obligations even for dead results. No value comes from an
implementation slot merely initialized to zero.

Physical MMX observers keep the entire source branch-free and their region
uninterrupted through real EMMS. Seed status and prepare unrelated state before
entering the region; do not relax that boundary to accommodate an old fixture.
Architecture-scoped dispatch maps must remain visible to supported-op extraction;
test the isolated source file as well as whole-repository reporting.

The two ordinary half conversions share their complete eighteen-row Go grammar
and precision-family carrier/input helpers, not raw-only FP16 permission.
Preserve VEX/EVEX physical identity, integer-expression imm8 classification,
mode32 named/raw arity, active bytes, merge and mask inputs, including Void.
Narrowing memory uses its real masked native opcode, not conversion plus an
ordinary store. EVEX.z memory faults before source, mask or address evaluation;
Go's SAE-memory rejection is separate. Matching x86 emission retains original
MXCSR and exception effects, including dynamic immediate controls 4–7.
Authenticate the complete raw producer before any continuation. Original Go
objects, initialized five-target public objects and explicitly private fixed-
rounding mathematics are separate evidence; the latter is not native execution.

Raw-only FP16 floating conversions distinguish active scalar/lane bytes from
their X/Y/Z carriers. Decoder identity binds the original operands and vector
length; actual mask, merge and source inputs stay mandatory for Void. Keep
scalar passthrough unknown where its source bytes are unknown, and clear wider
aliases according to EVEX. Matching x86 targets emit the original opcode to
preserve MXCSR, exceptions and masked access; cross-target numerical execution
is a separate oracle. Check actual object controls, not just LLVM compilation.
Dispatch conflicts and malformed addresses must fail before emitting any IR.

Raw FP16 SQRT shares the named SQRT grammar and byte dependency, not its caller
permission. Exact decoded source identity is required by the lowering-only
continuation. Scalar upper bytes preserve their actual source knowledge;
packed Z needs all 32 mask bits. Share the native scalar emitter with FP16
conversions while retaining each family's memory width and arithmetic opcode.
Original unbound formats, initialized public objects and portable numerical
execution are separate axes; none certifies native FP16 hardware execution.

Raw FP16 FMA shares the existing thirty-member typed family. Each order reads
both explicit sources and the old destination, including .Z. Scalar upper X
bytes come from the old destination, not the second source; retain unknown
bytes as unknown. Reuse the three-operand native emitter with scalar
conversion/SQRT, preserving the actual opcode, memory tuple and full 32-lane
mask. Exact raw identity only permits the paired lowering result; it grants
no caller, standalone query, physical entry or memory-backing authority.

Raw FP16 binary arithmetic shares the existing floating binary grammar and
byte dependencies. Keep all twelve packed/scalar members, full 32-lane masks,
scalar upper bytes from the second source, and old destination bytes only for
merging. MIN/MAX SAE and arithmetic ER have distinct native controls. Exact
decoded identity gates the paired lowering continuation, including Void;
unbound original format objects remain separate from initialized public objects.
Portable numerical/guard-page execution does not certify native FP16 execution.

Treat an external-library failure as a counterexample to the systematic
coverage mechanism, not only as a package-specific regression. Identify where
the independent Go rules, typed grammar, lowering/effect consumers or executed
tests diverged; then enumerate and repair the entire affected rule class.
Add a regression that still finds the defect without that external library.
Rerun both the complete affected class and the original discovering sample.

REP/REPN SCAS/CMPS does not define status FLAGS when its count is zero. A paired
whole-source result proof may nevertheless accept a following conditional when
both bounded zero-count successors write the same complete constant result and
have no observable memory or call effects. Full-width exact copies can cancel;
shared pointer origins, changed offsets and partial writes cannot. Keep the
ordinary nonempty input/access proof, CFG joins and shared work limits intact.
This rule never grants FLAGS to another consumer or a standalone query. CLD/STD
always update virtual DF; only matching x86 targets emit the physical instruction.
Check both incoming native ZF states separately from portable value execution.

Keep the Go-table oracle independent of the implementation spec. Retain each
encoding row's prefix, zcase, byte offset and opcode-specific attributes as well
as its operand classes. A shared ytab or a name/row count is not a complete
format check. Concrete syntax witnesses do not prove which overlapping encoder
row Go selected, LLVM object success, runtime semantics or an ABI contract.

Non-temporal vector moves share the complete legacy yxr_ml/ylddqu and both
five-row AVX tables, including MOVNTDQ's MOVNTO alias. Retain actual native
opcodes: LLVM nontemporal/align metadata cannot preserve dead-access or alignment
faults. Legacy loads preserve wider aliases; VEX/EVEX loads clear them. Legacy
Yml register destinations fault before inputs. VEX.WIG is not EVEX.W0/W1;
masking, zeroing and broadcast remain reserved. Reuse packed fixed-local byte,
alignment and spill-revocation proofs, not another memory permission. Native
byte boundaries grant neither raw entry nor symbolic-read authority. Original
unbound formats need Go objects and public Context controls; initialized
counterparts own public objects and separately required runtime evidence.

A bound whole-instruction prefix must own dispatch before overlapping generic
handlers. For scalar LOCK, an emitted correct helper is not evidence that the
source operation uses it: inspect every original function body through all
public APIs and both IR levels, then retain actual objects and native execution.
Keep complete prefix adjacency, carry, frame and address checks unchanged.

Use test-driven development for every instruction change:

1. Reproduce the unsupported instruction or incorrect operand-form behavior in
   a focused test and run it to observe the expected failure.
2. Before implementing the opcode, enumerate its complete family and all forms
   in the current Go assembler tables. Add positive and negative form tests.
3. Implement a coherent instruction family, not only the single spelling that
   exposed the gap. Cover every X/Y/Z width, register and memory source,
   architecture restriction, mask/zero form, broadcast form, and rounding/SAE
   form present in the Go tables.
4. Compile generated IR with LLVM 22 for every affected target. Add runtime
   conformance when an instruction's lane preservation, operand order, flags,
   masking, NaN behavior, or memory effects are not established by compilation.
5. Rerun the discovering external-library shard or official corpus that exposed
   the problem. One fixed mnemonic must not hide another form from the same
   family.

Prefer typed, table-driven grammars over mnemonic-specific branches. Separate
orthogonal axes such as operation, lane/stack width, operand class, encoding
generation, architecture mode, masks/broadcast/rounding, implicit registers,
and semantic effect. The parser/validator, register-liveness scan, lowering,
supported-op extraction, and completeness test should consume the same spec
where practical. A completeness test must compare the whole spec table with
the current Go encoder family so adding one observed spelling cannot leave
sibling forms unmodeled.

The twelve compact/expand names share Go's complete `_yvcompresspd` and
`_yvexpandpd` grammar: X/Y/Z widths, matching banks, optional K1-K7 and masked
register zeroing. Compressed memory `.Z` encodes an architectural #UD before
source, mask or address access, not an ordinary store. Keep original Go bytes,
fault-priority controls and all-five-x86-target objects. Isolated probes lack
initialized source/mask/merge inputs; complete sequences must establish them
without borrowing zeroed implementation slots. Logical FP fields are separate
scalar allocations: gather expand inputs and scatter compact results across
their actual fields, retaining masked tails and rejecting missing bytes or
incoming-parameter writes. This grants no contiguous native backing or new
caller-memory permission. Preserve the independent scanner-input regressions
when intentionally updating the official classification baseline.

Keep mandatory numerical/result obligations separate from cost-only routing.
A newly modeled family must not bypass its complete source proof because a
function has no result store, an unused bool parameter, another storage role,
or an unused FP address. That role needs its own proof, not an exemption.
Unknown source/result bytes cannot fall back to zero-initialized implementation
allocas. Test these boundaries through all public APIs, including default and
explicit architectures; retain independent canonical-bool and memory contracts.
The complete SETcc family consumes predicate FLAGS for every named destination,
including dead register writes in Void functions. Only SETCC/SETCS can consume
a lone CLC/STC producer; that CF fact does not define other predicates. Neither
an unused bool parameter nor a native-only routing predicate supplies FLAGS.

Private bool tails retain the source architecture when selecting their consumer.
AMD64 no-CALL tails belong to the existing whole-source direct-tail proof, not
the 386 custom-register helper graph. Handoff still verifies live source and
declaration observations; default mode means AMD64. Keep all 16 SETcc predicates,
canonical result bytes, independent helper frames and actual 386 helper tests.
Portable i1-to-i32 value execution is not native entry or C bool ABI evidence.

All four floating x87 moves share their existing F/D, load/store, pop and
register grammar. Paired native 4/8-byte accesses remain unaligned and volatile;
reads consume an incoming pointer and numerical indexes, while stores retain
the stricter pointer-base role. Reuse x87 value/depth effects and require source
bytes even for Void. W/L/Q PUSH reads use their exact stack-width grammar and
a transfer-local read view; no later backing or standalone-query fact follows.
Retain original Go objects, three-mode target objects, portable values/canaries
and exact dead-access faults. Native x87 environment/exception execution stays
with its required original-source runtime owners.

Complete 386 x87 rounding leaves may save and restore two control words within
one physical word below unchanged SP. The closed save/copy/change/FRNDINT/restore
grammar changes only RC bits, preserves the original zero-frame NOSPLIT source,
and uses the existing native control-word and byte-initialization effects.
It grants no named AUTO frame, incoming-SP backing or ambient Software control.
Keep the complete SDK floor source, all 70 register/control/layout cases,
mutation boundaries and the required native original-Go/LLVM runtime owner.

Mode32 zero-argument manual I8/I16/I32 returns use the existing logical AX
transport. Share its CFG and exact-byte return obligation with the distinct
custom-register bool checker; I1 still needs canonical zero/one. Route absent
and partial AX writes through that proof even without another numerical effect.
The role has no FP layout, native frame, raw entry or incoming register bytes.

Mode32 private FLAGS copies retain bounded bit dependencies across W/L PUSHF
and POPF. Shared B/W/L XOR grammar consumes only original bare SP offsets
within reaching PUSH depth. An adjacent popped register may cancel identical
unknown dependencies; it cannot expose an unrelated unknown bit. Clone and
join those dependencies conservatively, charge them to the shared byte budget,
and revoke the popped view after one instruction. Complete source replay and
paired lowering own this storage; standalone queries retain their old boundary.
Keep negative named AUTO separate from the mutable private SP projection in
both the proof and emitter. Original source objects and portable numerical
execution remain separate from native FLAGS/ABI conformance.

Indexed permutes and GFNI share the existing typed EVEX/VEX binary grammar;
unary vector bit counts project their original two/three operands locally.
Never mutate source operands to reuse a grammar. I2 old-destination indices
and T2 old-destination tables remain inputs even with zero masking. Complete
vector reads use actual X/Y/Z byte views, not the older scalar/legacy-X reader.
Memory widths come from each opcode's full tuple or independent broadcast
attribute. Shared numerical dependencies grant no native/caller memory role.
All VEX/EVEX value writers, including unmasked and masked native expansion,
must use the encoding-aware vector writeback. A generic legacy X store may
leave nonzero Y/Z aliases stale even when the source-result model correctly
marks them zero. Seed the complete old vector with nonzero bytes and observe
inactive aliases independently; zero-input or low-result-only fixtures cannot
establish this behavior. Keep legacy SSE's upper-preserving writeback separate.
Keep the actual architecture when projecting unary mask arity or physical
decoder operands. Go-accepted non-SIB extended GP bases in mode32 retain their
missing physical context only after the complete remaining grammar validates;
invalid SIB/index, scale, suffix or mask syntax cannot borrow that boundary.

Native GFNI and indexed permutes retain complete E4NF source-tuple reads even
when masks or a dead table make the numerical result independent. Packed bit
counts retain E4 per-lane access suppression. Reuse exact volatile full/guarded
read helpers, including independent broadcast widths. The paired lowering
continuation supplies conditional numerical values only; it never grants
pointer backing, a declaration-query result or a reusable memory certificate.
Keep all 23 members, complete object axes, missing-input/Void regressions and
live/dead guard-page checks. Portable Software execution is not native AVX512.

Native compact arrays advance their offset only for enabled lanes. Paired
source continuation consumes exactly guarded volatile accesses; masked stores
do not read old destination bytes or establish future read facts. Keep logical
FP/AUTO scatter/gather separate. EVEX.z memory compression faults before any
mask/source/address read, rather than behaving like a zeroing register result.

CRC32B/W/L/Q shares the complete Go source grammar across lowering, liveness
and numerical effects. Every row reads the old accumulator's low32, uses its
exact source width, zero-extends its result and preserves FLAGS/DF. Go's
CRC32B Px encoder has different byte-register/REX aliases from MUL's Pb row;
retain independent original-Go byte witnesses. Native reads must stay exact,
unaligned and volatile even when their result is discarded. Only the paired
lowering continuation may consume their conditional numerical result.

Scalar shifts and rotates share the complete Group2, double-shift and BMI2
grammar with memory effects. Native RMWs retain exact volatile loads and stores,
including count zero; BMI2 memory sources retain only their exact volatile read.
Mode32 BMI2 Q spellings still access four bytes. Check every observable count/data
byte, address and incoming CF before aliased writes; native accesses retain
their input obligations even for Void. The closed nontrapping register domain
may propagate dead unknown values, never use them as initialized outputs.
Continuing a paired native access defines numerical outputs, not pointer,
pointee, caller, raw-entry or reusable memory facts. Logical FP/AUTO storage
retains its separate byte-view contracts. W double shifts with unbounded counts
remain Context because some counts have undefined architectural results.
Keep the complete independent Go rows, original conformance programs, portable
full-count/FLAGS/canary execution and the required native Linux original-Go/LLVM
guard-page/read-only oracle separate. A zero-count original-opcode hardware
spot check does not qualify the complete LLVM native counterpart.

A proper low-mask AND projection requires both actual caller-address and
complete pointer must-facts, never an opaque pointer alone. Its B/W/L/Q write
defines only the written bytes and revokes every address identity. Native-word
INC/DEC may preserve an already proved affine caller pointer, including only
the old knowledge of CF; partial or unknown inputs cannot create one. These
rules add no memory backing, bounds, raw entry or store permission. A numerical
family may consume an already checked cached mixed-bool canonical role; it
cannot manufacture that role from initialized bytes or a bool declaration.

Macro expansion uses complete Go assembler identifier tokens, including middle
dot and division slash, never prefixes or text inside string/character literals.
Unresolved constants need context for an isolated instruction probe, but must
fail full translation before raw decoding. Preserve resolved named stack
addresses; never replace missing constants or malformed addresses with zero.

X86 branch operands use the original Go case-sensitive register namespace before
shared aliases: lowercase or foreign register-looking labels stay labels, while
actual Go registers retain their indirect/register semantics. Apply this to the
complete jump class, including CALL, LOOP, XBEGIN and conditional hints. A local
CALL label can pass Go's parser and crash its encoder; parser coverage is not
an accepted object or ordinary rejection. Preserve independent token, object and
executed-result controls without relaxing target or callee boundaries.

ARM64's fresh virtual SP allocation is disjoint from incoming pointers only
when the complete original and normalized source excludes escaping its address
and entry transport cannot replace SP. A source CFG proof may admit exact
affine GP temporaries used only for bounded, non-writeback local reads and
fully overwritten before calls or returns. Mixed/different-offset joins keep
may-frame taint; unknown effects, indexing, address stores and live call/result
transport cannot wash it away. Under that bounded proof,
ordinary pointer stores and pure escaped code-address values cannot corrupt
saved SP cells. Actual source arithmetic/transforms on a code address must
retain derived-code taint even after unknown CFG joins; filtering ordinary
data cannot turn a computed native PC into a pure-code alias proof.
Explicit/aliased/indexed SP writes, FP contents, unknown callouts,
raw/native effects and frame-address escape remain conservative. Audited
same-file register helpers retain the original proof across local-call
rewriting; a bare source-local call never acquires it. Scalar and paired atomic
stores must account for their memory operand as well as GP outputs.

Raw-containing framed ARM64 source-leaf functions have a separate bounded
physical-SP proof, checked on both original and normalized CFGs. Constant SP
movement must balance on every source RET; different-delta joins fail. R29 and
the automatic saved-FP cell start as unknown may-frame values. Known scalar and
GP/FP pair memory forms preserve private eight-byte pointer spills and reject
partial overlap, unknown indexing/writeback and SIMD pointer transport. Only
the actual Go framed-leaf RET epilogue consumes R29; continuation/LR checks stay
independent. External stores, live result aliases, calls, hardware RETs and
unregistered effects cannot borrow this proof. Go's physical autosize is not
the LLVM private-allocation size. Runtime oracles must execute original raw
Go objects as well as LLVM objects with independent references and canaries.

ARM64 VMOV/VDUP availability records the validated source lane span separately
from implementation loads that merely preserve other destination bytes. Lane
insertion defines only the written bits; F/V aliases and CFG joins retain the
unknown remainder, and a full vector consumer still needs all of its bits.
Scalar/arranged non-preserving transfers clear their architectural inactive
bits. Typed calls and source scratch invalidation revoke prior lane definitions.
This is numerical definedness, not caller, pointer or private-frame permission.
VDUP's arranged case79 derives both source width and index bounds from its
destination; the source suffix identifies only the ELEM class. VMOV and scalar
VDUP retain their separate suffix-selected bounds.
Lane syntax shares Go's single decimal-token rule after CPP expansion: trim
lexical whitespace, reject signs/expressions/nondecimal or unresolved tokens,
and retain every instruction's independent physical width/index bound.

CPUID/XGETBV share the complete Go `ynone/Pm` rows with implicit low-dword
inputs and zero-extended GP outputs. Read all inputs before writing any output;
retain that obligation for Void and unused-bool signatures. Only actual output
registers lose caller-address identity. Exact original/normalized query identity
preserves FLAGS, DF and private numerical storage, not a native entry, source
stack or caller-memory contract. Keep pointer, partial-byte and CFG negatives,
original bare-source Context controls, initialized all-target objects and the
required original-Go/LLVM native AMD64 and IA32 execution owners separate.
Timestamps reuse the identity boundary but retain their own input/output spec.

RDRAND/RDSEED W/L/Q share all six Go `yrdrand` rows with the result observer.
Their destination is write-only at the exact width: W preserves unknown upper
bytes and L zero-extends. NUM means machine bits, not successful entropy or a
vendor-independent CF=0 value. Only CF reports availability; the other five
status flags clear. Exact original/raw identity preserves unrelated registers,
DF/ID and private storage. Physical SP/BP and missing ABI results remain separate
obligations, even for Void. Retain full encoder attributes, all register codes,
partial-byte negatives and original format objects; object compilation does not
qualify native random execution.

ENQCMD/ENQCMDS share exact named/raw operand and address-size grammar. Both
GP address operands are read-only; an actual native continuation defines ZF
retry and clears the other five status flags. Preserve the native side-effecting
64-byte command read, memory clobber and fault/privilege behavior, not memcpy.
Only independently established incoming addresses supply the public native
continuation. Raw identity, original mode, initialized inputs and complete ABI
results remain mandatory, including Void. No submission success, PASID, CPL,
alignment, backing or later pointee-read fact follows. Check all ModRM/SIB,
address16 and displacement boundaries before IR. Original unbound/segment/
address-override formats keep Go/emitter objects and public Context; independent
initialized programs own public objects. Neither objects nor status simulation
qualifies native device execution.

UMWAIT/TPAUSE share their existing implicit-system grammar with mandatory
low-dword control and EDX:EAX inputs. Their native continuation defines CF and
clears the other five status flags without changing GP, DF or private storage.
Raw source retains exact original/normalized opcode and operands; it cannot
borrow address-size, segment, raw-return or monitor-address roles. Input proofs
remain mandatory for Void, unused bool and every CFG path. Original unbound
formats retain Go/public-Context/emitter coverage; separate initialized status
programs own public objects, not a native-execution claim. The other system/RTM
and hardware-status families retain their independent effect obligations.

RTM's four-name grammar is shared by lowering and XTEST's numerical effect.
Only the exact zero-operand query defines all six status flags without numerical
inputs and preserves unrelated GP, DF and private storage. The same identity
checks apply to decoded raw source; no entry, frame or memory role follows.
Do not grant transaction begin/end/abort an ordinary straight-line effect.
XABORT requires a resolved integer in 0..255, not a floating token with an
integer zero field. Retain dispatch identity and complete byte-domain objects;
compiling the native RTM opcode is not hardware execution qualification.

The eight mask/vector B/W/D/Q moves share a register-only EVEX grammar with
X/Y/Z widths and K0-K7 data operands, never writemasking or suffixes. Caller
and numerical effects require actual mask data or each vector lane's sign
byte; unrelated lower bytes do not contribute to a reverse result. Forward
writes clear every wider alias, while reverse writes zero-extend the mask
remainder. Missing inputs remain obligations for Void and unused-bool entries;
internal implementation zeros supply neither data nor a named/physical entry
contract. Use the
encoding-aware packed writeback even for X destinations: legacy `storeX`
preserves wider bytes. Independent whole-byte runtime checks must observe both
directions separately rather than relying only on a round trip.

KMOVB/W/D/Q is a separate grammar. B/W/D-to-GP defines the complete zero-extended
native word; its FP/native memory effect still uses only the named byte width.
Logical FP reads gather exact fields, and narrow stores retain untouched bytes.
KADD, KSHIFT and KUNPCK share two complete typed operand shapes, not numerical
operations. Every source mask remains required, even for Void and oversized
shifts; floating/unresolved immediates never become Yu8. A checked normalized
caller continuation must consume its exact original source/signature/stack
owner, not impersonate a logical FP proof. Paired native KMOV and all sixteen
SETcc byte stores retain exact unaligned volatile effects and known inputs or
FLAGS. They supply no reusable memory, pointee, raw-entry or caller permission.
Format-only sources keep original Go objects and explicit Context controls;
separate initialized counterparts own executable and public LLVM coverage.

KAND/KANDN/KOR/KXNOR/KXOR/KNOT/KTEST/KORTEST share the complete B/W/D/Q
K-register grammar. KNOT never reads its write-only destination; only equal-source
XOR/XNOR/ANDN is input-independent. TEST variants define all six status flags,
not DF/ID. Exact original/normalized raw identity may preserve existing GP,
direction and private-stack facts; it grants no memory, entry or frame role.
Void and unused-bool signatures retain input obligations. Preserve independent
Go encoder attributes, named/raw portable values and original unbound formats.

PSADBW/VPSADBW/MPSADBW/VMPSADBW/VDBPSADBW share ordered byte selectors
across lowering, caller and result analysis. Only corresponding-byte block SAD
with identical register sources is input-independent; sliding/shuffled forms
are not. Memory still consumes the complete native tuple, even with zero masks
or dead outputs, and legacy m128 keeps its original opcode/fault behavior.
VEX VPSADBW/VMPSADBW and EVEX VPSADBW ignore W; VDBPSADBW requires W0.
Test physical WIG independently: Go's encoder emits only W0 for these forms.

The eight SQRT names share the floating operand grammar and one caller/result
byte dependency. Only the first operand supplies numerical input; scalar
VEX/EVEX copies its second operand's upper X bytes without requiring unused
low bytes or inventing unknown passthrough bytes. Masks and merging inputs stay
required even for Void. Retain actual side-effecting native opcodes: default
MXCSR, dead exceptions, memory faults and explicit ER+SAE are not pure sqrt IR.
Packed memory requires native backing; logical field addresses authorize only
exact bounded scalar reads. Caller bounds alone do not establish legacy m128
alignment. Physical VEX.WIG, scalar EVEX.LIG and low-bank mode32 masks need
independent LLVM-MC witnesses; scalar VEX.L1 stays rejected as unpredictable.
Preserve raw EVEX generation through feature inference and native emission.
Complete initialized named/raw three-API objects on all five x86 targets are
separate from original unbound Go/emitter formats and native execution. The
required Linux scalar runtime checks rounding, passthrough, masking and MXCSR;
the existing native-wide conformance retains packed SQRT. FP16 remains a
distinct raw-only family, with no inherited caller or entry permission.

The four packed multiply-add names share the existing complete binary grammar
with mandatory numerical inputs, result definedness and paired native reads.
MMX keeps its separate closed physical-state owner. Every first/second input,
mask and merging destination stays required even for Void or an unused bool.
Zero masking removes only the merge dependency; it supplies no data/address
permission. Reuse encoding-aware writeback and preserve unrelated GP, FLAGS,
DF, masks and storage facts. Keep original unbound sources as actual-Go and
public-Context format controls alongside complete initialized public objects;
raw objects, caller proofs and native execution remain independent claims.

The eight immediate shuffles share their integer-only source grammar and exact
byte selectors with lowering, caller definedness and memory shapes. Bind the
complete legacy and VEX/EVEX rows independently, including signed MMX Yi8,
unsigned legacy X Yu8, mode32 int32 source classification and raw imm8 signed
rendering. Float/unresolved operands fail before every consumer. Legacy X
writes preserve upper aliases; VEX/EVEX clears them. E4NF reads retain the full
tuple even with dead results or zero masks; dword broadcast reads m32.
Legacy m128 retains the original observable SSE2 memory opcode, not an align-1
replacement. Virtual FP/SP/BP and unbound address-size roles remain Context,
as does caller alignment without a real witness. Execute independent original
Go opcode bytes and LLVM live/dead boundary controls. Label IR-prepass axes
separately from backend optimization; MMX objects and Rosetta diagnostics do
not certify physical x87/MMX state or native AVX512 execution.
Go 1.20's maskless `.Z` acceptance is a historical encoder defect, not another
legal format. Observe its exact reserved EVEX.z/aaa=0 bytes and still require
both named and raw rejection through all APIs; current Go must reject source.

PSHUFB/VPSHUFB use the shared binary grammar without MMX, broadcast or SAE.
Dynamic control bytes depend on every potentially selected byte in their own
128-bit data lane; sparse caller/result knowledge must retain that dependency.
Legacy memory keeps the original m128 opcode and alignment, while vector E4NF
reads retain the complete tuple even with zero masks or dead outputs. VEX/EVEX
clears wider aliases and both raw encodings are WIG; Go's W0 emission and named
386 operand cap do not restrict a validated physical encoding. Feature inference
must recognize isolated `.Z`, not borrow SSSE3 from a sibling function. Keep the
bounded raw-literal proof separate from ordinary native reads. See Intel's
[PSHUFB instruction reference](https://cdrdv2-public.intel.com/789581/325383-sdm-vol-2abcd.pdf)
and [E4NF exception tables](https://cdrdv2-public.intel.com/858446/253666-088-sdm-vol-2a.pdf).

The main instruction dispatcher and legacy vector entry must both delegate to
that same complete byte-shuffle lowerer, including handled errors before IR.
Keep direct-dispatch tests as well as public API tests when extracting a family;
an old helper entry cannot silently fall through after its switch body moves.

The private x86 raw decoder hands off actual physical memory operands without
reinterpreting formatter DS/ES/FS/GS or RIP spellings as public Go source
register groups. Only actual `PrefixIgnored` metadata permits removing a
printed segment prefix; an unused, nonignored physical prefix remains Context
before IR. Environment-load aliases additionally bind the complete decoded
encoding and 32-bit layout. Sixteen-bit environments remain unsupported.
Environment and packed-BCD consumers preserve the pointer's address space
through every load, store and GEP. These conversions confer no new caller,
native-memory, extent, raw-return or source-syntax permissions.

Raw x86 NOP's ModRM/SIB, segment and PC-relative fields encode length, not a
memory access. Validate the complete instruction and prefixes before consuming
it as an operand-free NOP, retaining its original length for CFG boundaries.
The pinned decoder's missing REX.W 0F 1F /0 row has a narrowly scoped width
adapter; it cannot rewrite another opcode, reserved extension or invalid
prefix. Keep real-memory handoff failures and XCHG/PAUSE effects unchanged.
Go NOPW/NOPL rows, original literal bytes, five-target objects and portable LLVM
state tests are distinct from required native Linux AMD64/386 execution.
Rosetta rejects some valid register NOPs and cannot certify that native axis.
The lowering-only result observer may compose this sealed operand-free NOP
handoff with independently paired named native reads. Check both original and
normalized NOP identity; another raw opcode, native TEXT, return, address-size,
source-stack or fixed-local role keeps its original boundary. Inert padding
does not grant caller memory or a standalone declaration-query permission.
Current-Go PCALIGN source is a separate producer fixture; the complete literal
NOP/read matrix still runs on the historical SDK, which lacks that directive.

ENDBR32/64 preserve numerical registers, FLAGS, DF/ID and private storage,
but update CET tracking. Keep their actual side-effecting native instructions,
never replace them with NOPs. Share only source-state preservation, requiring
exact raw origin/opcode/operand identity; ENDBR32 remains raw-only. This creates
no memory, missing-input, ABI frame or raw-return permission. Retain complete
current-Go encoder rows, both physical encodings, five-target public objects,
private-stack checks and the original native GP/FLAGS runtime owner.
See Intel's [CET specification](https://cdrdv2-public.intel.com/874239/252046-082-sdm-change-document.pdf).

Scalar ADD/SUB/ADC/SBB native memory-to-register reads reuse the existing
complete B/W/L/Q grammar for widths, carry and physical REX byte aliases. The
paired lowerer must retain an exact volatile load even for dead data/FLAGS;
the lowering-only result consumer additionally requires the old destination
bytes and ADC/SBB's incoming CF. Continued execution does not prove pointer
validity, extent or alignment. Native writes, unknown or numerical addresses,
pointer-as-data, physical SP/BP aliases, raw entries and standalone declaration
queries keep their separate contracts. Execute live/dead, carry/borrow, width,
status, alias and guard-page controls against actual original Go bytes; portable
objects and Rosetta execution do not replace the required native Linux owner.

Static scalar RMWs share that numerical grammar but require the actual
same-module DATA directory, complete access extent and writable destination.
Readonly address targets are not mutable sinks. Non-shared 386 TYPE_ADDR
arithmetic consumes a bound relocation value, not a pointee load or pointer
permission. Missing symbols, CF, result bytes and readonly/short sinks remain
Context. Keep original unbound formats separate from initialized DATA objects.

Named FS/GS scalar and bit-string RMWs share Go's existing segment normalization.
The segment supplies its hardware base; each explicit GP offset needs complete
numerical bytes. Ordinary addresses retain their incoming-pointer rule.
Exact volatile accesses or the native LOCK opcode remain observable, including
dead results; continuation creates no memory, TLS or future-read facts.
Standalone observers cannot borrow this paired rule. Retain all family widths,
bare/indexed Go bytes, five-target native objects and missing-input controls;
object compilation does not qualify native segment execution.

The scalar native MOV-store family checks its complete inputs even for Void
or unused-bool signatures. A separate lowering-only bit-copy scope permits a
whole native word of actual typed entry-derived address bits in an ordinary
zero-frame leaf without calls, raw entry or another storage owner. It grants
no NUM bytes, pointee validity, bounds, GC root, escape-safety or pointer result.
String cursor updates retain only their existing weaker address-bit facts;
they revoke the reusable native-read pointer. Keep the complete original
cursor-comparison sources plus independent positive zero-count and negative
updated-cursor native read/store controls. The standalone store observer cannot
borrow this source scope or manufacture it from a pointer type alone.

An x86 raw-return caller-region producer is a separate, bounded source proof,
not a pointer-type or `noescape` nonalias promise. It requires the same actual
selected Go/ASM inventory, typed syntax, actual numerical/pointer sizes and
source bytes, closes every use of
an unexported bodyless ABI0 entry, and accepts only direct slice-data inputs
and independent numerical result/length locals. Missing sources, indirect or
assembly callers, linknames and local-address escape remain Context. A region
witness alone never admits raw RET: the complete source stack/CFG/effect proof
must separately consume the exact slots and write envelope. Compiler loaders
must supply the actual complete selection; an AST subset or self-reported hash
is not authenticated package-selection evidence.

The bounded AMD64 caller-region consumer covers scalar MOVB/W/L/Q and the
Go-table MOVSS/SD, VMOVSS/SD and KMOVB/W/D/Q move forms. It tracks exact
full-word pointer imports/copies, constant affine offsets and numerically
initialized GP/SIMD bytes. Mask values must be source-defined, not pointer bits;
legacy lane preservation and VEX/EVEX merge/zero rules remain distinct.
Floating literals follow the actual Go frontend rewrite: original positive
zero in X0-X15 becomes legacy XORPS, preserving wider aliases; negative zero,
float32 rounding/underflow and high-register constants follow their pool-memory
encoding. Integer/unresolved literals and invalid mask/merge forms remain
rejected. Legacy scalar ADDSS/ADDSD/SUBSS/SUBSD and MULSS/MULSD/DIVSS/DIVSD
use their own finite FLOAT constant-pool rewrite, including both signs of zero;
they do not inherit MOV's positive-zero XORPS rewrite. Their FLOAT leaf may
have unary signs and parentheses, but not integer or binary-expression source
syntax. The destination's low scalar bytes must already be numerically defined.
Raw FP16, packed moves and arithmetic need separate complete effect
families and do not inherit this permission.
Inputs and local lengths are read-only;
only the independently fresh scalar result has a bounded write envelope.
Instruction-local memory certificates bind the entire operands, direction and
native width. Every source return must still restore SP/BP, and unknown joins,
private-stack escape, g-register use, unregistered vector/native effects and stale source or
signature metadata remain Context. Rosetta fixture execution is diagnostic,
not evidence that an external AVX/AVX512 library ran on native AMD64 hardware.

The existing <=3, zero-based +1 residue-loop rule composes only across separately
proved reducible SCCs: one entry, one exact adjacent comparison/latch, no early
exit, and a DAG after removing that latch's backedge. Each feasible path retains
its own complete source origins, initialized bytes and numerical versions across
SCCs. The original shared finite replay budget and independent final replay stay
unchanged; this does not prove dynamic affine, sentinel or nested loops and never
uses an acyclic hull join to manufacture a cyclic invariant or allocation bounds.
MOVQ's named MOVD/MOVDQ2Q aliases retain those same numerical origins,
versions and complete zero-based partitions through local source-only dispatch.
Raw physical opcodes never inherit that alias registration. Fixed-local scalar
constant/boolean knowledge, memory-width observations and carry initialization
likewise retain MOVQ's exact width without rewriting original source identity.
The required Linux AMD64 source-alias counted-provenance runtime compares
original Go and independent LLVM O0/O2 values, immutable lengths and full
input/output canaries; no new loop, g or native-entry class is admitted.

A scalar GP MOV to static storage needs actual module-owned writable DATA/GLOBL
extent and every selected input byte. This is mandatory even for an isolated
Void function; an unrelated result instruction must not accidentally supply
the input check. Floating, pointer, physical SP/BP and unresolved external
inputs cannot become numerical store bytes. Reuse the native-width volatile
emitter and Go's real immediate encoding normalization, including signed imm32
extension for wide MOV aliases; do not grant storage from an address alone.

Signed packed dword-to-float conversion uses one validated whole native
CVTDQ2PS/PD opcode, retaining ambient MXCSR rounding, precision, trapping,
masking and embedded rounding. The same native emitter serves the complete
38-name FP32/FP64-to-signed/unsigned I32/I64 and remaining integer-to-float
family. Shared typed shapes distinguish physical vector width, active lane
count, memory tuple and architectural zero padding. Named, raw, result and
caller effects consume that grammar; narrowing broadcast counts active lanes,
not destination carrier lanes. VEX.WIG remains ignored in both x86 modes.
Pure `fptosi`/rounding IR is not equivalent: it loses MXCSR exceptions and
out-of-range inputs become poison. Keep each whole conversion `sideeffect`
even when its numerical result is dead. Its caller effects require every potential
input byte and merge byte; masks do not authorize a missing memory envelope.
Packed FP fields and virtual SP/BP lack original native backing and remain
Context without a separate source-bound storage proof. Mode32 high banks
likewise cannot borrow a software register view.
Go's MMX-to-X forms (including GP spellings admitted to Ymm) and X-to-MMX
destinations remain Context:
no current producer closes physical MMX identity, x87 Tag/TOS, pending
exceptions and observations by the caller after RET. They are Go-object and
format coverage, not successful LLVM objects. The native Linux AMD64 fault
oracle is a required cross-runtime root; SSE numerical Rosetta observations
and five-target AVX512 object compilation do not replace it or AVX512 execution.
Keep independent complete Go table/attribute witnesses and byte-exact raw
parity. Runtime axes include clean and preset status, NaN/overflow, RC,
DAZ/FTZ, masks, alias canaries, integer FLAGS, dead memory and unmasked native
traps. Partition full-family objects and executable fixtures into disjoint
batches of at most 96 functions; check the union and release each LLVM module
and context before the next batch. Each batch owns its temporary artifacts
through a synchronous subtest. Primary references are
[Intel SDM Vol. 2A](https://cdrdv2-public.intel.com/812383/253666-sdm-vol-2a.pdf)
(conversion instruction pages and exception classes) and the
[LLVM 22 LangRef](https://releases.llvm.org/22.1.0/docs/LangRef.html)
(`fptosi` poison and inline-assembly constraints), not software-value parity alone.

Scalar FP-to-GP conversions likewise retain their complete typed native opcode
and MXCSR effect. A paired native-read consumer must check all preceding inputs,
even if the scalar result is dead. Raw continuations bind complete immutable
producer replay, encoded operands, architecture and physical EVEX generation
before any strict fast path. The transfer writes only the real GP destination;
it cannot erase unrelated DF/ID, private storage or caller-address identities.
Private format objects and initialized public companions are separate evidence
from the unchanged original native programs.

The AMD64 fixed-local observer consumes those same two typed conversion
grammars for all 42 names, not another mnemonic list. Its complete original
Go frame binding may supply only initialized private memory: retain the exact
source tuple, legacy m128 alignment, active merge bytes, narrowing zero padding
and legacy versus VEX/EVEX wider aliases. A zero mask cannot excuse missing
storage. Unbound FP/SP/BP, physical MMX, caller pointers and source escapes keep
their existing failures; this adds neither a loop nor a floating ABI contract.
The actual-object boundary observer separately measures complete VEX/EVEX
conversion encodings, including physical RIP operands. It discards operands
and supplies no raw-source or scalar-read permission. Keep default raw RIP
rejection, every truncation and reserved-field controls. Native Linux execution
owns the full conversion family; original-Go/LLVM SSE value, MXCSR and private
canary comparisons on Rosetta remain explicitly narrower evidence.

All eight scalar COMI/UCOMI names share Go's twelve complete encoder rows,
read-only scalar input widths and native MXCSR/FLAGS effects. A pure LLVM
relation loses signaling-NaN distinctions and dead exceptions. Preserve the
actual EVEX generation, including low-register raw encodings, and register-only
SAE; no masks, broadcast or vector writes follow. Source-accepted mode32 high
registers lack a physical binding and remain Context. A matching explicit x86
target is required, even for dead source. SSE original-Go/state/guard-page
oracles do not stand in for required Linux AMD64 native VEX/EVEX, wide-register
preservation and unmasked IE/DE/SAE execution. Object and runtime reports retain
those different scopes; typed byte effects grant no new memory ownership.
The paired COMI/UCOMI native read uses the same exact scalar width and existing
incoming-pointer identity as lowering. Its continuation defines only status
FLAGS, never DF/ID, vector writes, memory backing or future read facts. Keep
declaration-only observers strict and retain both initialized public objects
and original uninitialized-format Context/emitter checks. Returning all FLAGS
requires independent DF/ID inputs; a six-status projection cannot create them.
VEX WIG and EVEX LLIG do not imply portable VEX.L=1 behavior: Intel's SDM
warns of generation-dependent behavior for that encoding. Keep literal L1
Context rather than silently emitting L0. Validate all operand/file syntax
before returning a deferred physical-mode or memory-role Context.

COMI input proof is mandatory for isolated Void instructions as well. The
four vector names' twelve raw RIP forms use only the existing decoder-owned
literal consumer: exact decoded relocation, complete DATA extent/payload,
immutable whole-function replay and original raw RET binding. They still need
every scalar register byte. Ordinary raw native-pointer reads, legacy forms,
mode32 literals and SAE memory do not inherit this literal role.

The CLI captures a private inventory at its actual package-load boundary and
rechecks complete compiled Go sources with that load's dependency types and
target sizes only for raw-return candidates. All selected assembly and CPP
inputs are included, with source/expansion checks through the final object.
Effective overlays, generated/cgo mappings and external package drivers require
their actual compiled-source mapping; original files cannot impersonate them.
This private load snapshot cannot be restored from JSON or supplied by an old
standalone `compileOne` caller. Candidate detection is only a cost predicate.

ARM32's specialized raw-data lowerers and NZCV source proof share one typed
registration. Only those decoded data forms preserve source-defined APSR
flags; conditional forms still require their predicate on every CFG path.
Their GP outputs conservatively kill source-value witnesses, including memory
writeback. Unknown WORDs, calls and unproved FPSCR-to-APSR transfers do not
retain flags. Check every registered family and condition against LLVM-MC,
Go objects and the required ARM Go-WORD/LLVM four-flag execution oracle.

For a newly discovered instruction, update all four layers before calling it
complete: the family-specific lowerer, positive/negative Go-table form tests,
LLVM 22 object compilation for every affected supported architecture, and the
architecture's supported-op extraction test in `cmd/plan9asmll/main_test.go`.
The external corpus uses that extraction result in its diagnostics, so omitting
the last layer can make a supported instruction look unsupported.

ARM64 named system registers share the raw encoding grammar. Regenerate their
encoding/access metadata with current Go using `go generate arm64_sysregs.go`;
do not edit `arm64_sysregs_generated.go` manually. The completeness regression
compares the full current Go table and checks every readable register against
LLVM 22. Use physical system-register names to avoid feature-gated LLVM aliases,
never fabricated constants for CPU-ID reads. Keep text/direct-module/CFG/raw
paths observable and require the Linux MRS runtime oracle: only the kernel's
HWCAP_CPUID-advertised ID-register space is safe for unprivileged execution.

The seven ARM64 scalar GP memory moves share `parseARM64ScalarMemoryForm`:
signed/unsigned widths, direct/indexed addressing, pre/post writeback, AUTO/FP
and SB roles. Go's long-offset expansion reads the old effective address,
materializes R27, then reads the possibly aliased transfer register. Lowering,
caller-link/code provenance, private-frame bounds, availability and raw-PC width
must consume that same ordered model. Only actual WORD decoding supplies a
physical-instruction identity. AUTO/FP classes require the complete source TEXT;
LLVM shadow slots are not native SP or linked-page identity. Differing old/new
Go encoders require source context when their scratch value is observed, never
a guess from the translator's build version. Preserve the independent Go-table,
byte/state, initialized numerical/canary and complete target-object tests in
`arm64_scalar_memory_*_test.go`.

Isolated ARM64 coverage probes parse their own explicit zero-frame NOFRAME
TEXT fixture and retain a real faulting exit. This validates concrete AUTO
forms without borrowing the original function's frame or encoder identity.
Foreign TEXT, unbound FP, unresolved offsets and unsafe continuations remain
rejected; a compile-only probe is never executable semantic coverage.

Compiler/executable/emulator subprocesses in native root oracles should use
`runtimeOracleCombinedOutput` with their actual `CommandContext` and deadline.
The helper retains output and failures, bounds pipe waits and cleans its owned
Unix process group after cancellation or ordinary parent exit. Non-Unix owns
only the direct child. Extend the lifecycle AST regression when adding a new
consumer; do not introduce another direct `CombinedOutput` call that bypasses
the helper. The reusable LLVM compile, C link and executable-run stages each
receive a fresh five-minute budget, limited by the existing test deadline minus
three seconds for cleanup; this is not a five-minute whole-suite budget. An
exhausted budget fails without launching another command. Release LLVM modules
before their contexts and before each fixture's temporary files are removed.
Generated C oracles must keep case IDs in diagnostics, never in process exit
codes: Unix truncates 256 to success. Use fixed nonzero failure status and
wrong-result mutation tests. Bound large fixture batches, check their complete
disjoint union, and prevent optimization from recreating one giant C function.

A typical x86 investigation starts with the Go 1.27 tables and an assembler
probe:

```sh
goroot=$(go env GOROOT)
rg -n 'A?VADDPS|yvaddps' "$goroot/src/cmd/internal/obj/x86"
sed -n '<start>,<end>p' "$goroot/src/cmd/internal/obj/x86/avx_optabs.go"
GOOS=linux GOARCH=amd64 go tool asm -o _out/form.o _out/form_amd64.s
GOOS=linux GOARCH=386 go tool asm -o _out/form.o _out/form_386.s
```

Record the initial failure in test output before adding the lowering. Focused
form tests normally belong in `amd64_ecosystem_test.go`,
`amd64_operand_forms_test.go`, or the corresponding ARM file. Add the opcode to
`TestExtractSupportedOpsFindsCompleteAddedInstructionFamilies` so external
corpus diagnostics recognize it. Semantic fixtures live under
`testdata/conformance/<arch>` and must be checked against both native Go and the
LLVM runtime oracle where supported.

Raw x86 far/interrupt returns must select the existing `IRETW/L/Q` and
`RETFW/L/Q` grammar from the decoder's actual mode and operand size. A bare
`CB` remains a 32-bit far return even in amd64 mode; widthless `LRET` is not
a source-level Go opcode or evidence for a 64-bit return. Preserve encoded
imm16 operands, reject unregistered prefixes, and compare original Go and
LLVM object bytes for all five supported x86 targets. Those object checks
do not prove a privileged kernel's far-return stack or runtime behavior.

Named x86 addresses retain the pseudo-base role separately from subsequent
physical register groups: `slot(FP)(SI*1)` supplies an index, while
`slot(FP)(SI)` supplies Reg, which Go rejects on amd64 and ignores on 386.
Scale spellings are Go's single decimal tokens 1/2/4/8, not arbitrary constant
expressions. A parsed indexed FP/AUTO operand does not establish a contiguous
frame, dynamic bounds, or address provenance and remains Context without those
contracts. Ordinary amd64 SB memory cannot combine RIP with a base/index.
For 386 SB memory/LEA, Reg is ignored but Index is used; a non-shared relocated
SB address immediate ignores both. Keep these effects and the decoder's
physical SP operands distinct. Alternate pseudo-role overwrite forms remain
explicit Context rather than being misclassified as Go-rejected syntax.
The complete Go x86 register-name inventory is checked before discarding
unused 386 SB annotations; this never grants a segment/SIMD register input.
TLS memory progedit and segment Index operands remain Context without their
native address/source-encoder contracts. In particular TYPE_ADDR segment Index
prefixes differ in the actual Go 1.20 and 1.27 encoders; no build-version guess
selects their meaning.
`CaptureGoX86TLSMoveSource` independently assembles the complete original and
expanded source with its actual Go tool, OS, architecture and shared flag.
It binds every TEXT body, ordered relocation, frame/argument header and original
source position. `BindTLSMoves` consumes only observed zero-width NOP rewrites
of MOVL/MOVQ and its MOVD/MOVDQ2Q source aliases' TLS-to-GP rows, including
Go's complete pre-encoding AX..R15 range on 386. Such a NOP preserves both
initialized and unknown destination bytes; the complete existing source/result
proof still runs before lowering.
The source observer supplies no package selection, signature, native frame,
thread, TLS address or g identity. ELF LE/IE relocations, Windows/Android runtime
offsets, Plan 9 private storage and actual TLS memory remain Context without
their native entry/thread/storage producer. Keep live before/after source,
object, target and callback guards, and the required native Linux AMD64
`TestCrossLinuxRuntimeMatrixX86TLSNoopPreservesWideGP` execution counterpart.
Grouped SB CALL/JMP/RET operands have Go's TYPE_BRANCH role, not a native
indexed read; they remain Context without a bound branch/entry contract.

Unnamed x86 source register groups preserve a missing second-group scale as
zero. This is distinct from an explicit invalid multiplier token. MOVL/Q
address sources become LEAL/Q in Go's progedit before operand classification;
those derived LEAs and ordinary physical memory must reject unencodable SIB
indexes/scales. Audited TYPE_CONST rows instead ignore Reg/Index annotations.
Do not apply the ordinary SIB guard to named, segment/TLS, branch or decoded
physical roles, or let source normalization repair an original CFG certificate.
Unnamed address-immediate register groups retain the source `g` spelling until
the actual source mode is known. Go registers this alias only for amd64; 386
still accepts explicit `R14` annotations that its TYPE_CONST rows ignore.
Qualifying the alias grants neither a register input nor a native address.
For a stack-unobserving raw near-RET leaf, MOVL/Q's numerical LEA adapter
rechecks both complete source views and their return/memory constraints. It
cannot inherit stack, caller, fixed-local, raw-text or another instruction's
decoder certificates. TYPE_CONST arithmetic is a separate rule and remains
Context in that protected domain. Neither adapter grants pointer provenance.

The main implementation entry points are:

- x86/386/amd64: `amd64_blocks.go`, `amd64_needed.go`, `amd64_translate.go`,
  then the family-specific `amd64_lower_*.go` file;
- ARM: `arm_blocks.go`, `arm_needed.go`, `arm_translate_cfg.go`, then
  `arm_lower_*.go` and frame/register handling in `arm_eval.go`;
- ARM64: `arm64_translate.go`, `arm64_eval.go`, and `arm64_lower_*.go`;
- wasm: opcode families in `wasm_ops.go`, lowering in `wasm_translate.go`, and
  intrinsic declarations in `translate_prelude.go`;
- command-side package signature, ABI, include, and target handling:
  `cmd/plan9asmll/main.go` with tests in its nested module.

Supported-opcode reporting scans opcode-keyed package maps as well as explicit
switches. Every newly introduced opcode map must have an architecture-specific
extraction regression in `cmd/plan9asmll/main_test.go`; otherwise a real
translator failure can be misreported as an unknown instruction.

For x86 form tests, cover at least these targets:

- `darwin/amd64` — `x86_64-apple-darwin`
- `linux/amd64` — `x86_64-unknown-linux-gnu`
- `windows/amd64` — `x86_64-pc-windows-msvc`
- `linux/386` — `i386-unknown-linux-gnu`
- `windows/386` — `i686-pc-windows-msvc`

Do not add an `unsupported_forms` skip for a supported target. Context-dependent
forms may be classified separately only when translation genuinely requires
information unavailable to the scanner.

For named ARM64 private data tables, the explicit typed-call transport and
fresh-frame proof may authorize bounded indexed accesses and counted-loop
writeback. Track numeric bounds separately from may-frame provenance: joins,
stale comparisons, unknown transforms and hardware-masked shift counts must
never restore an erased address or narrow an unknown index incorrectly.
Certify each store's complete byte envelope within private DATA `[8, frame+8)`;
the saved caller link at SP+0 and overlapping cells remain protected. This is
an instruction-local certificate, not a function-wide unknown-store exemption.
Reject address escape through calls, results, FP, memory or vector banks, raw
effects, mixed origins and exhausted proof budgets. Exercise the shared scalar
and GP/FP pair grammar with Go-accepted widths, signed loads, zero aliases,
indexed and offset/pre/post forms, LLVM objects and initialized runtime
canaries. An old fixture with undefined data establishes only its explicit
object contract; never report it as successful runtime coverage.

For ARM64 GP data-processing proof, use the lowerer's typed operand grammar:
explicit Rd is a full overwrite, but two-operand arithmetic/shift forms and
BFI/BFXIL read it. W results clear the upper GP half; extracts and extensions
still consume their actual source. Unknown, aliased or joined frame inputs
cannot be washed away. Preserve transformed code-address taint and require
independent exact LR/SP/BP/g/OS-register restoration, even for typed void
returns. Go optab rows do not automatically establish frontend spellings:
single-operand NEG is rejected by stock Go, and a cross-bank W bitfield
accepted by its alias encoder is not an overwrite proof.

Scalar GP moves likewise distinguish their source from the write-only Rd.
Narrow register copies retain derived code-address bits; resolved MOVW/MOVD
literals and the seven literal-zero aliases do not read old Rd. MOVK remains
read-modify-write. Go's inherited nonzero MOVWU literal rows can emit zero
machine words; stock syntax acceptance alone grants no overwrite witness.

For ARM64 immediate arithmetic, logical and compare forms, follow the complete
Go constant classes (including MBCON), register classes and reserved row size.
R27 may be written before an aliased source is read; direct/split forms need
not write it. Raw decoded instructions must not acquire source-pseudo effects.
Go-accepted fixed-width expansion can contain a reachable UDF, and different
Go encoders can produce non-equivalent fallthrough. Preserve exact byte/fault
oracles and require source-encoder Context when that identity is unavailable.

The bounded raw zero-frame proof may also produce the local-control plan,
but only after every original and exact normalized source context passes.
Different helper invocations retain separate incoming/private pointer states;
their return labels are combined only after exact SP/LR/fixed-register and
escape checks. No partial certificate survives a failed component, unknown
effect or exhausted bound. Ordinary/native/unproved functions keep the coarse
control analysis. Runtime fixtures must execute both helper pointer contexts,
not just compile a synthetic return dispatcher.

An authenticated current-PC raw BL in a single-instruction block is a terminal
sink: LLVM still writes its continuation to LR and branches to itself. The
source proof checks all preceding effects, joins and other returns, and emits
no return certificate for the sink. Ordinary recursion, multi-instruction
helpers and actual dead source retain the existing bounds and guards; only an
empty block-splitter continuation after a final self BL has no source to check.
Floating immediates never acquire an integer GP MOV overwrite witness, including
through the legacy MOVD transfer fallback.
The seven scalar GP MOV lowerers also reject Go's distinct floating-constant
class before register, memory, symbol or writeback dispatch; FMOV is unchanged.

An ARM64 ABI0 native-width read may overlap the alignment gap after the final
direct narrow integer parameter only with a complete actual typed declaration
and independent original/normalized whole-source bit-use proofs. Every use of
the unspecified bits must remain unobservable across GP and SIMD aliases, CFG
joins, comparisons, addresses, stores and results. The bounded first contract
is call-free and rejects unknown effects. A proved read may choose an explicit
representative for those dead bits; it does not assert that native padding was
initialized, create a padding slot, or authorize any address or write. Preserve
the source MOV width, encoder scratch effects and PC identity. Manual sparse
frames and changed type layouts retain their original missing-slot failure.

A native-width store beyond a narrow declared result is different: its tail
bytes are observable by an assembly caller after RET. A callee declaration,
call-free body, or typed numerical oracle cannot authorize discarding them.
Dropping that caller with `KeepFunc` does not close the original boundary;
code-address and DATA references likewise grant no typed-entry permission.
Keep the missing-slot failure until a real caller/backing contract closes the
complete native effect. Check the independent nine-width native observer and
all three translation APIs when changing this boundary.

`TestARM64ABI0ResultTailCompilerCallerObservation` independently compiles an
ordinary Go caller and its ABI wrapper with the original eight-byte ASM store.
Both SDKs allocate outgoing storage but read only the declared uint32 result.
This observation is not proof that every caller ignores the tail: the separate
nine-width ASM observer reads it, and the current SDK's atomic entry has public
linkname and cross-package ASM tail-call roles. Run the current-source audit as
well as the cross-SDK fixtures. ABI0's rounded allocation size is not a writable
FrameSlot and must not erase the missing native caller/backing contract.

The framed raw-leaf proof registers PC-relative WORD branches through the same
exact source-boundary checker as translation. It independently checks both
original and normalized CFGs, including dead components; named normalized
edges must not reclassify skipped executable WORDs as anonymous data. Unknown
widths, native address/data islands, calls, escapes and unbalanced/fixed-register
returns remain rejected. This CFG registration supplies neither a callee ABI
nor permission to clobber Go's reserved R18/g entry identities.

The x/arch decoder corpus is not a Go-accepted instruction list. Its
`MOVHU.P 107(R13), R13` and `MOVHU.W 192(R2), R2` encodings violate Go's
base/data writeback-overlap check. The mixed MOVHU decoder form is therefore
unsupported, not a missing valid Go format. The independent
`TestARM64DecoderWritebackOverlapRejectedLikeGo` regression checks both
assemblers' rejection; `check-arm64-plan9-corpus.sh` separately requires every
Go-accepted selected-family case to remain lowerable.

The decoder also prints reserved ADD/SUB extended-register shifts of five to
seven. `TestARM64DecoderExtendedShiftBoundariesMatchGo` checks every W/X and
flags alias, all eight extensions and shifts zero through seven against the
actual invoked Go assembler, including the older compatibility toolchain.
Only shifts zero through four are accepted. Native register CALL/JMP forms
retain function-context classification: a decoder entry supplies neither a
callee ABI nor its native frame, continuation and result transport.

## Semantic and raw-encoding checks

All fourteen scalar sign/zero-extension moves retain their shared Go grammar
and native source width, including word-to-word aliases and mode32 MOVLQZX.
Ordinary native and certified caller/frame reads use exact-width volatile loads,
even with a dead result. The lowering-only result observer may consume a known
incoming pointer plus initialized numerical index if the paired load continues;
it asserts no backing, bounds, alignment or reusable memory authority. W preserves
unknown high bytes, L clears the upper half and all forms preserve FLAGS. Public
declaration/raw-return proofs stay independent. Keep actual Go encoder attributes,
all-five-target objects and original-byte/LLVM numerical and fault oracles paired.
See [LLVM 22 volatile accesses](https://releases.llvm.org/22.1.0/docs/LangRef.html#volatile-memory-accesses);
volatile access does not establish validity for a later nonvolatile read.

Ordinary register-addressed native MOVB/W/L/Q and Go's qword MOVD alias use one
typed load row for lowering and the private result observer. Exact-width
volatile reads retain dead faults; B/W preserve other bytes and L clears the
upper half. Continuing the paired load establishes only numerical result bytes,
not pointee, caller, frame or raw-entry authority. Keep the complete Go MOV
tables separate from the MMX/X, system, immediate, static-symbol, FP/AUTO and
store consumers.

The ordinary register-to-native MOV store rows locally reverse that same typed
GP grammar, including qword aliases and actual REX byte views. Keep native
stores exact, unaligned and volatile even when their results are dead. A paired
NUM continuation needs the strict incoming-pointer base and numerical index;
it changes no logical storage/GP/FLAGS facts and grants no reusable memory,
pointer-data/GC, caller, raw or frame permission. The complete native BIT
continuation likewise consumes its shared grammar and exact volatile read/write
emitter, defines CF and revokes only the ISA's undefined flags. Adjacent popped
word masking retains only actual known bits, never virtual slot padding. Other
instructions revoke that transient observation; joins intersect it and its
logical bytes count toward the unchanged source-flow budget.
Actual REX changes AH/CH/DH/BH ModRM spellings to SP/BP/SI/DI low bytes;
register allocation and effects must agree with Go's bytes. An implicit
physical SP/BP write remains Context without its native contract.

BEXTR and BZHI share Go's complete `_ybextrl` operand grammar, not their
control bytes or status effects. BEXTR consumes START/LEN; BZHI consumes only
the index's low byte and defines CF/OF/ZF/SF while killing AF/PF knowledge.
The Q spelling remains intact in mode32, where VEX.W is ignored and the
physical operand/read width is 32 bits. Use the common typed descriptor for
lowering, memory shape and numerical inputs. Void and unused-bool entries
still require those inputs; exact volatile paired reads survive zero controls
and dead results without granting reusable pointer/caller authority. Retain
original Go rows/bytes, public Context controls, initialized five-target
objects and independent full-control/alias/FLAGS/fault execution. See
[Intel SDM, BZHI, Vol. 2A §3-138](https://cdrdv2-public.intel.com/825743/325462-sdm-vol-1-2abcd-3abcd-4.pdf).

Packed low-product W/D/Q multiplication consumes the shared binary grammar;
W retains the word family's separate MMX bank. D/Q shape, lowering, caller
effects, memory tuples and result definedness must agree. Legacy PMULLD m128
keeps its observable SSE4.1 opcode and original alignment; virtual FP/SP/BP
storage cannot supply native backing. VEX/EVEX writes clear wider aliases,
and E4 masks suppress inactive source reads without shrinking the independently
proved possible caller envelope. Numerical FP/AUTO observations alone grant
no native memory permission. Preserve unknown inputs, merge bytes and masks.
VEX.WIG never selects a qword product; only EVEX.W does. Physical low-bank
mode32 EVEX masking is distinct from Go's named three-operand limit, and high
banks remain unbound. Keep complete Go rows/attributes, raw-byte parity,
five-target three-API objects and independent all-byte/mask/FLAGS execution.
Portable LLVM execution, including Rosetta, is not original AVX512 execution.
See Intel SDM Vol. 2B, PMULLD/PMULLQ and E4 exception class:
[instruction reference](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-2b-manual.pdf).

Packed integer add/subtract result analysis consumes every Go VEX/EVEX form,
including signed/unsigned saturation. Reuse the lowerer's typed operation and
lane widths, not a separate mnemonic allowlist. A numerical lane requires all
input-lane bytes; merging also requires its old destination bytes. Unknown masks,
native memory and mode32 physical banks do not gain authority. Complete add
lowering shares one grammar and read path: retain legacy native m128 alignment,
conditional volatile E4 reads even for dead results, and coherent VEX/EVEX
upper-zeroing. Keep caller permissions separate from that numerical observer.
Check complete Go encoder attributes, sparse byte holes, all aliases, flags,
mask/fault behavior and five-target three-API objects independently.

The nine scalar POPCNT/LZCNT/TZCNT W/L/Q forms share one Go-table grammar,
lowerer and typed byte-effect descriptor. Inputs are read before destination
overwrite; W preserves upper GP bytes and L zero-extends in mode64. POPCNT
defines all six status flags, whereas LZCNT/TZCNT define only CF/ZF and kill
knowledge of the others. Numerical result/caller consumers must check source
bytes independently; a count cannot turn an opaque pointer, unbound native
read or unknown AUTO byte into numerical knowledge. BSF/BSR's zero-input
undefined result and packed counts remain separate families. Keep complete
Go encoder-row checks, original accept/reject witnesses, result/flag negatives,
five-target objects and runtime regressions together when changing the model.

The six packed byte/floating move-mask names share their complete legacy/VEX
register grammar across lowering, intrinsic feature inference and result
definedness. Legacy mode32 X8-X15 is Go-rejected; VEX syntax acceptance does
not grant that physical bank to the result observer. Initialized X/Y bytes
produce a zero-extended GP mask without changing vector aliases or FLAGS.
Unknown/partial inputs and unbound MMX state remain Context. Test each
function's own LLVM feature requirements: a sibling PMOVMSKB must not supply
the SSE2 feature needed by an isolated VPMOVMSKB intrinsic on 386.

ARM64 RNDR/RNDRRS reads share the complete MRS/MOVD C_SPR-to-C_ZREG grammar
and raw Rt/reseed decoder. Named aliases must infer the same `+rand` feature
and define the same four virtual NZCV bits as WORD, including ZR/dead reads.
The LLVM intrinsic is side-effecting; never replace it with an untracked MRS.
Physical platform/g writes remain unbound at typed entries. Required Linux
tests execute original Go and all four LLVM consumers/optimization axes, using
independent allowed-value/status invariants rather than comparing random values
from different executions. Report observed failures honestly: no natural failure
is not a tested forced-failure path. Complete syntax/object coverage of reserved
register banks is separate from an executable caller-entry contract.

ARM64 scalar FADD/FSUB/FMUL/FNMUL/FDIV share the complete two-row Go
case-54 grammar and the raw H/S/D decoder. Their native side effects must
survive dead values and optimization: ordinary LLVM arithmetic is not an
FPCR/FPSR contract. FPCR.NEP merges the first source's full V128, not the old
destination. Copy sparse definedness without inventing upper bits; preserve
source NZCV and reject missing inputs across CFG joins. Keep original Go
state/canary oracles, all three translation APIs plus typed Go, bounded batches,
and required Linux/QEMU NEP/AH execution separate from object-only coverage.

An ordinary typed Void source may omit TEXT's argument-size suffix: `$0` is
Go's unknown size, not explicit `$0-0`. Recover that distinction from the
matching retained original header; the actual declaration still bounds every
input. Omission grants no padding, parameter writes or physical-frame role.
Explicit mismatches and unknown source bytes remain Context.

Go's original `reflect.makeFuncStub` and `methodValueCall` have empty source
declarations but physical dynamic callers; their native TEXT retains
`ArgsSizeUnknown`. Local outgoing-call storage, the argument-only `argLen`,
and the GC pointer bitmap cannot bound the complete argument/result frame.
Keep these failures explicit. A real producer would need the actual function
type/layout, closure-context register and entry identity, caller/result
transport, lifetime, and the runtime's dynamic stack maps/`retValid` protocol.
A manual LLVM carrier fixture or ordinary `func()` signature is not that
producer and cannot make the default benchmark pass.

The Advanced SIMD SM3 family is WORD-only in Go 1.27. Its exact seven forms
follow [Arm DDI 0602](https://documentation-service.arm.com/static/67e40f3398aa3c3b6eea6a85)
and LLVM 22's crypto encoder: PARTW1/PARTW2, SS1 and TT1A/B/TT2A/B, with
four-word vectors and TT indices 0–3. The shared raw-vector registry records no
GP/SP or memory effects; destructive destination reads and all aliases remain
explicit. Portable LLVM arithmetic is checked separately from original Go
WORD execution, which is required on Linux/QEMU CPU=max. Host-only arithmetic
execution is not evidence that the host implements FEAT_SM3.

- Distinguish physical encoding rules from Go frontend acceptance, especially
  for 386 VEX/EVEX registers and ignored VEX.W bits. Check primary architecture
  specifications in addition to Go tables.
- Validate operand order, implicit inputs/outputs, destination aliases, flags,
  width extension and lane boundaries. Keep every overlapping X/Y/Z view
  coherent; preserve legacy upper lanes and clear VEX/EVEX upper lanes.
- Test dynamic masks, irrelevant high mask bits, unaligned addresses, null
  inactive sources and guard pages. Consume results so optimization cannot
  remove the memory access under test.
- Check count masking versus saturating shifts, signedness, NaNs and
  out-of-range conversions. Avoid LLVM poison and undefined arithmetic.
- Native access width is not internal register-slot width. A 386 Q spelling
  can still require a four-byte memory read.
- Validate independent frame slots and spans; do not relax ABI checks just to
  compile an external library.
- Unknown raw VEX/EVEX instructions must fail closed, never become unrelated
  legacy instructions. Test truncated and reserved encodings.
- Demonstrate that the old implementation fails the new runtime oracle where
  practical. Use an isolated checkout/overlay, not a running frozen tree.

ARM64 literal WORD validates Go's complete `C_LCON` source class before its
low 32 bits reach any native preflight, decoder, lowerer or PC/data rewrite.
This is not an int32/uint32 range check: Go also accepts wide MOV and bitmask
constant classes. Reuse the shared constant classifier and retain actual-Go
accept/reject controls, exact low-word tests, and live/dead source rejection
through all four API consumers. A valid decoded opcode cannot repair an
original `C_VCON` operand; symbolic relocation roles remain separate.

Native-family preflight checks that constant class even for data, then uses a
private code view for the existing bounded raw-routine/append-pool proof.
Proved data bytes do not acquire instruction grammar or CPU-target requirements.
Dead WORDs after a source RET alone remain subject to those requirements.
The view changes no original source, branch, caller role or memory permission;
later lowering independently repeats its complete source/layout proof.

Use independent-axis tests for shared operand grammars rather than repeating
the same huge Cartesian product for every mnemonic. See
[validation](validation.md) for the required gates.

The packed unpack and logical families share only their binary operand grammar;
operation effects remain separate. Unpack interleaves bits, including floating
NaN payloads, within each 128-bit lane and keeps legacy upper aliases distinct
from VEX/EVEX upper-zeroing. Intel SDM Vol. 2A Tables 2-44/45 classify EVEX
unpack memory as E4NF: even a zero mask retains the complete native access.
MMX low unpack reads four bytes; MMX high unpack reads eight. FP spans must
cover all independent fields before emission. Go-accepted 386 names above
X7/Y7/Z7 need a real physical mode32 binding; keep their actual Go encodings
and Context regressions rather than interpreting them as ordinary virtual
registers. Consult the [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)
and preserve zero-mask/guard-page and complete-byte runtime oracles.

The zero-operand VZEROUPPER/VZEROALL family has implicit SIMD writes, not no-op
semantics. Its shared grammar/lowerer/caller effect uses registers 0-15 on
amd64 and 0-7 on 386, preserves registers 16-31, and distinguishes preserved
low X bytes from known-zero wider bytes. Raw VEX.L selects the two operations;
reserved pp/vvvv and forbidden prefix combinations must not inherit the pinned
decoder's incorrect VZEROUPPER spelling. Keep full-bank alias, flags, MXCSR and
mask canaries. See Intel SDM Vol. 2C VZEROALL/VZEROUPPER in the linked manual;
portable LLVM execution does not prove native AVX execution.

The six unsigned packed widening ratios have a separate PMOVZX/VPMOVZX typed
grammar and shared pure caller/result byte dependency; their existence does not
authorize signed PMOVSX callers. Bind legacy `yxm_q4` and both complete AVX operand tables, the
shrinking source tuple, K1-K7 and `.Z`; low-bank masked 386 forms are accepted
by Go, while high named X/Y registers still need a physical mode32 contract.
Read independent FP fields byte by byte, rejecting any missing byte before
emission. Legacy writes preserve coherent wider aliases; VEX/EVEX writes zero
above the destination width. Intel SDM PMOVSX/PMOVZX distinguishes VEX WIG
from EVEX's DQ-only W0 requirement. Keep complete-byte, NULL/guard-page and
flags/MXCSR oracles: E5 inactive lanes suppress source reads, but a known mask
does not itself grant caller memory bounds. Original legacy execution and
portable LLVM VEX/EVEX semantics are separate from native AVX512 execution.
The lowering-only result observer may consume its paired conditional native
read, never invent pointer backing or caller/frame authority. Retain the exact
shrinking tuple with volatile active reads: even a live low-lane result cannot
justify removing unobserved native input bytes. Dead outputs and E5 inactive
lanes need separate fault controls. Public queries, source joins, pointer/index
identity and raw-entry contracts remain strict. Bound runtime batches and compare
original legacy Go bytes, independent byte references and LLVM O0/O2 separately.

GP/X scalar bit transfers share one typed grammar for MOVL, MOVQ, Go's MOVD
and MOVDQ2Q source aliases (64-bit), VMOVD and VMOVQ. Named aliases preserve
their original `Op` and `Raw` identity and use every MOVQ scalar, memory, GP/X,
machine register and TLS row; they are not Intel opcode restrictions. Actual raw
F2 0F D6 remains an X-to-MMX native effect, independent of source-compatible
formatter spellings, and requires physical MMX/x87 entry and caller state.
Source normalization cannot wash away that origin or establish initialized
bytes. Canonicalize only local dispatch copies, not the complete source bound
by caller, raw-return or frame fingerprints. Go's FLOAT-immediate class has no
MOVQ or alias row and cannot become a zero integer. The required
Linux AMD64 `TestCrossLinuxRuntimeMatrixX86MOVQSourceAliasesOriginalAndLLVM`
counterpart executes original Go bytes and LLVM with separate GP, GP/X,
X128-clearing, native eight-byte read and address effects.
The grammar feeds original-source validation,
CFG routing, lowering, private FP-result initialization and caller byte effects;
the direct scalar module prototype cannot bypass it. Legacy writes preserve
upper vector aliases, while VEX/EVEX writes clear them. Mode32 VEX GP transfers
use 32 bits even for VMOVQ; its memory/X copies remain 64-bit. Raw-only VMOVW
keeps its decoder-bound 16-bit role and does not authorize named instructions
or caller state. Bind both complete current and historical legacy tables,
including the historical signed-imm32 MOVQ row. Keep every-byte FP holes,
dead volatile memory reads, original-Go NULL/guard-page faults, all register/
address axes, complete vector/GP canaries and the three-API five-target objects.
Accepted operand shapes never grant pointer permission or initialized data.

Raw VMOVW's exact original opcode/operands may consume the same GP/X byte
transfer inside ordinary lowering. Require both source bytes even for Void;
retain WIG, GP zero extension, complete vector upper clearing and exact volatile
m16 accesses. Only already-proved incoming pointers supply native addresses.
RIP literals, address overrides, segments, native returns and frame roles keep
their separate contracts; declaration-only observers gain no native read.
Keep unchanged unbound Go/emitter objects and Context controls alongside
initialized five-target objects, byte/origin mutations and the original portable
guard-page execution. See Intel's [VMOVW specification, section 5.61](https://cdrdv2-public.intel.com/678970/intel-avx512-fp16.pdf).

For ordinary GP/X native loads, the lowering-only result observer consumes the
same exact-width volatile read as scalar lane insertion. MOVL/MOVQ/MOVD and
VMOVD/VMOVQ retain loaded low bytes, known-zero X128 remainder and distinct
legacy/VEX/EVEX wider aliases. Memory Q remains eight bytes on 386, unlike its
GP-register WIG form. The paired named native-store continuation separately
requires every stored low byte and an incoming pointer address, even for Void.
It keeps the original exact unaligned volatile write without changing numerical
or storage facts; a masked/logical read rule cannot supply a write envelope.
These continuations cannot replace public declaration, caller, raw/frame, MMX
or physical-bank contracts or establish future memory validity. Keep original
unbound format objects, initialized read/store programs, overwritten-store
observations and portable byte/canary execution as separate evidence.

Scalar integer lane insert/extract shares `x86ScalarLaneProperties` across the
original-source validator, lowerer, caller-region effects and ABI0 result-byte
observer: all PINSRB/W/D/Q and PEXTRB/W/D/Q names, plus their V forms. A lane
insertion defines only its selected bytes; untouched unknown X bytes stay
unknown. Extraction needs exactly its selected bytes. Legacy preserves wider
aliases, while VEX/EVEX clears the bytes above X128. Go's legacy Ymm spellings
in these tables encode GP ModRM numbers, not physical MMX state. Bind complete
Go tables and opcode attributes independently. Mode32 VPEXTRQ retains the
original W1 encoding but uses the physical WIG dword lane and r32/m32 effect;
its unbound high banks remain Context. Scalar INSERTPS/EXTRACTPS result effects
reuse their existing typed source/target/zero selectors, not a new wider-vector
or mask permission.

Block extraction shares its complete insert/extract grammar with paired native
memory effects and mandatory Void inputs. Require every selected source byte,
mask and complete incoming pointer/index before continuing; unknown bytes in
unselected chunks stay unknown. Unmasked stores are exact unaligned volatile
writes, even when overwritten. Masked E6NF stores retain their original native
opcode without reading inactive destination bytes. Continuation establishes no
memory facts or caller/raw/physical permission. Keep logical FP/AUTO ownership
separate, original unbound format objects intact, and initialized public objects,
portable byte/canary execution and required native execution distinct.

Scalar PEXTRB/W/D/Q, VPEXTRB/W/D/Q and EXTRACTPS/VEXTRACTPS stores consume
their existing typed lane selector and the exact selected bytes. The paired
volatile native write needs an incoming pointer base and numerical index;
Void and unused bool cannot waive these obligations. A store creates no
memory or later-read fact. Original uninitialized native/segment formats retain
Go/emitter objects and public Context, not initialized public success.

Private POPW/L/Q native stores reuse the complete existing stack-width and
bit-initialization proof. Keep native widths, cell identity, underflow, balance,
FLAGS/DF/ID correlations and missing-byte checks. Only a paired exact volatile
store can consume those popped numerical bytes at an incoming-pointer address;
the standalone observer gains no native memory or physical entry role.
Rejected paired stores must not mutate the reaching private state.

Any integer-lane instruction with declared integer FP results consumes the
whole original-function must-initialized byte proof before lowering, including
later GP-to-FP stores and all RET paths. A final-opcode-only check is inadequate.
An explicit AMD64 ABIInternal scalar entry uses the same bounded source CFG,
but initializes only the declared bytes in Go's nine integer argument registers
and checks its scalar AX result at every RET. It does not initialize ABI0 FP
fields, spill slots, hidden g/closure state or unspecified upper argument bytes.
Pointer arguments remain opaque identities; aggregates, floating/boolean
transport, multiple results and raw/native entries need their separate contracts.
Narrow byte/word FP views require unique actual numeric field bytes; pointer,
padding, input stores, partial results and unknown effects remain Context.
Native memory uses its exact volatile byte width and existing caller bounds;
no new frame, pointer or native backing is inferred. Keep original Go objects,
five-target three-API objects, selected/unknown lane mutations, full vector/GP
alias canaries and flags/MXCSR observations. Portable LLVM execution and Darwin
Rosetta observations do not establish native Linux or AVX512 execution. An
unknown AES effect is still unknown even after PINSRD is registered.

The lowering-only result observer additionally consumes the paired native
PINSRB/W/D/Q, VPINSRB/W/D/Q and INSERTPS/VINSERTPS loads. Continuing past their
exact-width volatile read defines only the selected bytes, with the existing
lane/zero-selector and upper-alias rules. Even a dead result or an INSERTPS zero
selector retains the native access. Incoming pointer identity and numerical
indexes are not bounds, validity or initialized-pointee facts; declaration-only,
caller, native-store and raw/frame observers remain strict. Keep the complete
Go rows, five-target objects and original legacy-Go/LLVM numerical and fault
oracles separate from a claim of physical VEX/EVEX execution.

`CaptureGoAMD64FrameSource` is an initial, sealed **observation**, not a frame
permission. It independently selects and exports a flat main module's complete
ordinary Go sources, retaining only bodyless integer, finite pointer and slice
assembly declarations. Stock-SDK imports bind the actual compiler-selected
source/export graph; bodies, values and imports themselves grant no native
permission. Foreign module dependencies still need their own source handoff.
SDK dependency macro registrations remain guarded compiler inputs, not ordinary
target CPP authority. Retain their bounded literal-include closure using Go's
fixed package-CWD search, including shared fallbacks and directory shadowing.
Dynamic directives, root escape and changed source fail. Only the actual
compiler/source/export role supplies a generated header; no expanded CPP or
private-frame permission is created by this source-only capture.
The observer then binds
all selected ASM, headers,
actual Go tool/source routes, original object bytes and complete source positions.
The caller selects the trusted stock-Go installation and explicit private command
caches; a public selection record, manual signature or JSON cannot recreate its
token. Both conventional BP producers are recognized from actual machine bytes,
not from a Go version guess. Ordinary conditional CPP additionally binds the
actual SDK's complete macro-registration ASTs through the shared
`internal/goasmmacros` reader. Both the independent Go assembler and source
preprocessor consume that same observed target/profile definition list; header
changes permanently revoke the source observation. Environment strings alone
are not macro-source authority. Unknown generated/foreign/test/unwind roles
remain Context. Closed fixed-local Windows metadata has a separate complete
object/listing/prologue/source-PC join. Its exact SDK schema binds all eight
producer inputs: hashed SEH definitions from Go 1.23 onward have different
symbol/Aux enums, linkname flags and alignment listing syntax. Use the selected
producer's schema, never optional formatting or global object-version widening.
Native exception handlers remain outside that observation. Every
Verify rechecks bytes, complete inventory and actual export/selection before and
after commands; failure or Close revokes the token. The observer alone has no
allocator, caller certificate, native-memory grant or compiler adapter.
Pointer/slice/bool observations retain the independent language type/model and
object-bound ABI0 data/len/cap slots, including pointee, element, named/alias RHS
and field identity. A go/types pointee model is not an observed native extent:
Go1.20 StdSizes omits compiler tail padding/zero-tail storage in some structs.
These observations grant no input extent, alias or GC contract. The bounded
fixed-local consumer separately proves scalar/component transport. Its Binder
re-typechecks the complete original typed declaration and retains that
language identity; each consumer checks it against the live factory declaration
and object role/signature before and after translation. The restricted
transport grammar applies to types reachable from assembly parameters/results,
not unrelated Go declarations such as an XOF interface or callback type.
All original Go sources are still independently typechecked; complete scope
names and local type/alias roles remain bound. Unrelated ordinary types cannot
create assembly signatures or bypass signedness, alias RHS, pointee or field
checks on a real assembly signature. By-value aggregates,
recursive/generic types, noninteger/nonboolean elements and nonordinary roles remain Context.
Opaque incoming pointers may be copied through full-width GP/private cells
and pointer results. The separate native-input access role accepts typed FP
pointer bases with plain displacements and exact typed access widths. It grants
no pointee extent, alignment or private-frame certificate; preserve native
accesses and faults even when numerical results are dead. Pointer arithmetic,
indexed/TLS addresses and pointer escape require their own proven contracts.
Pointers never become numerical bytes or private-SP addresses. Every overlapping store revokes
their cell identity, including an unknown or zero mask. Slice data/len/cap and
multiple results require every exact ABI0 component to be initialized. A bool
occupies one physical byte but returns LLVM i1: only proved zero/one bytes,
including complete SETcc and canonical CMOV alternatives, may enter that slot.
The eight mod64 residues and independent byte-alias replay remain mandatory.
The complete CFG uses a bounded fixed-point worklist; provisional memory facts
are published only after convergence. An ordinary same-function branch is not
an external tail call. Go-generated split-entry checks are recognized from
exact original code, source positions and relocations; only the ordinary body
layout is projected. Source-written CALL/TLS and private helpers receive no
permission from that observation. Keep these contracts distinct from component
transport and from native-input access.
Mixed TEXT/DATA requires a separate complete current-Go source/object/listing
observation on each AMD64 OS. Bind every DATA definition, byte, zero tail,
relocation and original TEXT position; Windows unwind retains its independent
complete-object join. Observing mutable/BSS/address DATA grants no memory use.
SDK DATA reuses the same live complete source/object observation rather than
recapturing it with standalone producer flags. Ordinary ABI0 global references
can remain in that inventory without becoming private literals or address roles.
The fixed-local consumer separately admits bounded private, relocation-free
readonly literals whose actual Go bytes equal the entire LLVM initializer.
Retain exact symbol identity, native extent/alignment and live source guards;
reject coalesced definitions, stores, address escape, and zero-mask out-of-bounds
reads. Only already registered typed numerical operands consume this proof;
literal reads never receive private-frame certificates. Complete KMOV/VAES byte
boundaries use the shared physical decoder without borrowing raw RIP translation
permission. Original-Go/LLVM execution and all-target objects remain distinct
from an original external-library replay or ledger pass.
The runtime oracle independently snapshots original Go ABI0 bool bytes and
adjacent canaries. Its LLVM caller uses an explicit i1-to-i32 shim: these tests
do not certify C `_Bool` return attributes or a new foreign-call ABI.
The fixed-local contract also accepts a typed void return with no result slots.
Void does not exempt any original or
normalized DAG, local-byte initialization, native alignment, SP restoration,
BP/g, escape or source-lifetime check, and cannot authorize an FP input store.
Compile-only void object tests establish no numerical return or external-library
runtime coverage; observations alone still have no local-memory permission.
Factory artifacts use the request's effective explicit TMPDIR, not the parent's
temporary environment. Verify and Close check the created directory identity;
replaced or redirected directories are never recursively cleaned. The package
root is fixed to its resolved canonical source at capture: a later change to
the caller's original alias does not change that source. Explicit cache roots
remain caller-owned; capture does not authenticate ownership or delete them.

Exact downloaded frame capture distinguishes the selected package directory
from its original module root. A flat subpackage may bind its
declared path only through the independently guarded whole ZIP and original
go.mod; archive namespace aliases do not replace that declared namespace.
Actual Go selection must retain the same module root, metadata, language and
package path. Ancestor metadata or source changes revoke the capability.
Preserve a missing `go` directive as missing in the original module record.
Match its actual cmd/go metadata by role: the main module has the fixed 1.16
default, while a dependency retains an empty GoVersion. Do not rewrite go.mod,
normalize dependency metadata into a main role, or borrow the current SDK's
language version. The actual compiler/source/export checks and independent
main-source typecheck still enforce that language; malformed or changed
metadata remains rejected. Keep current-Go and Go 1.20 producer regressions.
SDK imports retain the actual SDK source/export graph. Each foreign module
requires the frame factory's own exact Go-download/whole-ZIP observation,
canonical module/package/metadata/language identity and complete compiler
source/export consumption. Replacements and unobserved version changes fail;
restoring changed dependency bytes cannot revive a revoked observation.
An archive without go.mod may retain canonical proxy metadata only through
the shared public SumDB signature and record-inclusion verifier, bound to the
actual exact ZIP h1, metadata h1 and bytes. It remains external metadata,
never an invented ZIP member or a cache-CWD main module. Full ZIP/tree checks
and permanent mutation revocation remain required. A legacy primary uses a
separately owned exact-version dependency query, not cache-CWD main inference.
Its private metadata preparation can resolve only versions already in the
observed download cache's file-proxy index; disable direct/network fallback.
Only registered stock-Go resolution progress is permitted during preparation.
Then freeze that private configuration and repeat the complete actual query
read-only; unknown diagnostics, changed pins, replacements and query/cleanup
failures remain errors. Retain the dependency's absent GoVersion metadata and
the compiler's implicit Go 1.16 language, not the query main's language.
Both frame factories still independently check every selected exact ZIP,
original source, compiler export and object. The temporary query provides no
numerical-command, memory, native-entry or source-exclusion permission.
The source-role extension grants no new native instruction/memory effects or
dynamic-frame permission. Keep the original Go objects and three-API LLVM 22
O0/O2 objects on all AMD64 targets separate from external-library success.

The independent x86 SDK numerical/data observation uses exact Linux x86,
Darwin/amd64 and Windows x86 profiles. Source macros, baseline CPU settings,
CGO defaults, LLVM triples and every native member remain target-bound;
ordinary owned numerical capture retains its separate Linux-only boundary.
Default Darwin PIE carries exact shared compiler/assembler flags; Windows PIE
does not. CPU variables' original self-linkname NonpkgDefs remain a CPU-only
storage role, never a generic-global or external-function permission. SDK
compiler metadata may include the complete bounded JSON directive prologue
from the pinned Go writer/linker grammar. Observe its rows without applying
imports, linker flags or calls; standalone/owned objects retain their old bound.
Keep full original CRC32 source/object checks on each added platform and
cross-target, malformed-row, ABI/index and source-lifetime rejection controls.

Ordinary fixed-local capture observes Go's actual AMD64 v1/v2/v3/v4 profiles
independently. Original feature-tagged source selection, compiler exports,
target/CPU environment and native objects stay bound to that exact capture;
changing and restoring a profile cannot revive a revoked observation. The
owned assembler uses cmd/go's GOOS, GOARCH and GOAMD64 definitions, with ordinary
conditionals closed by the shared actual-source registration above. Generated
headers still require their separate source mapping; macro selection grants
no unregistered numerical, frame or memory effects. A higher profile
is neither a native CPU execution certificate nor new memory permission.
The focused profile tests own one disposable build cache per test root so
Go 1.27's objdump helper is not rebuilt for every case; sources, modules and
temporary artifacts remain separate, and every case reruns the actual driver.

Broadcast result-byte consumers share the complete scalar/block grammar with
lowering. Read exactly its source tuple, not the destination width, from existing
initialized FP/AUTO bytes or the lowering-only same-file DATA directory. The
mask may preserve unknown destination bytes but cannot authorize missing source
bytes or native pointer storage. Standalone declaration queries have no DATA
owner; source/raw address overrides retain their separate contracts. Keep the
eighteen memory members, full Go rows, five-target objects, mask/extent negatives
and portable numerical execution together. Historical Go maskless `.Z` objects
are reserved-encoding observations, not accepted forms or runtime passes.

RIP broadcast constants retain their private decoder role, never a named
immediate grammar. A bounded whole-source replay may hand exact scalar constants
or block DATA tuples to those same typed effects. It still requires actual mask
and merge bytes, independently checked raw RET and complete source/DATA identity;
frames, conditional native reads and declaration-only queries gain nothing.
Portable broadcast data values execute on the actual host target; do not hide
them behind an unrelated x86-only native launcher. Original AVX512 execution
remains a separate required test axis.

Physical MOVSXD and ordinary dword literal loads share an exact four-byte
decoder input role. Opcode 63's default dword, REX.W and 66+REX.W forms keep
their independent zero/sign-extension writes. Supply that fact only to the
current source-stack numerical transfer, then clear it before saving state.
It establishes no pointer, later-read or DATA ownership; the whole-source raw
return guard still verifies actual literal bytes. Keep physical SP/BP/g roles,
vendor-ambiguous word reads, original encoding identity and stale-proof controls.

VEX/EVEX logical RIP literals reuse the same bounded whole-source consumer and
existing typed logical effects. Require exact decoder read identity, source
operand and full/broadcast tuple width; missing source, mask and merge bytes
remain unknown. The complete original/decoded/normalized source and raw RET
checks stay independent. This adds no native read, frame, legacy/MMX or
declaration-query permission. Preserve original unbound Go/emitter objects and
public Context separately from initialized public objects.

EVEX VPSLLDQ/VPSRLDQ RIP literals use that same bounded source consumer and
the existing typed shift effect. Read the entire X/Y/Z tuple even when a byte
count of 16 or more makes every result lane zero. VEX remains register-only;
mask, broadcast and zeroing fields remain reserved. Preserve all 256 selectors,
128-bit lane boundaries, wider-alias clearing and original FLAGS without
granting a standalone DATA query or raw-return frame permission.

VEX/EVEX packed integer EQ/GT literals share the existing complete B/W/D/Q
comparison grammar and byte effect. Exact source identity and full/broadcast
tuple width remain mandatory. Vector input bytes and actual masks stay required;
the EVEX K result is write-only, not a merging vector destination. This adds no
legacy/MMX, native-read, frame or standalone DATA-query role. Keep original
uninitialized formats separate from initialized public objects. C-only signal
and exit-status controls execute on the actual host; they do not require an
x86 native-instruction launcher or certify native AVX512 execution.

VEX/EVEX floating-compare literals reuse their typed PS/PD/SS/SD input effects
and existing native emitter. Preserve the entire predicate byte, MXCSR, fault
behavior, scalar passthrough and write-only K results. Exact decoder/DATA identity
and full/scalar/broadcast tuples supply only the current instruction's inputs,
not native-read or frame authority. A CFG state clone deliberately revokes this
transient DATA scope; instruction-local test oracles must not confuse that
revocation with the instruction's own effect. Keep original unbound formats
separate from initialized public objects and native execution.

VEX/EVEX packed add/subtract literals reuse their complete typed wrapping and
signed/unsigned saturating forms. Exact decoder read identity and full/broadcast
tuple extent feed the existing lane-byte effect. Unknown source lanes remain
unknown, merging requires old destination bytes, and zeroing does not invent a
mask or memory extent. Whole-source/raw-return checks, mode32, native-read,
legacy/MMX and declaration-only boundaries stay independent. Keep original
missing-mask formats and independently initialized public programs distinct.
