# Canonical x86 bool results

The ordinary scalar-register lowering role accepts one logical `i1` result
only when the complete explicit ABIInternal source proves AX's physical low
byte is initialized and exactly zero or one on every path to RET. The actual
Go logical signature, scalar input register assignment and result field must
still agree. Bool inputs, tuples, spills, FP/AUTO backing, raw directives and
hidden/native entry state retain their independent Context boundaries.

Per-byte canonicality is a separate must-fact from initialization. Complete
typed SETcc, scalar moves (including source-only MOVD/MOVDQ2Q aliases),
extensions, conditional moves and AND/OR/XOR preserve only proven canonical
bytes; other writes revoke the affected facts. Reads, FLAGS, source shape and
memory are first validated by the independent typed transfer. Joins intersect
both domains, and the existing finite byte-work budget counts the additional
state without increasing its limit. No known low byte initializes unknown GP
upper bytes. Arbitrary initialized bytes 2, 3 or 255 cannot gain a logical bool
by truncation to `i1`.

Execution tests keep two independent axes. The complete actual Go assembler
ABIInternal instruction bytes execute through an explicit test-only AX/BX
adapter with raw-u64, stack and GP canaries. Standalone `-p runtime` grants
encoder-fixture selector permission only: it is not a captured SDK source,
native Go caller certificate or runtime-path masquerade. LLVM calls the
translated `i1` function through an explicit `i1` to `i32` shim, with C crossing
only integer signatures; this is not a C `_Bool` ABI assertion. A separate owned
Go package executes genuine ABI0 bool callers and observes their original raw
return byte and canaries, including noncanonical 2/3/255 raw-byte controls that
are never normalized through a bool call. Linux/amd64 is the required execution
counterpart when local AMD64/Rosetta execution is unavailable.

This role neither binds the linked SDK literal-minimum-alignment producer nor
exposes a linked address as a number. Full original maps functions remain
subject to their linked-low-bit, caller, pointer, loop and native-entry contracts.

## Explicit mode32 logical register result

An independent lowering-only role consumes complete explicit `ArgRegs` with
one logical I1 return in AX, no ABI selector, zero frame/argument extent and
no FP slots. Each unique registered word carrier receives only its declared
I1/I8/I16/I32 bytes; Ptr supplies opaque address identity, never numerical
bytes or backing. Only an actual I1 input starts canonical. The shared bounded
CFG and canonical-byte transfer require AX's low byte to be zero/one at every
RET; unknown upper bytes and initialized 2/3/255 remain distinct.

The existing complete typed mode32 CMPXCHG B/W/L/8B emitter can supply its
conditional numerical outputs and defined status flags after its preserved
native memory opcode continues. Every explicit/implicit data input and pointer
address is checked; LOCK must be adjacent to the complete memory operation.
No source rewrite, LLVM atomic alignment, reusable memory extent, physical Go
entry/caller or ABI0 byte slot is inferred. This logical source/IR proof is not
an original-Go caller, backend-object or executed-semantics certificate.

## Bounded 386 ABI0 byte result

The independent SDK literal-predicate role admits only a complete ordinary 386
no-argument, zero-frame function with exactly one declared bool result byte
at FP+0 and original argument size one. Other literal-predicate contexts,
direct-tail, raw and native roles retain Context; the shape authenticates no source.
Each declared physical byte has a separate bounded canonical must-fact,
cloned and intersected across the complete source CFG. Numerical initializedness
remains independent: raw 2, 3 and 255 may be read or compared and then replaced
by SETcc or another proved zero/one before RET. Overwrites revoke canonicality,
and every predecessor must supply a canonical result. The existing shared
byte-work envelope counts this state without increasing its limit.

The cached whole-source proof is required even without an FP/SIMD probe.
Intermediate loads and stores retain the physical I8 value; only the final
proved result is truncated to logical I1. This does not initialize unknown GP
upper bytes, expand FP storage, permit pointer/frame escapes or establish
native Go entry. The required Linux AMD64 execution counterpart uses original
386 Go bool callers and independent raw-byte/canary observers, plus LLVM's
explicit I1-to-I32 shims; fixture inventory/IR tests alone are not execution.

An independent lowering-only extension handles existing zero-frame logical
inputs and declared-slot aliases. Only actual I1 parameter leaves start
canonical; numeric byte inputs remain merely initialized until a typed
operation proves zero/one. LEAL and full-word copies retain a separate exact
slot/interior address, never numerical, caller or graph-result pointer facts.
Scalar/extension reads and SETcc stores stay inside that declared field;
partial/mixed aliases, escapes and overwritten carriers lose the role. This
optional alias state is cloned/intersected and charged to the same finite work
envelope. Intermediate bool parameter reads/writes also preserve I8 bytes.
Other scalar leaves reuse their existing exact parameter/effect rules: opaque
pointers and floating values do not become canonical or numerical pointers.

A separate request-local ordinary CALL contract retains the complete original
File and exact signatures before KeepFunc/normalization. It accepts only a
same-file zero-frame readonly leaf with one actual I1 input byte at FP+0 and
one result byte at FP+4. The leaf receives its independent complete canonical
proof once; recursion, unknown calls, input writes, escapes, raw/source changes
and native/direct-tail roles retain Context. Original caller and callee source
tuples are replayed, never relabeled or cropped. Resolve callbacks finish before
the final source/signature check; all three APIs discard artifacts on late
mutation. This is logical lowering, not Go-native CALL entry authentication.

Actual positive caller TEXT frame bounds contain only the two declared outgoing
bytes (SP+0/SP+4); padding and general physical-SP/AUTO storage gain nothing.
Separate NUM/canonical outgoing facts clone/intersect and share the unchanged
finite byte/visit envelope with the cached callee proof. A CALL requires the
actual outgoing parameter byte to be canonical and writes only its declared
result. All GP/SIMD/mask/FLAGS, pointer and slot-address facts are revoked across
CALL; no unspecified high GP byte becomes initialized. Intermediate outgoing
bytes remain I8 until the proved logical call transport. The existing complete
seven-function bool-frame fixture remains intact; pure/IR tests are not an
object or execution certificate, and actual 386 SDK/native validation is a
separate gate.
