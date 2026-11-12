# Actual caller-address predicates

The bounded x86 result observer retains a separate must-fact for complete actual
typed pointer arguments, either ABI0 FP imports or the existing ordinary AMD64
scalar-register entry. This domain is not `pointerGP`: readonly literal addresses,
mixed OR carriers, native state and partial pointer fields cannot seed it.

Full native-word MOV/copies (including the source-only MOVQ aliases), already
validated LEA and numerical ADD/SUB address transforms preserve provenance.
All partial/full typed GP overwrites revoke it; encoder aliases use their actual
GP destination. Unknown effects revoke all carriers. CFG joins intersect the
new fact independently of initialized numerical bytes and opaque identities.
Its sixteen logical state bytes are counted under the unchanged 64-MiB,
4,096-instruction and 16,384-visit limits.

The complete B/W/L/Q TEST register/immediate grammar reads actual physical
address bits and defines only original CF/OF/Z/S/P. AF stays undefined. It
initializes no numerical GP bytes and grants no dereference, extent, alignment,
escape, GC result or physical native-entry permission. The same typed flag
consumers and independent canonical bool-byte guard remain mandatory. Native
compare retries handle only actual memory forms; register-only effects delegate
to the shared ordinary/caller/literal transfer, with no memory-rule widening.

Independent original Go encoder bytes execute through an explicitly declared
AX/BX adapter against the same actual pointer supplied to LLVM. Raw upper-byte,
stack/GP and complete caller-array canaries remain observable; the LLVM caller
uses only an explicit i1-to-i32 shim, not a C `_Bool` contract. A separate genuine
owned Go ABI0 caller observes 4,096 actual pointer addresses, raw result words,
input-pointer identity and adjacent canaries. The standalone `-p runtime`
encoder fixture is not SDK ownership or native Go ABIInternal caller authority.
Linux emulated execution and native fork execution remain separate receipts.

The complete unmodified SDK maps source can now compose this domain with the
authenticated literal minimum and existing conditional native-load/result
rules. All two TEXTs and DATA remain; mutable AES globals stay genuine external
runtime loads. Object tests independently compare each LLVM literal definition's
alignment to the original minimum and existing Go-size rule. No forced align16,
guessed keys, cropped functions or new loop/bounds promise is introduced.
Logical LLVM object compilation is not execution of the complete SDK program,
physical Go entry authorization or benchmark completion. The separate shared
[frontend handoff](x86-sdk-literal-frontend.md) selects the authentic minimum
only on typed literal-predicate demand; it does not expand this caller domain.
