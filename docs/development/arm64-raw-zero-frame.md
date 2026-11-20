# ARM64 raw zero-frame ownership proof

Zero-frame and `NOFRAME` functions do not receive a Go LR/FP prologue merely
because a raw WORD later decodes to BL. A private raw BL witness records its
exact same-source PC target; diagnostic comments cannot provide that origin.

The additive whole-source proof tracks a bounded negative-SP envelope, may-frame
GP aliases and spills, and independent BP/LR reaching values. Every root return
restores entry SP/BP/LR; a bounded local raw call returns with its call-site SP
and exact continuation. Unknown/native calls, unallocated stack cells, differing
SP joins, partial pointer spills, unknown indexing and address escapes fail.
Dead components are checked too. Existing framed-source and continuation guards
remain independent. Proof registration is not an object or runtime pass.

After exact root SP/BP/LR/g and OS-reserved R18 restoration, an explicit ordinary ABI0 void signature
can discard dead virtual GP scratch. It requires complete direct eight-byte
pointer/integer FP parameters, exact TEXT argument size, no results, register
ABI, custom assignment, native entry or hidden context. Source-only proofs
cannot guess this contract. Earlier stores, escapes and calls remain checked;
void transport is not an all-instruction or frame-address exemption.
Raw WORDs can name g/R18 even when Go's textual parser cannot. Their complete
entry identity is checked independently of address taint: partial spill writes,
constant overwrites, mixed joins and unknown effects cannot inherit restoration.

`TestARM64RawZeroFrame*` retains original Go-accepted minimum RED cases, explicit
escape/overlap/call-context negatives, and physical-leaf source-origin checks.
The shared MC matrix adds 132 raw scalar/GP-pair/FP-pair width/sign/offset and
writeback/local-call variants plus 48 actual Go memory spellings. Required
ARM64 native/cross runtime tests compare original Go WORD objects and LLVM22
against independent numeric/full-canary oracles, including two arithmetic
helper calls whose effects must actually execute. These fixtures do not prove
that an entire external module translates.

The complete scalar AMUL/AMADD rows share a typed input selector with control
analysis. Two operands read the destination; three/four operands do not read
its stale value unless an explicit source aliases it. Every actual PC input
retains derived-code taint. The 28-form original-Go/LLVM oracle compares
independent low/high, signed, long and accumulate arithmetic, all four NZCV
sentinels, unaligned full canaries and real LR-returning callers.

Continuation memory uses the same typed scalar/GP/FP-pair grammar as private
frame ownership. Each store invalidates only its actual byte range; partial
loads and floating code bits never restore an exact caller pointer. Unknown
indexes, malformed writeback and transformed code remain conservative. The
96-form original-Go/LLVM runtime oracle keeps physical SP aligned and checks
offset, pre/post and raw-local-call paths adjacent to saved LR/BP cells.
