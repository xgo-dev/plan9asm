# x86 source address-immediate roles

Go's source rewrite precedes operand classification. `MOVL/Q $offset(base), reg`
becomes `LEAL/Q`; the register and index still compute the effective address.
The audited scalar integer rows instead classify unnamed `TYPE_ADDR` as a
constant and ignore its register annotations. 386 truncates the offset to
32 bits; Q arithmetic, comparison, test, multiply and push sign-extend imm32.
Shift/rotate counts use `Yu8` (not negative `Yi8`), while bit-test counts use
signed `Yi8`. Tests bind these distinctions to actual stock-Go source and bytes.

The lowering view is immutable and follows original caller/raw/frame proofs.
It cannot repair or inherit LOCK, raw-return or physical-frame certificates.
Named SB/AUTO/FP sources retain their separate consumers. Unresolved offsets,
unbound segment/TLS/address-size roles and unaudited opcode classes fail closed;
integer annotations never grant x87/SSE memory or float-literal permissions.

The independent byte/math/canary oracles retain O0 and O2. Darwin ARM64/Rosetta
observations are diagnostic only; their required Linux roots remain a distinct
execution axis, not something implied by five-target LLVM object acceptance.
