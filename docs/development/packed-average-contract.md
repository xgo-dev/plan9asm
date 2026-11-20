# Packed unsigned average

`PAVGB/PAVGW/VPAVGB/VPAVGW` share the actual Go `ymm` and `_yvandnpd`
operand grammar, but retain distinct encoding effects. Named 386 MMX rows are
rejected by Go's `Py1` selector. Named 386 high X/Y syntax is not proof of a
physical register; only complete decoded low-bank raw bytes can retain an
EVEX mask in mode32. Portable JSON cannot restore that private marker.

Each byte/word computes `(unsigned(a) + unsigned(b) + 1) / 2` with a widened
sum. Legacy X writes preserve upper views; VEX/EVEX writes zero bytes above
their width. EFLAGS and MXCSR are unchanged. EVEX E4.nb memory reads suppress
inactive lane faults, while active reads stay observable even with dead results.

Legacy m128 remains the original native instruction (including alignment and
segment faults); logical FP and unbound SP/BP are not native backing. Logical FP
values need every declared byte even with an all-zero mask. Registered widths
and byte effects do not grant caller, pointer, frame, or fixed-local permission.

LLVM objects cover five targets and three APIs. Full translated 64-byte views
have independent O0/O2 arithmetic, flags, CSR, and canary oracles. Original SSE
and MMX results are separate observations, not whole physical x87/MMX state.
Original VEX upper aliases have a required Linux test with actual AVX/AVX2
preflight and pinned guest transport. Rosetta is diagnostic, not native AMD64;
original EVEX execution is not claimed by the translated shadow-view oracle.
