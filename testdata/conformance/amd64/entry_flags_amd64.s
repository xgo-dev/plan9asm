#include "textflag.h"

// Zero-prologue-clobber entry-flag differential adapter for native amd64.
//
// callWithEntryFlags(sel, flags) selects the target kernel pointer BEFORE
// setting RFLAGS via PUSHQ AX; POPFQ, and immediately invokes the NOSPLIT $0-0
// target with CALL R11 (which modifies no RFLAGS bits). Because every target
// has frame size $0 and NOSPLIT, Go's assembler emits ZERO prologue
// instructions before the target's first instruction.

TEXT ·callWithEntryFlags(SB), NOSPLIT, $0-24
	MOVQ sel+0(FP), CX
	LEAQ entryFlagRawRead<>(SB), R11
	CMPQ CX, $0
	JEQ  dispatch
	LEAQ entryFlagCFXorOF<>(SB), R11
	CMPQ CX, $1
	JEQ  dispatch
	LEAQ entryFlagPextrq0Low41HighCF<>(SB), R11
	CMPQ CX, $2
	JEQ  dispatch
	LEAQ entryFlagPextrq1Low41HighCF<>(SB), R11
	CMPQ CX, $3
	JEQ  dispatch
	LEAQ entryFlagPextrq1LowCFHigh41<>(SB), R11
	CMPQ CX, $4
	JEQ  dispatch
	LEAQ entryFlagPextrq0LowCFHigh41<>(SB), R11
dispatch:
	MOVQ flags+8(FP), AX
	ANDQ $0x8d5, AX
	ORQ  $0x202, AX
	PUSHQ AX
	POPFQ
	CALL R11
	MOVQ AX, ret+16(FP)
	RET

// sel=0: returns masked status flags (OF:11, SF:7, ZF:6, AF:4, PF:2, CF:0)
// directly from entry RFLAGS to prove zero prologue clobber.
TEXT entryFlagRawRead<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ AX
	ANDQ $0x8d5, AX
	RET

// sel=1: returns CF ^ OF — equal (0) under both all-0 (0x000) and all-1 (0x8d5),
// but 1 when CF or OF is flipped individually!
TEXT entryFlagCFXorOF<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ AX
	MOVQ AX, BX
	SHRQ $11, BX
	XORQ BX, AX
	ANDQ $1, AX
	RET

// sel=2: X0 = {low=41, high=entry CF}, extract lane 0 -> always 41.
TEXT entryFlagPextrq0Low41HighCF<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ $41, AX
	MOVQ AX, X0
	PINSRQ $1, BX, X0
	PEXTRQ $0, X0, AX
	RET

// sel=3: X0 = {low=41, high=entry CF}, extract lane 1 -> entry CF (0 or 1).
TEXT entryFlagPextrq1Low41HighCF<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ $41, AX
	MOVQ AX, X0
	PINSRQ $1, BX, X0
	PEXTRQ $1, X0, AX
	RET

// sel=4: X0 = {low=entry CF, high=41}, extract lane 1 -> always 41.
TEXT entryFlagPextrq1LowCFHigh41<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $1, X0, AX
	RET

// sel=5: X0 = {low=entry CF, high=41}, extract lane 0 -> entry CF (0 or 1).
TEXT entryFlagPextrq0LowCFHigh41<>(SB), NOSPLIT, $0-0
	PUSHFQ
	POPQ BX
	ANDQ $1, BX
	MOVQ BX, X0
	MOVQ $41, AX
	PINSRQ $1, AX, X0
	PEXTRQ $0, X0, AX
	RET
