#include "textflag.h"

// Native amd64 x87 machine-code differential kernels.
// Every function here is compiled by BOTH Go's native amd64 assembler AND
// plan9asm.TranslateGoModule -> LLVM 22 opt -O2 -> llc, and every popped stack
// slot, 80-bit constant byte, 10-byte BCD word, arithmetic result, and RFLAGS
// snapshot is compared bit-for-bit.

// diffX87FmovdStackDepths exercises FMOVD and FMOVDP across multiple stack
// depths and register aliases, popping the ENTIRE stack after each sequence so
// every slot (not just ST(0)) is verified.
TEXT ·diffX87FmovdStackDepths(SB), NOSPLIT, $32-8
	MOVQ out+0(FP), DI

	// Case A (Round 10 P1 #1 exact repro): FLDZ; FLD1; FMOVD F1, F0
	// Go encodes FMOVD F1, F0 as D9 C1 (FLD ST(1)), pushing 0.0 -> stack [0, 1, 0].
	FLDZ
	FLD1
	FMOVD F1, F0
	FMOVDP F0, 0(DI)    // out[0] = 0.0
	FMOVDP F0, 8(DI)    // out[1] = 1.0
	FMOVDP F0, 16(DI)   // out[2] = 0.0

	// Case B (depth 3, FMOVD F2, F0 pushes ST(2)): push 10.0, 20.0, 30.0 -> [30, 20, 10]
	// FMOVD F2, F0 -> [10, 30, 20, 10]. Pop all 4 slots.
	MOVQ $0x4024000000000000, AX // 10.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x4034000000000000, AX // 20.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x403e000000000000, AX // 30.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	FMOVD F2, F0
	FMOVDP F0, 24(DI)   // out[3] = 10.0
	FMOVDP F0, 32(DI)   // out[4] = 30.0
	FMOVDP F0, 40(DI)   // out[5] = 20.0
	FMOVDP F0, 48(DI)   // out[6] = 10.0

	// Case C (FMOVD F0, F0 duplicates ST(0) via D9 C0 = FLD ST(0)):
	// push 5.0, 7.0 -> [7, 5]; FMOVD F0, F0 -> [7, 7, 5]. Pop all 3 slots.
	MOVQ $0x4014000000000000, AX // 5.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x401c000000000000, AX // 7.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	FMOVD F0, F0
	FMOVDP F0, 56(DI)   // out[7] = 7.0
	FMOVDP F0, 64(DI)   // out[8] = 7.0
	FMOVDP F0, 72(DI)   // out[9] = 5.0

	// Case D (FMOVD F0, F2 overwrites ST(2) in place via DD D2 = FST ST(2), NO push):
	// push 1.0, 2.0, 9.0 -> [9, 2, 1]; FMOVD F0, F2 -> [9, 2, 9]. Pop all 3 slots.
	FLD1
	MOVQ $0x4000000000000000, AX // 2.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x4022000000000000, AX // 9.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	FMOVD F0, F2
	FMOVDP F0, 80(DI)   // out[10] = 9.0
	FMOVDP F0, 88(DI)   // out[11] = 2.0
	FMOVDP F0, 96(DI)   // out[12] = 9.0

	// Case E (FMOVDP F0, F2 stores ST(0) into ST(2) BEFORE popping -> [22, 33]):
	// push 11.0, 22.0, 33.0 -> [33, 22, 11]; FMOVDP F0, F2 -> [22, 33]. Pop both.
	MOVQ $0x4026000000000000, AX // 11.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x4036000000000000, AX // 22.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x4040800000000000, AX // 33.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	FMOVDP F0, F2
	FMOVDP F0, 104(DI)  // out[13] = 22.0
	FMOVDP F0, 112(DI)  // out[14] = 33.0

	// Case F (FMOVDP F0, F1 stores ST(0) into ST(1) BEFORE popping -> [55]):
	// push 44.0, 55.0 -> [55, 44]; FMOVDP F0, F1 -> [55]. Pop remaining slot.
	MOVQ $0x4046000000000000, AX // 44.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	MOVQ $0x404b800000000000, AX // 55.0
	MOVQ AX, 0(SP)
	FMOVD 0(SP), F0
	FMOVDP F0, F1
	FMOVDP F0, 120(DI)  // out[15] = 55.0

	RET

// diffX87Constants loads all 7 x87 constants (FLD1, FLDZ, FLDPI, FLDL2E,
// FLDL2T, FLDLG2, FLDLN2), verifies both IEEE-754 f64 (FMOVDP) and raw 80-bit
// extended bytes (FMOVXP).
TEXT ·diffX87Constants(SB), NOSPLIT, $0-16
	MOVQ outF64+0(FP), DI
	MOVQ outRaw80+8(FP), SI

	FLD1
	FMOVD F0, F0
	FMOVXP F0, 0(SI)
	FMOVDP F0, 0(DI)

	FLDZ
	FMOVD F0, F0
	FMOVXP F0, 10(SI)
	FMOVDP F0, 8(DI)

	FLDPI
	FMOVD F0, F0
	FMOVXP F0, 20(SI)
	FMOVDP F0, 16(DI)

	FLDL2E
	FMOVD F0, F0
	FMOVXP F0, 30(SI)
	FMOVDP F0, 24(DI)

	FLDL2T
	FMOVD F0, F0
	FMOVXP F0, 40(SI)
	FMOVDP F0, 32(DI)

	FLDLG2
	FMOVD F0, F0
	FMOVXP F0, 50(SI)
	FMOVDP F0, 40(DI)

	FLDLN2
	FMOVD F0, F0
	FMOVXP F0, 60(SI)
	FMOVDP F0, 48(DI)

	RET

// diffX87BCD exercises Go's FMOVB/FMOVBP (DF /4 = FBLD, DF /6 = FBSTP) and FBLD/FBSTP aliases.
TEXT ·diffX87BCD(SB), NOSPLIT, $0-24
	MOVQ inBCD+0(FP), SI
	MOVQ outBCD+8(FP), DI
	MOVQ outF64+16(FP), DX

	FMOVB 0(SI), F0
	FMOVD F0, F0
	FMOVDP F0, 0(DX)
	FMOVBP F0, 0(DI)
	FBLD 0(DI)
	FBSTP 0(DI)
	RET

// diffX87Arith80 exercises FADDD/FADDDP/FSUBD/FSUBDP/FSUBRD/FSUBRDP/FMULD/FMULDP/FDIVD/FDIVDP/FDIVRD/FDIVRDP.
TEXT ·diffX87Arith80(SB), NOSPLIT, $0-24
	MOVQ out+16(FP), DI

	// [0] a + b via FADDDP F0, F1
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FADDDP F0, F1
	FMOVDP F0, 0(DI)

	// [1] a - b via FSUBDP F0, F1 (ST(1) - ST(0) = a - b)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FSUBDP F0, F1
	FMOVDP F0, 8(DI)

	// [2] b - a via FSUBRDP F0, F1 (ST(0) - ST(1) = b - a)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FSUBRDP F0, F1
	FMOVDP F0, 16(DI)

	// [3] a * b via FMULDP F0, F1
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FMULDP F0, F1
	FMOVDP F0, 24(DI)

	// [4] a / b via FDIVDP F0, F1 (ST(1) / ST(0) = a / b)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FDIVDP F0, F1
	FMOVDP F0, 32(DI)

	// [5] b / a via FDIVRDP F0, F1 (ST(0) / ST(1) = b / a)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FDIVRDP F0, F1
	FMOVDP F0, 40(DI)

	// [6] non-popping FSUBD F1, F0 (ST(0) - ST(1) = b - a)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FSUBD F1, F0
	FMOVDP F0, 48(DI)
	FMOVDP F0, F0

	// [7] non-popping FSUBRD F1, F0 (ST(1) - ST(0) = a - b)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FSUBRD F1, F0
	FMOVDP F0, 56(DI)
	FMOVDP F0, F0

	// [8] non-popping FDIVD F1, F0 (ST(0) / ST(1) = b / a)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FDIVD F1, F0
	FMOVDP F0, 64(DI)
	FMOVDP F0, F0

	// [9] non-popping FDIVRD F1, F0 (ST(1) / ST(0) = a / b)
	FMOVD a+0(FP), F0
	FMOVD b+8(FP), F0
	FDIVRD F1, F0
	FMOVDP F0, 72(DI)
	FMOVDP F0, F0

	RET

// diffX87FUCOMI verifies FUCOMI, FUCOMIP, FCOMI, FCOMIP flags (ZF/PF/CF) AND
// proves OF/SF/AF are cleared to 0 even when pre-set to 1 before the compare.
TEXT ·diffX87FUCOMI(SB), NOSPLIT, $0-24
	MOVQ out+16(FP), DI

	// [0] FUCOMI F0, F1 (a vs b) with OF=1, SF=1, AF=1 pre-set via POPFQ
	FMOVD b+8(FP), F0
	FMOVD a+0(FP), F0
	MOVQ $0xa92, AX
	PUSHQ AX
	POPFQ
	FUCOMI F0, F1
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 0(DI)
	FMOVDP F0, F0
	FMOVDP F0, F0

	// [1] FUCOMIP F0, F1 (a vs b, pops a) + [2] remaining ST(0) == b
	FMOVD b+8(FP), F0
	FMOVD a+0(FP), F0
	MOVQ $0xa92, AX
	PUSHQ AX
	POPFQ
	FUCOMIP F0, F1
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 8(DI)
	FMOVDP F0, 16(DI)

	// [3] FCOMI F1, F0 (a vs b) with OF=1, SF=1, AF=1 pre-set
	FMOVD b+8(FP), F0
	FMOVD a+0(FP), F0
	MOVQ $0xa92, AX
	PUSHQ AX
	POPFQ
	FCOMI F1, F0
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 24(DI)
	FMOVDP F0, F0
	FMOVDP F0, F0

	// [4] FCOMIP F1, F0 (a vs b, pops a) + [5] remaining ST(0) == b
	FMOVD b+8(FP), F0
	FMOVD a+0(FP), F0
	MOVQ $0xa92, AX
	PUSHQ AX
	POPFQ
	FCOMIP F1, F0
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 32(DI)
	FMOVDP F0, 40(DI)

	RET
