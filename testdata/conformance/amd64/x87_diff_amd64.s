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

// diffX87TopStatus verifies architectural x87 stack TOP pointer (bits 13:11,
// mask 0x3800) via FSTSW AX across FINIT, pushes, FMOVD Fi,F0, FTST/FCOMD
// (preserving TOP while updating C3/C2/C1/C0), FCLEX, pops, FCOMDPP double-pop,
// FDECSTP, FINCSTP, and 8-push wraparound.
TEXT ·diffX87TopStatus(SB), NOSPLIT, $0-8
	MOVQ out+0(FP), DI

	// [0] FINIT -> TOP = 0 (0x0000)
	FINIT
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 0(DI)

	// [1] FLD1 -> TOP = 7 (0x3800) [Round 11 P1 #1 counterexample]
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 8(DI)

	// [2] FLDZ -> TOP = 6 (0x3000)
	FLDZ
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 16(DI)

	// [3] FMOVD F1, F0 (FLD ST(1), pushes 1.0) -> TOP = 5 (0x2800)
	FMOVD F1, F0
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 24(DI)

	// [4] FXCHD F0, F1 (F0=0.0, F1=1.0); FTST -> C3=1 (0x4000) + TOP=5 (0x2800) = 0x6800
	FXCHD F0, F1
	FTST
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x7f00, AX
	MOVQ AX, 32(DI)

	// [5] FCOMD F1, F0 (0.0 < 1.0) -> C0=1 (0x0100) + TOP=5 (0x2800) = 0x2900
	FCOMD F1, F0
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x7f00, AX
	MOVQ AX, 40(DI)

	// [6] FCLEX preserves TOP=5 (0x2800)
	FCLEX
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 48(DI)

	// [7] FMOVDP F0, F0 (pop 1) -> TOP = 6 (0x3000)
	FMOVDP F0, F0
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 56(DI)

	// [8] FCOMDPP F0, F1 (pop 2) -> TOP = 0 (0x0000)
	FCOMDPP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 64(DI)

	// [9] FDECSTP -> TOP = 7 (0x3800)
	FDECSTP
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 72(DI)

	// [10] FINCSTP -> TOP = 0 (0x0000)
	FINCSTP
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 80(DI)

	// [11] 8 pushes wrap TOP modulo 8 back to 0 (0x0000)
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	MOVQ AX, 88(DI)

	FINIT
	RET

// diffX87Binary80Precision verifies true 64-bit significand binary80 precision
// across FADDDP, FSUBDP, FMULDP, FDIVDP, and FSQRT in BOTH X87Hardware and
// X87Software modes (starting with FINIT so CW = 0x037f on Linux and Windows).
TEXT ·diffX87Binary80Precision(SB), NOSPLIT, $24-16
	MOVQ outInt+0(FP), DI
	MOVQ outRaw80+8(FP), SI
	FINIT

	// outInt[0]: 2^53 + 1 = 9007199254740993 [Round 11 P1 #2 counterexample]
	MOVQ $0x0020000000000000, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FLD1
	FADDDP F0, F1
	FMOVVP F0, 0(DI)

	// outInt[1]: 2^62 + 1 = 4611686018427387905
	MOVQ $0x4000000000000000, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FLD1
	FADDDP F0, F1
	FMOVVP F0, 8(DI)

	// outInt[2]: 2^62 - 1 = 4611686018427387903
	MOVQ $0x4000000000000000, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FLD1
	FSUBDP F0, F1
	FMOVVP F0, 16(DI)

	// outInt[3]: (2^53 + 1) * 3 = 27021597764222979
	MOVQ $9007199254740993, AX
	MOVQ AX, 0(SP)
	MOVQ $3, BX
	MOVQ BX, 8(SP)
	FMOVV 0(SP), F0
	FMOVV 8(SP), F0
	FMULDP F0, F1
	FMOVVP F0, 24(DI)

	// outInt[4]: (2^60 + 2) / 3 = 384307168202282326
	MOVQ $0x1000000000000002, AX
	MOVQ AX, 0(SP)
	MOVQ $3, BX
	MOVQ BX, 8(SP)
	FMOVV 0(SP), F0
	FMOVV 8(SP), F0
	FDIVDP F0, F1
	FMOVVP F0, 32(DI)

	// outInt[5]: sqrt(2^62) = 2^31 = 2147483648
	MOVQ $0x4000000000000000, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FSQRT
	FMOVVP F0, 40(DI)

	// outRaw80[0..9]: 1 / 3 in full 80-bit binary80
	FLD1
	MOVQ $3, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FDIVDP F0, F1
	FMOVXP F0, 0(SI)

	// outRaw80[10..19]: sqrt(2) in full 80-bit binary80
	MOVQ $2, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FSQRT
	FMOVXP F0, 10(SI)

	// outRaw80[20..29]: sqrt(3) in full 80-bit binary80
	MOVQ $3, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FSQRT
	FMOVXP F0, 20(SI)

	// outRaw80[30..39]: pi + log2(e) in full 80-bit binary80
	FLDPI
	FLDL2E
	FADDDP F0, F1
	FMOVXP F0, 30(SI)

	// outRaw80[40..49]: pi * ln(2) in full 80-bit binary80
	FLDPI
	FLDLN2
	FMULDP F0, F1
	FMOVXP F0, 40(SI)

	// outRaw80[50..59]: 1 - 2^-63 in full 80-bit binary80
	FLD1
	FLD1
	MOVQ $0x4000000000000000, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FDIVDP F0, F1
	MOVQ $2, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FDIVDP F0, F1
	FSUBDP F0, F1
	FMOVXP F0, 50(SI)

	RET

// diffX87Exceptions verifies sticky x87 arithmetic exception flags (IE=0x01,
// DE=0x02, ZE=0x04, OE=0x08, UE=0x10, PE=0x20) plus non-sticky C1 (0x0200) and
// TOP (0x3800) via FSTSW AX across FDIVDP, FADDDP, FMULDP, FSQRT, and FCLEX
// in BOTH X87Hardware and X87Software modes (Round 12 P1 #1).
TEXT ·diffX87Exceptions(SB), NOSPLIT, $24-8
	MOVQ out+0(FP), DI

	// [0] 1 / 0 -> ZE (0x04) + TOP=7 (0x3800) = 0x3804
	FINIT
	FLD1
	FLDZ
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x383f, AX
	MOVQ AX, 0(DI)

	// [1] 0 / 0 -> IE (0x01) + TOP=7 (0x3800) = 0x3801
	FINIT
	FLDZ
	FLDZ
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x383f, AX
	MOVQ AX, 8(DI)

	// [2] 1 / 3 -> PE (0x20) + C1 (0x0200, rounded up) + TOP=7 (0x3800) = 0x3a20
	FINIT
	FLD1
	MOVQ $3, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3a3f, AX
	MOVQ AX, 16(DI)

	// [3] Sticky persistence: ZE from 1/0 persists across exact 1+1=2 while C1 clears -> 0x0004
	FINIT
	FLD1
	FLDZ
	FDIVDP F0, F1
	FMOVDP F0, F0
	FLD1
	FLD1
	FADDDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 24(DI)

	// [4] FCLEX clears sticky exceptions while preserving TOP=7 -> 0x3800
	FCLEX
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x383f, AX
	MOVQ AX, 32(DI)

	// [5] FSQRT(-1.0) -> IE (0x01)
	FINIT
	FLD1
	FCHS
	FSQRT
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x003f, AX
	MOVQ AX, 40(DI)

	// [6] FSQRT(2.0) -> PE (0x20), rounds down (C1=0) -> 0x0020
	FINIT
	MOVQ $2, AX
	MOVQ AX, 0(SP)
	FMOVV 0(SP), F0
	FSQRT
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 48(DI)

	// [7] Overflow: maxFinite * 2.0 -> C1 (0x0200) | OE (0x08) | PE (0x20) = 0x0228
	FINIT
	MOVQ $-1, AX
	MOVQ AX, 0(SP)
	MOVQ $0x7ffe, AX
	MOVW AX, 8(SP)
	FMOVX 0(SP), F0
	FLD1
	FLD1
	FADDDP F0, F1
	FMULDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 56(DI)

	// [8] Underflow: minNormal / 3.0 -> C1 (0x0200) | UE (0x10) | PE (0x20) = 0x0230
	FINIT
	MOVQ $0x8000000000000000, AX
	MOVQ AX, 0(SP)
	MOVQ $0x0001, AX
	MOVW AX, 8(SP)
	FMOVX 0(SP), F0
	MOVQ $3, AX
	MOVQ AX, 16(SP)
	FMOVV 16(SP), F0
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 64(DI)

	// [9] Denormal operand: smallestSubnormal + 1.0 -> DE (0x02) | PE (0x20), C1=0 -> 0x0022
	FINIT
	MOVQ $1, AX
	MOVQ AX, 0(SP)
	MOVQ $0, AX
	MOVW AX, 8(SP)
	FMOVX 0(SP), F0
	FLD1
	FADDDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 72(DI)

	FINIT
	RET

// diffX87ConstRoundingModes verifies all 7 FLD* constants (FLD1, FLDZ, FLDPI,
// FLDL2E, FLDL2T, FLDLG2, FLDLN2) stored as raw 10-byte extended values via
// FMOVXP under all 4 FLDCW rounding control modes: RN (0x037f), RD (0x077f),
// RU (0x0b7f), and RZ (0x0f7f) (Round 12 P1 #2).
TEXT ·diffX87ConstRoundingModes(SB), NOSPLIT, $16-8
	MOVQ outRaw80+0(FP), DI
	FINIT

	// Mode 0: RN (CW = 0x037f) -> outRaw80[0..69]
	MOVQ $0x037f, AX
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLD1
	FMOVXP F0, 0(DI)
	FLDZ
	FMOVXP F0, 10(DI)
	FLDPI
	FMOVXP F0, 20(DI)
	FLDL2E
	FMOVXP F0, 30(DI)
	FLDL2T
	FMOVXP F0, 40(DI)
	FLDLG2
	FMOVXP F0, 50(DI)
	FLDLN2
	FMOVXP F0, 60(DI)

	// Mode 1: RD (CW = 0x077f) -> outRaw80[70..139]
	MOVQ $0x077f, AX
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLD1
	FMOVXP F0, 70(DI)
	FLDZ
	FMOVXP F0, 80(DI)
	FLDPI
	FMOVXP F0, 90(DI)
	FLDL2E
	FMOVXP F0, 100(DI)
	FLDL2T
	FMOVXP F0, 110(DI)
	FLDLG2
	FMOVXP F0, 120(DI)
	FLDLN2
	FMOVXP F0, 130(DI)

	// Mode 2: RU (CW = 0x0b7f) -> outRaw80[140..209]
	MOVQ $0x0b7f, AX
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLD1
	FMOVXP F0, 140(DI)
	FLDZ
	FMOVXP F0, 150(DI)
	FLDPI
	FMOVXP F0, 160(DI)
	FLDL2E
	FMOVXP F0, 170(DI)
	FLDL2T
	FMOVXP F0, 180(DI)
	FLDLG2
	FMOVXP F0, 190(DI)
	FLDLN2
	FMOVXP F0, 200(DI)

	// Mode 3: RZ (CW = 0x0f7f) -> outRaw80[210..279]
	MOVQ $0x0f7f, AX
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FLD1
	FMOVXP F0, 210(DI)
	FLDZ
	FMOVXP F0, 220(DI)
	FLDPI
	FMOVXP F0, 230(DI)
	FLDL2E
	FMOVXP F0, 240(DI)
	FLDL2T
	FMOVXP F0, 250(DI)
	FLDLG2
	FMOVXP F0, 260(DI)
	FLDLN2
	FMOVXP F0, 270(DI)

	FINIT
	RET

// diffX87BCDOne loads a raw 10-byte binary80 value via FMOVX, stores 10-byte
// packed BCD via FMOVBP under caller-specified FLDCW cw, and records FSTSW
// (TOP|C1|IE|DE|ZE|OE|UE|PE = 0x3a3f).
TEXT ·diffX87BCDOne(SB), NOSPLIT, $16-32
	MOVQ cw+0(FP), AX
	MOVQ inRaw80+8(FP), SI
	MOVQ outBCD+16(FP), DI
	MOVQ outSW+24(FP), DX
	FINIT
	MOVW AX, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVBP F0, 0(DI)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3a3f, AX
	MOVQ AX, 0(DX)
	FINIT
	RET

// diffX87ConvInt converts a raw 10-byte binary80 value via FMOVWP (i16),
// FMOVLP (i32), and FMOVVP (i64) under caller-specified FLDCW cw, capturing
// each converted value and its isolated FSTSW (C1|IE..PE = 0x023f).
TEXT ·diffX87ConvInt(SB), NOSPLIT, $16-32
	MOVQ cw+0(FP), R9
	MOVQ inRaw80+8(FP), SI
	MOVQ outVals+16(FP), DX
	MOVQ outSW+24(FP), R8

	// [0] i16 via FMOVWP
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVWP F0, 8(SP)
	MOVWQZX 8(SP), AX
	MOVQ AX, 0(DX)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 0(R8)

	// [1] i32 via FMOVLP
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVLP F0, 8(SP)
	MOVLQZX 8(SP), AX
	MOVQ AX, 8(DX)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 8(R8)

	// [2] i64 via FMOVVP
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVVP F0, 16(DX)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 16(R8)

	FINIT
	RET

// diffX87ConvFloat converts a raw 10-byte binary80 value via FMOVFP (f32),
// FMOVDP (f64), and FRNDINT (10-byte raw binary80) under caller-specified
// FLDCW cw, capturing each output and its isolated FSTSW (C1|IE..PE = 0x023f).
TEXT ·diffX87ConvFloat(SB), NOSPLIT, $16-48
	MOVQ cw+0(FP), R9
	MOVQ inRaw80+8(FP), SI
	MOVQ outF32+16(FP), DX
	MOVQ outF64+24(FP), CX
	MOVQ outRnd80+32(FP), R8
	MOVQ outSW+40(FP), R10

	// [0] f32 via FMOVFP
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVFP F0, 0(DX)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 0(R10)

	// [1] f64 via FMOVDP
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVDP F0, 0(CX)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 8(R10)

	// [2] FRNDINT -> read FSTSW BEFORE FMOVXP (which clears C1)
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FRNDINT
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 16(R10)
	FMOVXP F0, 0(R8)

	FINIT
	RET

// diffX87ArithPC executes FADDDP, FSUBDP, FMULDP, FDIVDP, and FSQRT(a) on raw
// 10-byte binary80 inputs under caller-specified FLDCW cw (covering all 3 PC x
// 4 RC modes), recording all 5 raw 10-byte results and isolated FSTSW (0x023f).
TEXT ·diffX87ArithPC(SB), NOSPLIT, $16-40
	MOVQ cw+0(FP), R9
	MOVQ aRaw80+8(FP), SI
	MOVQ bRaw80+16(FP), DI
	MOVQ outRaw80+24(FP), R8
	MOVQ outSW+32(FP), R10

	// [0] a + b
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVX 0(DI), F0
	FADDDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 0(R10)
	FMOVXP F0, 0(R8)

	// [1] a - b
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVX 0(DI), F0
	FSUBDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 8(R10)
	FMOVXP F0, 10(R8)

	// [2] a * b
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVX 0(DI), F0
	FMULDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 16(R10)
	FMOVXP F0, 20(R8)

	// [3] a / b
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FMOVX 0(DI), F0
	FDIVDP F0, F1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 24(R10)
	FMOVXP F0, 30(R8)

	// [4] sqrt(a)
	FINIT
	MOVW R9, 0(SP)
	FLDCW 0(SP)
	FMOVX 0(SI), F0
	FSQRT
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 32(R10)
	FMOVXP F0, 40(R8)

	FINIT
	RET

// diffX87Cmp executes FCOMD, FUCOM, FCOMI, FUCOMI, and FTST on raw 10-byte
// binary80 inputs, capturing both condition codes (C3/C2/C1/C0 or RFLAGS
// OF/SF/ZF/AF/PF/CF) and sticky x87 exceptions (IE/DE) in FSTSW.
TEXT ·diffX87Cmp(SB), NOSPLIT, $0-32
	MOVQ aRaw80+0(FP), SI
	MOVQ bRaw80+8(FP), DI
	MOVQ outCC+16(FP), R8
	MOVQ outExc+24(FP), R10

	// [0] FCOMD F1, F0 (ST(0)=a vs ST(1)=b)
	FINIT
	FMOVX 0(DI), F0
	FMOVX 0(SI), F0
	FCOMD F1, F0
	MOVQ $0, AX
	FSTSW AX
	MOVQ AX, BX
	ANDQ $0x4700, AX
	MOVQ AX, 0(R8)
	ANDQ $0x003f, BX
	MOVQ BX, 0(R10)

	// [1] FUCOM F0, F1 (ST(0)=a vs ST(1)=b)
	FINIT
	FMOVX 0(DI), F0
	FMOVX 0(SI), F0
	FUCOM F0, F1
	MOVQ $0, AX
	FSTSW AX
	MOVQ AX, BX
	ANDQ $0x4700, AX
	MOVQ AX, 8(R8)
	ANDQ $0x003f, BX
	MOVQ BX, 8(R10)

	// [2] FCOMI F1, F0 (ST(0)=a vs ST(1)=b, OF/SF/AF pre-set to 1)
	FINIT
	FMOVX 0(DI), F0
	FMOVX 0(SI), F0
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
	MOVQ AX, 16(R8)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 16(R10)

	// [3] FUCOMI F0, F1 (ST(0)=a vs ST(1)=b, OF/SF/AF pre-set to 1)
	FINIT
	FMOVX 0(DI), F0
	FMOVX 0(SI), F0
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
	MOVQ AX, 24(R8)
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x023f, AX
	MOVQ AX, 24(R10)

	// [4] FTST (ST(0)=a vs 0.0)
	FINIT
	FMOVX 0(SI), F0
	FTST
	MOVQ $0, AX
	FSTSW AX
	MOVQ AX, BX
	ANDQ $0x4700, AX
	MOVQ AX, 32(R8)
	ANDQ $0x003f, BX
	MOVQ BX, 32(R10)

	FINIT
	RET

// diffX87DynamicStackBranch verifies non-overflowing fixed-8 and dynamic
// CFG-joined x87 stack depths (both branch polarities and FFREE F7 clearing
// ST(7)'s tag before join), recording FSTSW TOP|SF|IE (0x3841) or SF|IE (0x0041).
TEXT ·diffX87DynamicStackBranch(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	MOVQ out+8(FP), DI

	// [0] Fixed 8 pushes -> TOP=0, SF=0, IE=0 (0x0000)
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3841, AX
	MOVQ AX, 0(DI)

	// [1] Dynamic 6/7 + 1 pushes (if x != 0 extra push) -> x=0: 7 pushes (TOP=1 -> 0x0800); x!=0: 8 pushes (TOP=0 -> 0x0000)
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE dyn1_skip
	FLD1
dyn1_skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3841, AX
	MOVQ AX, 8(DI)

	// [2] Swapped dynamic 6/7 + 1 pushes (if x == 0 extra push) -> x=0: 8 pushes (0x0000); x!=0: 7 pushes (0x0800)
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JNE dyn2_skip
	FLD1
dyn2_skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3841, AX
	MOVQ AX, 16(DI)

	// [3] Dynamic 7/8 with FMOVDP F0, F0 pop on the 8-push branch before join + 1 push -> 8 pushes on both paths (TOP=0, SF=0, IE=0 -> 0x0000)
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE dyn3_skip
	FLD1
	FMOVDP F0, F0
dyn3_skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3841, AX
	MOVQ AX, 24(DI)

	FINIT
	RET
