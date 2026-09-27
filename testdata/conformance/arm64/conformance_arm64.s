#include "textflag.h"

TEXT ·families(SB), NOSPLIT, $0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1
	MOVD 0(R1), R2
	MOVD 8(R1), R3

	BFI $8, R2, $16, R3
	MOVD R3, 0(R0)
	MOVD 8(R1), R3
	BFIW $4, R2, $8, R3
	MOVD R3, 8(R0)
	MOVD 8(R1), R3
	BFXIL $12, R2, $20, R3
	MOVD R3, 16(R0)
	MOVD 8(R1), R3
	BFXILW $12, R2, $12, R3
	MOVD R3, 24(R0)
	SBFIZ $8, R2, $16, R4
	MOVD R4, 32(R0)
	SBFIZW $4, R2, $12, R4
	MOVD R4, 40(R0)
	SBFX $12, R2, $20, R4
	MOVD R4, 48(R0)
	SBFXW $12, R2, $12, R4
	MOVD R4, 56(R0)
	UBFIZ $8, R2, $16, R4
	MOVD R4, 64(R0)
	UBFIZW $4, R2, $12, R4
	MOVD R4, 72(R0)
	UBFX $12, R2, $20, R4
	MOVD R4, 80(R0)
	UBFXW $12, R2, $12, R4
	MOVD R4, 88(R0)

	MOVD $5, R2
	MOVD $9, R3
	SUBS R2, R2, ZR
	CSEL EQ, R2, R3, R4
	MOVD R4, 96(R0)
	CSELW EQ, R2, R3, R4
	MOVD R4, 104(R0)
	CSINC NE, R2, R3, R4
	MOVD R4, 112(R0)
	CSINCW NE, R2, R3, R4
	MOVD R4, 120(R0)
	CSINV NE, R2, R3, R4
	MOVD R4, 128(R0)
	CSINVW NE, R2, R3, R4
	MOVD R4, 136(R0)
	CSNEG NE, R2, R3, R4
	MOVD R4, 144(R0)
	CSNEGW NE, R2, R3, R4
	MOVD R4, 152(R0)
	CSET EQ, R4
	MOVD R4, 160(R0)
	CSETW EQ, R4
	MOVD R4, 168(R0)
	CSETM EQ, R4
	MOVD R4, 176(R0)
	CSETMW EQ, R4
	MOVD R4, 184(R0)
	CINC EQ, R2, R4
	MOVD R4, 192(R0)
	CINCW EQ, R2, R4
	MOVD R4, 200(R0)
	CINV EQ, R2, R4
	MOVD R4, 208(R0)
	CINVW EQ, R2, R4
	MOVD R4, 216(R0)
	CNEG EQ, R2, R4
	MOVD R4, 224(R0)
	CNEGW EQ, R2, R4
	MOVD R4, 232(R0)

	MOVD 0(R1), R2
	REV R2, R4
	MOVD R4, 240(R0)
	REVW R2, R4
	MOVD R4, 248(R0)
	REV16 R2, R4
	MOVD R4, 256(R0)
	REV16W R2, R4
	MOVD R4, 264(R0)
	REV32 R2, R4
	MOVD R4, 272(R0)
	ASR $8, R2, R4
	MOVD R4, 280(R0)
	ASRW $8, R2, R4
	MOVD R4, 288(R0)
	LSL $8, R2, R4
	MOVD R4, 296(R0)
	LSLW $8, R2, R4
	MOVD R4, 304(R0)
	LSR $8, R2, R4
	MOVD R4, 312(R0)
	LSRW $8, R2, R4
	MOVD R4, 320(R0)
	ROR $8, R2, R4
	MOVD R4, 328(R0)
	RORW $8, R2, R4
	MOVD R4, 336(R0)
	MOVD $12, R5
	ASR R5, R2, R4
	MOVD R4, 344(R0)
	ASRW R5, R2, R4
	MOVD R4, 352(R0)
	LSL R5, R2, R4
	MOVD R4, 360(R0)
	LSLW R5, R2, R4
	MOVD R4, 368(R0)
	LSR R5, R2, R4
	MOVD R4, 376(R0)
	LSRW R5, R2, R4
	MOVD R4, 384(R0)
	ROR R5, R2, R4
	MOVD R4, 392(R0)
	RORW R5, R2, R4
	MOVD R4, 400(R0)

	SUBS R5.UXTB<<1, R2, R4
	MOVD R4, 408(R0)
	SUBSW R5.SXTB<<1, R2, R4
	MOVD R4, 416(R0)
	TST R5<<4, R2
	CSET EQ, R4
	MOVD R4, 424(R0)
	TSTW R5->3, R2
	CSET EQ, R4
	MOVD R4, 432(R0)

	MOVD $1, R5
	MOVH (R1)(R5<<1), R4
	MOVD R4, 440(R0)
	MOVHU (R1)(R5<<1), R4
	MOVD R4, 448(R0)
	MOVW (R1)(R5.UXTW<<2), R4
	MOVD R4, 456(R0)
	MOVWU (R1)(R5.UXTW<<2), R4
	MOVD R4, 464(R0)
	MOVB R2, R4
	MOVD R4, 472(R0)
	MOVBU R2, R4
	MOVD R4, 480(R0)

	FMOVQ (R1), F0
	FMOVQ F0, 488(R0)
	MOVD R1, R5
	FMOVQ.P 16(R5), F1
	FMOVQ F1, 504(R0)
	MOVD R1, R5
	FMOVQ.W 16(R5), F2
	FMOVQ F2, 520(R0)

	MOVD $0x89abcdef, R2
	MOVW R2, R4
	MOVD R4, 536(R0)
	MOVD $0x80000000, R2
	ANDSW R2, R2, R4
	CSET MI, R5
	MOVD R5, 544(R0)
	MOVD $0x100000000, R2
	MOVD $0, R3
	CMPW R2, R3
	CSET EQ, R4
	MOVD R4, 552(R0)
	CSET HS, R4
	MOVD R4, 560(R0)
	MOVD $1, R2
	MOVD $0x80000000, R3
	CMPW R2, R3
	CSET VS, R4
	MOVD R4, 568(R0)

	MOVW $0x89abcdef, R2
	MOVD R2, 576(R0)

	FMOVQ (R1), F3
	FMOVD F3, R2
	MOVD R2, 584(R0)

	FMOVQ (R1), F4
	MOVD $0x1234, R2
	FMOVD R2, F4
	FMOVQ F4, 592(R0)
	RET

// scalarFloatSquareRoots covers scalar S/D constants, F-register copies,
// F<->general-register bit moves, memory stores, and square roots.
TEXT ·scalarFloatSquareRoots(SB), NOSPLIT, $0-8
	MOVD out+0(FP), R0
	FMOVS $(4.0), F0
	FSQRTS F0, F1
	FMOVS F1, 0(R0)
	FMOVS F1, R1
	FMOVS R1, F2
	FMOVS F2, 4(R0)
	FMOVD $(16.0), F3
	FSQRTD F3, F4
	FMOVD F4, 8(R0)
	RET

// fusedMultiplyAddSemantics distinguishes all four sign variants and both
// scalar widths. In Go assembler order the operands are Fm, Fa, Fn, Fd.
TEXT ·fusedMultiplyAddSemantics(SB), NOSPLIT, $0-8
	MOVD out+0(FP), R0
	FMOVS $(2.0), F0
	FMOVS $(5.0), F1
	FMOVS $(3.0), F2
	FMADDS F0, F1, F2, F3
	FMSUBS F0, F1, F2, F4
	FNMADDS F0, F1, F2, F5
	FNMSUBS F0, F1, F2, F6
	FMOVS F3, 0(R0)
	FMOVS F4, 4(R0)
	FMOVS F5, 8(R0)
	FMOVS F6, 12(R0)

	FMOVD $(2.0), F10
	FMOVD $(5.0), F11
	FMOVD $(3.0), F12
	FMADDD F10, F11, F12, F13
	FMSUBD F10, F11, F12, F14
	FNMADDD F10, F11, F12, F15
	FNMSUBD F10, F11, F12, F16
	FMOVD F13, 16(R0)
	FMOVD F14, 24(R0)
	FMOVD F15, 32(R0)
	FMOVD F16, 40(R0)
	RET

// vectorPermuteSemantics fixes the Plan 9 Vm,Vn,Vd operand order and all six
// ZIP/UZP/TRN lane-selection variants with distinguishable byte inputs.
TEXT ·vectorPermuteSemantics(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R0
	MOVD n+8(FP), R1
	MOVD m+16(FP), R2
	FMOVQ (R1), F0
	FMOVQ (R2), F1
	VZIP1 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 0(R0)
	VZIP2 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 16(R0)
	VUZP1 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 32(R0)
	VUZP2 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 48(R0)
	VTRN1 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 64(R0)
	VTRN2 V1.B16, V0.B16, V2.B16
	FMOVQ F2, 80(R0)
	RET

// vectorWideningShiftSemantics distinguishes signed/unsigned extension,
// low/high source halves, and the immediate-shift forms of the family.
TEXT ·vectorWideningShiftSemantics(SB), NOSPLIT, $0-16
	MOVD out+0(FP), R0
	MOVD source+8(FP), R1
	FMOVQ (R1), F0
	VUXTL V0.B8, V1.H8
	FMOVQ F1, 0(R0)
	VUXTL2 V0.B16, V1.H8
	FMOVQ F1, 16(R0)
	VSXTL V0.B8, V1.H8
	FMOVQ F1, 32(R0)
	VSXTL2 V0.B16, V1.H8
	FMOVQ F1, 48(R0)
	VUSHLL $7, V0.B8, V1.H8
	FMOVQ F1, 64(R0)
	VUSHLL2 $1, V0.B16, V1.H8
	FMOVQ F1, 80(R0)
	VSSHLL $3, V0.B8, V1.H8
	FMOVQ F1, 96(R0)
	VSSHLL2 $2, V0.B16, V1.H8
	FMOVQ F1, 112(R0)
	RET

// scalarExtendSemantics distinguishes 64-bit and W-register destinations for
// every signed and unsigned scalar extend mnemonic in Go's shared optab row.
TEXT ·scalarExtendSemantics(SB), NOSPLIT, $0-16
	MOVD out+0(FP), R0
	MOVD value+8(FP), R1
	SXTB R1, R2
	MOVD R2, 0(R0)
	SXTBW R1, R2
	MOVD R2, 8(R0)
	SXTH R1, R2
	MOVD R2, 16(R0)
	SXTHW R1, R2
	MOVD R2, 24(R0)
	SXTW R1, R2
	MOVD R2, 32(R0)
	UXTB R1, R2
	MOVD R2, 40(R0)
	UXTBW R1, R2
	MOVD R2, 48(R0)
	UXTH R1, R2
	MOVD R2, 56(R0)
	UXTHW R1, R2
	MOVD R2, 64(R0)
	UXTW R1, R2
	MOVD R2, 72(R0)
	RET

TEXT ·vectorCountBitsSemantics(SB), NOSPLIT, $0-16
	MOVD out+0(FP), R0
	MOVD source+8(FP), R1
	FMOVQ (R1), F0
	VCNT V0.B8, V1.B8
	FMOVQ F1, 0(R0)
	VCNT V0.B16, V1.B16
	FMOVQ F1, 16(R0)
	RET

TEXT ·unsignedWideningAddSemantics(SB), NOSPLIT, $0-24
	MOVD out+0(FP), R0
	MOVD narrow+8(FP), R1
	MOVD addend+16(FP), R2
	FMOVQ (R1), F0
	FMOVQ (R2), F1
	VUADDW V0.B8, V1.H8, V2.H8
	FMOVQ F2, 0(R0)
	VUADDW V0.H4, V1.S4, V2.S4
	FMOVQ F2, 16(R0)
	VUADDW V0.S2, V1.D2, V2.D2
	FMOVQ F2, 32(R0)
	VUADDW2 V0.B16, V1.H8, V2.H8
	FMOVQ F2, 48(R0)
	VUADDW2 V0.H8, V1.S4, V2.S4
	FMOVQ F2, 64(R0)
	VUADDW2 V0.S4, V1.D2, V2.D2
	FMOVQ F2, 80(R0)
	RET

// pairedAtomicSemantics exercises success and failure paths for both CASP
// widths and for the load-exclusive/store-exclusive pair family.
TEXT ·pairedAtomicSemantics(SB), NOSPLIT, $0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1

	// CASPD success: compare registers receive the old memory pair and the
	// destination pair is installed.
	MOVD $0x11, R2
	MOVD $0x22, R3
	MOVD $0xaa, R4
	MOVD $0xbb, R5
	MOVD R1, R6
	CASPD (R2, R3), (R6), (R4, R5)
	MOVD R2, 0(R0)
	MOVD R3, 8(R0)
	MOVD 0(R6), R8
	MOVD R8, 16(R0)
	MOVD 8(R6), R8
	MOVD R8, 24(R0)

	// CASPD failure: memory is unchanged and the compare pair receives its
	// actual contents.
	MOVD $0x99, R2
	MOVD $0x88, R3
	MOVD $0xcc, R4
	MOVD $0xdd, R5
	ADD $16, R1, R6
	CASPD (R2, R3), (R6), (R4, R5)
	MOVD R2, 32(R0)
	MOVD R3, 40(R0)
	MOVD 0(R6), R8
	MOVD R8, 48(R0)
	MOVD 8(R6), R8
	MOVD R8, 56(R0)

	// CASPW compares the low 32 bits of each register and zero-extends the
	// loaded pair back into the compare registers.
	MOVD $0xffffffff00000011, R2
	MOVD $0xeeeeeeee00000022, R3
	MOVD $0xdddddddd000000aa, R4
	MOVD $0xcccccccc000000bb, R5
	ADD $32, R1, R6
	CASPW (R2, R3), (R6), (R4, R5)
	MOVD R2, 64(R0)
	MOVD R3, 72(R0)
	MOVD 0(R6), R8
	MOVD R8, 80(R0)

	MOVD $0xffffffff00000099, R2
	MOVD $0xeeeeeeee00000088, R3
	MOVD $0xdddddddd000000cc, R4
	MOVD $0xcccccccc000000dd, R5
	ADD $40, R1, R6
	CASPW (R2, R3), (R6), (R4, R5)
	MOVD R2, 88(R0)
	MOVD R3, 96(R0)
	MOVD 0(R6), R8
	MOVD R8, 104(R0)

	// A matching LDXP/STXP reservation succeeds.
	ADD $48, R1, R6
	LDXP (R6), (R2, R3)
	MOVD R2, 112(R0)
	MOVD R3, 120(R0)
	MOVD $0xcc, R4
	MOVD $0xdd, R5
	STXP (R4, R5), (R6), R7
	MOVD R7, 128(R0)
	MOVD 0(R6), R8
	MOVD R8, 136(R0)
	MOVD 8(R6), R8
	MOVD R8, 144(R0)

	// An intervening store invalidates an LDAXPW reservation, so STLXPW
	// reports failure and leaves the intervening value in memory.
	ADD $64, R1, R6
	LDAXPW (R6), (R2, R3)
	MOVD R2, 152(R0)
	MOVD R3, 160(R0)
	MOVD $0x000000aa00000099, R8
	MOVD R8, 0(R6)
	MOVD $0xcc, R4
	MOVD $0xdd, R5
	STLXPW (R4, R5), (R6), R7
	MOVD R7, 168(R0)
	MOVD 0(R6), R8
	MOVD R8, 176(R0)
	RET
