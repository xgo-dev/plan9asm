#include "textflag.h"

DATA ·goHexORMask<>+0(SB)/8, $0x4020100804020180
DATA ·goHexORMask<>+8(SB)/8, $0xcc33f00faa5500ff
GLOBL ·goHexORMask<>(SB), RODATA|NOPTR, $16

TEXT ·byteMemory(SB), NOSPLIT, $0-9
	MOVQ p+0(FP), AX
	MOVBLZX value+8(FP), SI
	ADDB SI, (AX)
	ADDQ $1, AX
	XORB SI, (AX)
	ADDQ $1, AX
	ANDB SI, (AX)
	ADDQ $1, AX
	ORB SI, (AX)
	RET

TEXT ·byteFlags(SB), NOSPLIT, $0-16
	MOVQ p+0(FP), AX
	MOVQ flags+8(FP), BX
	ADDB $1, (AX)
	SETCS 0(BX)
	SETEQ 1(BX)
	XORB $0xff, 1(AX)
	SETCS 2(BX)
	SETEQ 3(BX)
	ANDB $0, 2(AX)
	SETCS 4(BX)
	SETEQ 5(BX)
	ORB $0x80, 3(AX)
	SETCS 6(BX)
	SETLT 7(BX)
	RET

TEXT ·unpackLowQWords(SB), NOSPLIT, $0-16
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVOU (AX), X0
	PUNPCKLQDQ (BX), X0
	MOVOU X0, (AX)
	RET

TEXT ·unpackDuplicateLowQWord(SB), NOSPLIT, $0-8
	MOVQ dst+0(FP), AX
	MOVOU (AX), X0
	PUNPCKLQDQ X0, X0
	MOVOU X0, (AX)
	RET

TEXT ·shiftLegacyThreeOperand(SB), NOSPLIT, $0-20
	MOVL src+0(FP), AX
	MOVL dst+4(FP), R11
	MOVL amount+8(FP), CX
	SHLL CX, R11:AX
	MOVL R11, ret+16(FP)
	RET

TEXT ·clearTopBit(SB), NOSPLIT, $0-16
	MOVQ value+0(FP), AX
	BTRQ $63, AX
	MOVQ AX, ret+8(FP)
	RET

TEXT ·doubleShift32(SB), NOSPLIT, $0-20
	MOVQ out+0(FP), DI
	MOVL src+8(FP), AX
	MOVL dst+12(FP), R11
	MOVL amount+16(FP), CX
	SHLL CL, AX, R11
	MOVL R11, 0(DI)
	MOVL dst+12(FP), R11
	SHLL $7, AX, R11
	MOVL R11, 4(DI)
	LEAQ 8(DI), BX
	MOVL dst+12(FP), R11
	MOVL R11, (BX)
	SHLL CL, AX, (BX)
	LEAQ 12(DI), BX
	MOVL dst+12(FP), R11
	MOVL R11, (BX)
	SHLL $7, AX, (BX)
	MOVL dst+12(FP), R11
	SHRL CL, AX, R11
	MOVL R11, 16(DI)
	MOVL dst+12(FP), R11
	SHRL $7, AX, R11
	MOVL R11, 20(DI)
	LEAQ 24(DI), BX
	MOVL dst+12(FP), R11
	MOVL R11, (BX)
	SHRL CL, AX, (BX)
	LEAQ 28(DI), BX
	MOVL dst+12(FP), R11
	MOVL R11, (BX)
	SHRL $7, AX, (BX)
	RET

TEXT ·doubleShift64(SB), NOSPLIT, $0-32
	MOVQ out+0(FP), DI
	MOVQ src+8(FP), AX
	MOVQ dst+16(FP), R11
	MOVQ amount+24(FP), CX
	SHLQ CL, AX, R11
	MOVQ R11, 0(DI)
	MOVQ dst+16(FP), R11
	SHLQ $7, AX, R11
	MOVQ R11, 8(DI)
	LEAQ 16(DI), BX
	MOVQ dst+16(FP), R11
	MOVQ R11, (BX)
	SHLQ CL, AX, (BX)
	LEAQ 24(DI), BX
	MOVQ dst+16(FP), R11
	MOVQ R11, (BX)
	SHLQ $7, AX, (BX)
	MOVQ dst+16(FP), R11
	SHRQ CL, AX, R11
	MOVQ R11, 32(DI)
	MOVQ dst+16(FP), R11
	SHRQ $7, AX, R11
	MOVQ R11, 40(DI)
	LEAQ 48(DI), BX
	MOVQ dst+16(FP), R11
	MOVQ R11, (BX)
	SHRQ CL, AX, (BX)
	LEAQ 56(DI), BX
	MOVQ dst+16(FP), R11
	MOVQ R11, (BX)
	SHRQ $7, AX, (BX)
	RET

// scalarShiftRotateSemantics covers the scalar B/W/L/Q family, rotations,
// memory destinations, and the Go assembler's W-width double-shift forms.
TEXT ·scalarShiftRotateSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ value+8(FP), BX
	MOVQ count+16(FP), CX

	MOVQ BX, AX
	ROLB CL, AL
	MOVQ AX, 0(DI)
	MOVQ BX, AX
	RORB CL, AL
	MOVQ AX, 8(DI)
	MOVQ BX, AX
	SARB CL, AL
	MOVQ AX, 16(DI)
	MOVQ BX, AX
	SHRB CL, AL
	MOVQ AX, 24(DI)

	MOVQ BX, AX
	ROLW CX, AX
	MOVQ AX, 32(DI)
	MOVQ BX, AX
	SARW CL, AX
	MOVQ AX, 40(DI)
	MOVQ BX, AX
	SHLL CX, AX
	MOVQ AX, 48(DI)
	MOVQ BX, AX
	RORQ CL, AX
	MOVQ AX, 56(DI)

	MOVQ BX, 64(DI)
	SHRB CL, 64(DI)
	MOVQ BX, 72(DI)
	ROLW CX, 72(DI)

	MOVQ BX, AX
	MOVQ $0xfedcba9876543210, DX
	SHLW CL, AX, DX
	MOVQ DX, 80(DI)
	MOVQ BX, AX
	MOVQ $0xfedcba9876543210, DX
	SHRW CX, AX, DX
	MOVQ DX, 88(DI)

	MOVQ BX, AX
	SALB $3, AL
	MOVQ AX, 96(DI)
	MOVQ BX, AX
	SARL $3, AX
	MOVQ AX, 104(DI)
	RET

// incDecSemantics validates every width, register and memory destinations,
// 32-bit zero extension, and the INC/DEC flag contract (including preserved CF).
TEXT ·incDecSemantics(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ value+8(FP), BX
	MOVQ BX, AX
	INCB AL
	MOVQ AX, 0(DI)
	MOVQ BX, AX
	DECB AL
	MOVQ AX, 8(DI)
	MOVQ BX, AX
	INCW AX
	MOVQ AX, 16(DI)
	MOVQ BX, AX
	DECW AX
	MOVQ AX, 24(DI)
	MOVQ BX, AX
	INCL AX
	MOVQ AX, 32(DI)
	MOVQ BX, AX
	DECL AX
	MOVQ AX, 40(DI)
	MOVQ BX, AX
	INCQ AX
	MOVQ AX, 48(DI)
	MOVQ BX, AX
	DECQ AX
	MOVQ AX, 56(DI)
	MOVQ BX, 64(DI)
	INCB 64(DI)
	MOVQ BX, 72(DI)
	DECW 72(DI)

	MOVQ $0, 80(DI)
	MOVQ $0, AX
	SUBQ $1, AX
	MOVQ $0x7f, AX
	INCB AL
	SETCS 80(DI)
	SETOS 81(DI)
	SETMI 82(DI)
	SETEQ 83(DI)
	SETPS 84(DI)

	MOVQ $0, 88(DI)
	MOVQ $1, AX
	DECB AL
	SETCS 88(DI)
	SETOS 89(DI)
	SETMI 90(DI)
	SETEQ 91(DI)
	SETPS 92(DI)
	RET

// scalarAddSubSemantics validates every scalar width, register and memory
// destinations, partial-register preservation, L-register zero extension,
// imm32 sign extension for Q, and all arithmetic condition flags.
TEXT ·scalarAddSubSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ value+8(FP), BX
	MOVQ source+16(FP), CX

	MOVQ BX, AX
	ADDB CL, AL
	MOVQ AX, 0(DI)
	MOVQ $0, 8(DI)
	SETCS 8(DI)
	SETOS 9(DI)
	SETEQ 10(DI)
	SETMI 11(DI)
	SETPS 12(DI)

	MOVQ BX, 16(DI)
	SUBB $4294967295, 16(DI)
	MOVQ $0, 24(DI)
	SETCS 24(DI)
	SETOS 25(DI)
	SETEQ 26(DI)
	SETMI 27(DI)
	SETPS 28(DI)

	MOVQ BX, AX
	ADDW CX, AX
	MOVQ AX, 32(DI)
	MOVQ $0, 40(DI)
	SETCS 40(DI)
	SETOS 41(DI)
	SETEQ 42(DI)
	SETMI 43(DI)
	SETPS 44(DI)

	MOVQ BX, 48(DI)
	SUBW $4294967295, 48(DI)
	MOVQ $0, 56(DI)
	SETCS 56(DI)
	SETOS 57(DI)
	SETEQ 58(DI)
	SETMI 59(DI)
	SETPS 60(DI)

	MOVQ BX, AX
	ADDL CX, AX
	MOVQ AX, 64(DI)
	MOVQ $0, 72(DI)
	SETCS 72(DI)
	SETOS 73(DI)
	SETEQ 74(DI)
	SETMI 75(DI)
	SETPS 76(DI)

	MOVQ BX, 80(DI)
	SUBL $4294967295, 80(DI)
	MOVQ $0, 88(DI)
	SETCS 88(DI)
	SETOS 89(DI)
	SETEQ 90(DI)
	SETMI 91(DI)
	SETPS 92(DI)

	MOVQ BX, AX
	ADDQ CX, AX
	MOVQ AX, 96(DI)
	MOVQ $0, 104(DI)
	SETCS 104(DI)
	SETOS 105(DI)
	SETEQ 106(DI)
	SETMI 107(DI)
	SETPS 108(DI)

	MOVQ BX, 112(DI)
	SUBQ $4294967295, 112(DI)
	MOVQ $0, 120(DI)
	SETCS 120(DI)
	SETOS 121(DI)
	SETEQ 122(DI)
	SETMI 123(DI)
	SETPS 124(DI)
	RET

// compareExchangeScalarSemantics executes success and failure cases for all
// four widths. Each case records destination, accumulator, then CF/OF/ZF/SF/PF.
TEXT ·compareExchangeScalarSemantics(SB), NOSPLIT, $0-32
	MOVQ out+0(FP), DI
	MOVQ memory+8(FP), SI
	MOVQ expected+16(FP), BX
	MOVQ desired+24(FP), CX

	MOVQ BX, AX
	CMPXCHGB CL, 0(SI)
	MOVQ 0(SI), DX
	MOVQ DX, 0(DI)
	MOVQ AX, 8(DI)
	MOVQ $0, 16(DI)
	SETCS 16(DI)
	SETOS 17(DI)
	SETEQ 18(DI)
	SETMI 19(DI)
	SETPS 20(DI)
	MOVQ BX, AX
	CMPXCHGB CL, 8(SI)
	MOVQ 8(SI), DX
	MOVQ DX, 24(DI)
	MOVQ AX, 32(DI)
	MOVQ $0, 40(DI)
	SETCS 40(DI)
	SETOS 41(DI)
	SETEQ 42(DI)
	SETMI 43(DI)
	SETPS 44(DI)

	MOVQ BX, AX
	CMPXCHGW CX, 16(SI)
	MOVQ 16(SI), DX
	MOVQ DX, 48(DI)
	MOVQ AX, 56(DI)
	MOVQ $0, 64(DI)
	SETCS 64(DI)
	SETOS 65(DI)
	SETEQ 66(DI)
	SETMI 67(DI)
	SETPS 68(DI)
	MOVQ BX, AX
	CMPXCHGW CX, 24(SI)
	MOVQ 24(SI), DX
	MOVQ DX, 72(DI)
	MOVQ AX, 80(DI)
	MOVQ $0, 88(DI)
	SETCS 88(DI)
	SETOS 89(DI)
	SETEQ 90(DI)
	SETMI 91(DI)
	SETPS 92(DI)

	MOVQ BX, AX
	CMPXCHGL CX, 32(SI)
	MOVQ 32(SI), DX
	MOVQ DX, 96(DI)
	MOVQ AX, 104(DI)
	MOVQ $0, 112(DI)
	SETCS 112(DI)
	SETOS 113(DI)
	SETEQ 114(DI)
	SETMI 115(DI)
	SETPS 116(DI)
	MOVQ BX, AX
	CMPXCHGL CX, 40(SI)
	MOVQ 40(SI), DX
	MOVQ DX, 120(DI)
	MOVQ AX, 128(DI)
	MOVQ $0, 136(DI)
	SETCS 136(DI)
	SETOS 137(DI)
	SETEQ 138(DI)
	SETMI 139(DI)
	SETPS 140(DI)

	MOVQ BX, AX
	CMPXCHGQ CX, 48(SI)
	MOVQ 48(SI), DX
	MOVQ DX, 144(DI)
	MOVQ AX, 152(DI)
	MOVQ $0, 160(DI)
	SETCS 160(DI)
	SETOS 161(DI)
	SETEQ 162(DI)
	SETMI 163(DI)
	SETPS 164(DI)
	MOVQ BX, AX
	CMPXCHGQ CX, 56(SI)
	MOVQ 56(SI), DX
	MOVQ DX, 168(DI)
	MOVQ AX, 176(DI)
	MOVQ $0, 184(DI)
	SETCS 184(DI)
	SETOS 185(DI)
	SETEQ 186(DI)
	SETMI 187(DI)
	SETPS 188(DI)
	RET

// compareExchangePairSemantics validates CMPXCHG8B and CMPXCHG16B, including
// accumulator preservation on success and replacement on failure.
TEXT ·compareExchangePairSemantics(SB), NOSPLIT, $0-48
	MOVQ out+0(FP), DI
	MOVQ memory+8(FP), SI
	MOVQ expectedLow+16(FP), AX
	MOVQ expectedHigh+24(FP), DX
	MOVQ desiredLow+32(FP), BX
	MOVQ desiredHigh+40(FP), CX
	CMPXCHG8B 16(SI)
	MOVQ 16(SI), R8
	MOVQ R8, 0(DI)
	MOVQ AX, 8(DI)
	MOVQ DX, 16(DI)
	MOVQ $0, 24(DI)
	SETEQ 24(DI)

	MOVQ expectedLow+16(FP), AX
	MOVQ expectedHigh+24(FP), DX
	MOVQ desiredLow+32(FP), BX
	MOVQ desiredHigh+40(FP), CX
	CMPXCHG16B 0(SI)
	MOVQ 0(SI), R8
	MOVQ 8(SI), R9
	MOVQ R8, 32(DI)
	MOVQ R9, 40(DI)
	MOVQ AX, 48(DI)
	MOVQ DX, 56(DI)
	MOVQ $0, 64(DI)
	SETEQ 64(DI)
	RET

// parallelBitSemantics validates PDEP/PEXT L/Q semantics, register and memory
// mask forms, sparse masks, and the required zero extension of L results.
TEXT ·parallelBitSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ mask+8(FP), AX
	MOVQ source+16(FP), BX
	PDEPQ AX, BX, CX
	MOVQ CX, 0(DI)
	PDEPQ mask+8(FP), BX, CX
	MOVQ CX, 8(DI)
	PEXTQ AX, BX, CX
	MOVQ CX, 16(DI)
	PEXTQ mask+8(FP), BX, CX
	MOVQ CX, 24(DI)
	MOVQ $-1, CX
	PDEPL AX, BX, CX
	MOVQ CX, 32(DI)
	MOVQ $-1, CX
	PDEPL mask+8(FP), BX, CX
	MOVQ CX, 40(DI)
	MOVQ $-1, CX
	PEXTL AX, BX, CX
	MOVQ CX, 48(DI)
	MOVQ $-1, CX
	PEXTL mask+8(FP), BX, CX
	MOVQ CX, 56(DI)
	RET

// bitTestRegisterSemantics covers every BT/BTC/BTR/BTS width and verifies
// both CF and the width-specific register write behavior.
TEXT ·bitTestRegisterSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ value+8(FP), AX
	BTW $-1, AX
	MOVQ AX, 0(DI)
	SETCS 8(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTCW CX, AX
	MOVQ AX, 16(DI)
	SETCS 24(DI)
	MOVQ value+8(FP), AX
	BTRW $4, AX
	MOVQ AX, 32(DI)
	SETCS 40(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTSW CX, AX
	MOVQ AX, 48(DI)
	SETCS 56(DI)

	MOVQ value+8(FP), AX
	BTL $-1, AX
	MOVQ AX, 64(DI)
	SETCS 72(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTCL CX, AX
	MOVQ AX, 80(DI)
	SETCS 88(DI)
	MOVQ value+8(FP), AX
	BTRL $4, AX
	MOVQ AX, 96(DI)
	SETCS 104(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTSL CX, AX
	MOVQ AX, 112(DI)
	SETCS 120(DI)

	MOVQ value+8(FP), AX
	BTQ $-1, AX
	MOVQ AX, 128(DI)
	SETCS 136(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTCQ CX, AX
	MOVQ AX, 144(DI)
	SETCS 152(DI)
	MOVQ value+8(FP), AX
	BTRQ $4, AX
	MOVQ AX, 160(DI)
	SETCS 168(DI)
	MOVQ value+8(FP), AX
	MOVQ index+16(FP), CX
	BTSQ CX, AX
	MOVQ AX, 176(DI)
	SETCS 184(DI)
	RET

// bitTestMemorySemantics checks the unbounded memory bit string behavior for
// positive and negative register indexes at W/L/Q widths, plus imm8 masking.
TEXT ·bitTestMemorySemantics(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), DI
	MOVQ data+8(FP), BX
	MOVQ $17, CX
	BTW CX, 8(BX)
	SETCS 0(DI)
	BTCW CX, 8(BX)
	SETCS 1(DI)
	MOVQ $-1, CX
	BTRW CX, 8(BX)
	SETCS 2(DI)
	BTSW $-128, 8(BX)
	SETCS 3(DI)

	MOVQ $33, CX
	BTL CX, 32(BX)
	SETCS 4(DI)
	BTCL CX, 32(BX)
	SETCS 5(DI)
	MOVQ $-1, CX
	BTRL CX, 32(BX)
	SETCS 6(DI)
	BTSL $-128, 32(BX)
	SETCS 7(DI)

	MOVQ $65, CX
	BTQ CX, 56(BX)
	SETCS 8(DI)
	BTCQ CX, 56(BX)
	SETCS 9(DI)
	MOVQ $-1, CX
	BTRQ CX, 56(BX)
	SETCS 10(DI)
	BTSQ $-128, 56(BX)
	SETCS 11(DI)
	RET

// packedWordMultiplyAddSemantics covers PMADDWL's MMX/XMM rows and
// VPMADDWD's XMM/YMM rows using signed products and wrapping dword sums.
TEXT ·packedWordMultiplyAddSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	MOVQ (CX), M0
	PMADDWL (BX), M0
	MOVQ M0, 0(DI)
	EMMS
	MOVOU (CX), X0
	PMADDWL (BX), X0
	MOVOU X0, 8(DI)
	MOVOU (BX), X0
	MOVOU (CX), X1
	VPMADDWD X0, X1, X2
	MOVOU X2, 24(DI)
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPMADDWD Y0, Y1, Y2
	VMOVDQU Y2, 40(DI)
	VZEROUPPER
	RET

// packedUnsignedSignedByteMultiplyAddSemantics verifies the asymmetric
// signed/unsigned operand order and signed-word saturation for legacy XMM and
// VEX XMM/YMM PMADDUBSW forms.
TEXT ·packedUnsignedSignedByteMultiplyAddSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ signed+8(FP), BX
	MOVQ unsigned+16(FP), CX
	MOVOU (CX), X0
	PMADDUBSW (BX), X0
	MOVOU X0, 0(DI)
	MOVOU (CX), X1
	VPMADDUBSW (BX), X1, X2
	MOVOU X2, 16(DI)
	VMOVDQU (CX), Y1
	VPMADDUBSW (BX), Y1, Y2
	VMOVDQU Y2, 32(DI)
	VZEROUPPER
	RET

// packedDotProductSemantics validates unsigned-byte/signed-byte operand
// order, signed-word products, wrapping accumulation, and both saturating
// variants. Plan 9's first operand is the signed r/m source for BUSD.
TEXT ·packedDotProductSemantics(SB), NOSPLIT, $0-48
	MOVQ out+0(FP), AX
	MOVQ signedBytes+8(FP), BX
	MOVQ unsignedBytes+16(FP), CX
	MOVQ wordsA+24(FP), DX
	MOVQ wordsB+32(FP), SI
	MOVQ accumulator+40(FP), DI

	VMOVDQU32 (DI), Z0
	VMOVDQU8 (CX), Z1
	VMOVDQU8 (BX), Z2
	VPDPBUSD Z2, Z1, Z0
	VMOVDQU32 Z0, 0(AX)

	VMOVDQU32 (DI), Z0
	VPDPBUSDS Z2, Z1, Z0
	VMOVDQU32 Z0, 64(AX)

	VMOVDQU32 (DI), Z0
	VMOVDQU16 (DX), Z1
	VMOVDQU16 (SI), Z2
	VPDPWSSD Z2, Z1, Z0
	VMOVDQU32 Z0, 128(AX)

	VMOVDQU32 (DI), Z0
	VPDPWSSDS Z2, Z1, Z0
	VMOVDQU32 Z0, 192(AX)
	RET

// packedIntegerMinMaxSemantics covers every signed/unsigned B/W/D/Q minimum
// and maximum in the complete VEX/EVEX family.
TEXT ·packedIntegerMinMaxSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	VMOVDQU8 (BX), Z0
	VMOVDQU8 (CX), Z1
	VPMINSB Z0, Z1, Z2
	VMOVDQU8 Z2, 0(AX)
	VPMINUB Z0, Z1, Z2
	VMOVDQU8 Z2, 64(AX)
	VPMAXSB Z0, Z1, Z2
	VMOVDQU8 Z2, 128(AX)
	VPMAXUB Z0, Z1, Z2
	VMOVDQU8 Z2, 192(AX)
	VPMINSW Z0, Z1, Z2
	VMOVDQU16 Z2, 256(AX)
	VPMINUW Z0, Z1, Z2
	VMOVDQU16 Z2, 320(AX)
	VPMAXSW Z0, Z1, Z2
	VMOVDQU16 Z2, 384(AX)
	VPMAXUW Z0, Z1, Z2
	VMOVDQU16 Z2, 448(AX)
	VPMINSD Z0, Z1, Z2
	VMOVDQU32 Z2, 512(AX)
	VPMINUD Z0, Z1, Z2
	VMOVDQU32 Z2, 576(AX)
	VPMAXSD Z0, Z1, Z2
	VMOVDQU32 Z2, 640(AX)
	VPMAXUD Z0, Z1, Z2
	VMOVDQU32 Z2, 704(AX)
	VPMINSQ Z0, Z1, Z2
	VMOVDQU64 Z2, 768(AX)
	VPMINUQ Z0, Z1, Z2
	VMOVDQU64 Z2, 832(AX)
	VPMAXSQ Z0, Z1, Z2
	VMOVDQU64 Z2, 896(AX)
	VPMAXUQ Z0, Z1, Z2
	VMOVDQU64 Z2, 960(AX)
	RET

// inLaneFloatingPermuteSemantics covers immediate and variable-control
// VPERMILPS/VPERMILPD and makes the Plan 9 control/data operand order visible.
TEXT ·inLaneFloatingPermuteSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), DI
	MOVQ data+8(FP), BX
	MOVQ control+16(FP), CX
	VPERMILPS $0x1B, (BX), X0
	MOVOU X0, 0(DI)
	VPERMILPS $0x1B, (BX), Y0
	VMOVDQU Y0, 16(DI)
	VMOVDQU (BX), Y1
	VPERMILPS (CX), Y1, Y2
	VMOVDQU Y2, 48(DI)
	VPERMILPD $0x05, (BX), Y0
	VMOVDQU Y0, 80(DI)
	VMOVDQU (BX), Y1
	VPERMILPD (CX), Y1, Y2
	VMOVDQU Y2, 112(DI)
	VZEROUPPER
	RET

// packedWordMultiplySemantics covers low, signed-high, unsigned-high, and
// rounded signed-high products in both legacy and VEX forms.
TEXT ·packedWordMultiplySemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	MOVOU (BX), X0
	MOVOU (CX), X1
	PMULLW X0, X1
	MOVOU X1, 0(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	PMULHW X0, X1
	MOVOU X1, 16(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	PMULHUW X0, X1
	MOVOU X1, 32(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	PMULHRSW X0, X1
	MOVOU X1, 48(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	VPMULLW X0, X1, X2
	MOVOU X2, 64(AX)
	VPMULHW X0, X1, X2
	MOVOU X2, 80(AX)
	VPMULHUW X0, X1, X2
	MOVOU X2, 96(AX)
	VPMULHRSW X0, X1, X2
	MOVOU X2, 112(AX)
	RET

// packedFloatShuffleSemantics checks the per-128-bit-lane selector rules for
// packed single and packed double legacy/VEX shuffles.
TEXT ·packedFloatShuffleSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	MOVOU (BX), X0
	MOVOU (CX), X1
	SHUFPS $0x1b, X0, X1
	MOVOU X1, 0(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	SHUFPD $0x02, X0, X1
	MOVOU X1, 16(AX)
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VSHUFPS $0x1b, Y0, Y1, Y2
	VMOVDQU Y2, 32(AX)
	VSHUFPD $0x0a, Y0, Y1, Y2
	VMOVDQU Y2, 64(AX)
	VZEROUPPER
	RET

// immediatePackedBlendSemantics covers every Go 1.27 immediate packed-blend
// opcode. A non-palindromic mask validates source order, and the Y-width
// VPBLENDW result validates that its eight mask bits repeat per 128-bit lane.
TEXT ·immediatePackedBlendSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	MOVOU (CX), X0
	MOVOU (BX), X1
	PBLENDW $0xa5, X1, X0
	MOVOU X0, 0(AX)
	MOVOU (CX), X0
	BLENDPS $0xa5, (BX), X0
	MOVOU X0, 16(AX)
	MOVOU (CX), X0
	BLENDPD $0xa5, (BX), X0
	MOVOU X0, 32(AX)

	MOVOU (CX), X1
	VPBLENDW $0xa5, (BX), X1, X2
	MOVOU X2, 48(AX)
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPBLENDW $0xa5, Y0, Y1, Y2
	VMOVDQU Y2, 64(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	VPBLENDD $0xa5, X0, X1, X2
	MOVOU X2, 96(AX)
	VMOVDQU (CX), Y1
	VPBLENDD $0xa5, (BX), Y1, Y2
	VMOVDQU Y2, 112(AX)

	MOVOU (CX), X1
	VBLENDPS $0xa5, (BX), X1, X2
	MOVOU X2, 144(AX)
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VBLENDPS $0xa5, Y0, Y1, Y2
	VMOVDQU Y2, 160(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	VBLENDPD $0xa5, X0, X1, X2
	MOVOU X2, 192(AX)
	VMOVDQU (CX), Y1
	VBLENDPD $0xa5, (BX), Y1, Y2
	VMOVDQU Y2, 208(AX)
	VZEROUPPER
	RET

// packedUnpackSemantics covers low/high interleaving for every 8/16/32/64-bit
// legacy opcode and every Y-width V opcode, including per-128-bit-lane rules.
TEXT ·packedUnpackSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	MOVOU (CX), X0
	PUNPCKLBW (BX), X0
	MOVOU X0, 0(AX)
	MOVOU (CX), X0
	PUNPCKHBW (BX), X0
	MOVOU X0, 16(AX)
	MOVOU (CX), X0
	PUNPCKLWL (BX), X0
	MOVOU X0, 32(AX)
	MOVOU (CX), X0
	PUNPCKHWL (BX), X0
	MOVOU X0, 48(AX)
	MOVOU (CX), X0
	PUNPCKLLQ (BX), X0
	MOVOU X0, 64(AX)
	MOVOU (CX), X0
	PUNPCKHLQ (BX), X0
	MOVOU X0, 80(AX)
	MOVOU (CX), X0
	PUNPCKLQDQ (BX), X0
	MOVOU X0, 96(AX)
	MOVOU (CX), X0
	PUNPCKHQDQ (BX), X0
	MOVOU X0, 112(AX)

	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPUNPCKLBW Y0, Y1, Y2
	VMOVDQU Y2, 128(AX)
	VPUNPCKHBW Y0, Y1, Y2
	VMOVDQU Y2, 160(AX)
	VPUNPCKLWD Y0, Y1, Y2
	VMOVDQU Y2, 192(AX)
	VPUNPCKHWD Y0, Y1, Y2
	VMOVDQU Y2, 224(AX)
	VPUNPCKLDQ Y0, Y1, Y2
	VMOVDQU Y2, 256(AX)
	VPUNPCKHDQ Y0, Y1, Y2
	VMOVDQU Y2, 288(AX)
	VPUNPCKLQDQ Y0, Y1, Y2
	VMOVDQU Y2, 320(AX)
	VPUNPCKHQDQ Y0, Y1, Y2
	VMOVDQU Y2, 352(AX)
	VZEROUPPER
	RET

// qwordPermuteSemantics validates signed immediate selectors for both
// bit-identical qword permute opcodes using AVX2 instructions.
TEXT ·qwordPermuteSemantics(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ data+8(FP), BX
	VMOVDQU (BX), Y0
	VPERMQ $-40, Y0, Y2
	VMOVDQU Y2, 0(AX)
	VPERMPD $-40, Y0, Y2
	VMOVDQU Y2, 32(AX)
	VZEROUPPER
	RET

// qwordVariablePermuteSemantics validates Plan 9's data,control,destination
// order. It is assembled natively but only executed through lowered LLVM IR,
// because the original instructions require AVX-512.
TEXT ·qwordVariablePermuteSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ data+8(FP), BX
	MOVQ control+16(FP), CX
	VMOVDQU (BX), Y0
	VMOVDQU (CX), Y1
	VPERMQ Y0, Y1, Y2
	VMOVDQU Y2, 0(AX)
	VPERMPD Y0, Y1, Y2
	VMOVDQU Y2, 32(AX)
	VZEROUPPER
	RET

// packedFloatMoveVEXSemantics executes on the native oracle and validates the
// bit-preserving behavior of all four _yvmovapd opcodes without requiring
// AVX-512. Aligned moves use register operands so the input pointer may be
// arbitrarily aligned.
TEXT ·packedFloatMoveVEXSemantics(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	VMOVDQU (BX), Y0
	VMOVAPD Y0, Y1
	VMOVDQU Y1, 0(AX)
	VMOVAPS Y0, Y1
	VMOVDQU Y1, 32(AX)
	VMOVUPD (BX), Y1
	VMOVUPD Y1, 64(AX)
	VMOVUPS (BX), Y1
	VMOVUPS Y1, 96(AX)
	VZEROUPPER
	RET

// packedFloatMoveMaskSemantics validates PS dword masks, PD qword masks,
// merge/zero loads, register moves, and masked memory stores at X/Y/Z widths.
// It is assembled by the native oracle but executed only after LLVM lowering,
// because the original mask forms require AVX-512.
TEXT ·packedFloatMoveMaskSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ old+16(FP), CX
	MOVW $0xa55a, DX
	KMOVW DX, K1

	VMOVUPS (CX), X0
	VMOVUPS (BX), K1, X0
	VMOVUPS X0, 0(AX)
	VMOVUPS.Z (BX), K1, X0
	VMOVUPS X0, 16(AX)
	VMOVUPS (CX), X0
	VMOVUPS (BX), X1
	VMOVAPS X1, K1, X0
	VMOVUPS X0, 32(AX)
	VMOVUPS (CX), X0
	VMOVUPS X0, 48(AX)
	VMOVUPS (BX), X1
	VMOVAPS.Z X1, K1, 48(AX)

	VMOVUPD (CX), X0
	VMOVUPD (BX), K1, X0
	VMOVUPD X0, 64(AX)
	VMOVAPD.Z (BX), K1, X0
	VMOVUPD X0, 80(AX)
	VMOVUPD (CX), X0
	VMOVUPD X0, 96(AX)
	VMOVUPD (BX), X1
	VMOVAPD.Z X1, K1, 96(AX)

	VMOVAPS (CX), Y0
	VMOVAPS (BX), K1, Y0
	VMOVUPS Y0, 112(AX)
	VMOVAPS.Z (BX), K1, Y0
	VMOVUPS Y0, 144(AX)
	VMOVUPS (CX), Y0
	VMOVUPS Y0, 176(AX)
	VMOVUPS (BX), Y1
	VMOVUPS.Z Y1, K1, 176(AX)

	VMOVAPD (CX), Y0
	VMOVAPD (BX), K1, Y0
	VMOVUPD Y0, 208(AX)
	VMOVAPD.Z (BX), K1, Y0
	VMOVUPD Y0, 240(AX)
	VMOVUPD (CX), Y0
	VMOVUPD Y0, 272(AX)
	VMOVUPD (BX), Y1
	VMOVUPD.Z Y1, K1, 272(AX)

	VMOVUPS (CX), Z0
	VMOVUPS (BX), K1, Z0
	VMOVUPS Z0, 304(AX)
	VMOVUPS.Z (BX), K1, Z0
	VMOVUPS Z0, 368(AX)
	VMOVAPS (CX), Z0
	VMOVAPS Z0, 432(AX)
	VMOVAPS (BX), Z1
	VMOVAPS.Z Z1, K1, 432(AX)

	VMOVUPD (CX), Z0
	VMOVUPD (BX), K1, Z0
	VMOVUPD Z0, 496(AX)
	VMOVUPD.Z (BX), K1, Z0
	VMOVUPD Z0, 560(AX)
	VMOVAPD (CX), Z0
	VMOVAPD Z0, 624(AX)
	VMOVAPD (BX), Z1
	VMOVAPD.Z Z1, K1, 624(AX)
	VZEROUPPER
	RET

// packedSignExtendMoveVEXSemantics executes all six legacy and all six VEX
// signed widening opcodes. V forms use register sources to cover the form used
// by Kyber; legacy forms use exact-width memory sources.
TEXT ·packedSignExtendMoveVEXSemantics(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVOU (BX), X1
	PMOVSXBW (BX), X0
	MOVOU X0, 0(AX)
	PMOVSXBD (BX), X0
	MOVOU X0, 16(AX)
	PMOVSXBQ (BX), X0
	MOVOU X0, 32(AX)
	PMOVSXWD (BX), X0
	MOVOU X0, 48(AX)
	PMOVSXWQ (BX), X0
	MOVOU X0, 64(AX)
	PMOVSXDQ (BX), X0
	MOVOU X0, 80(AX)
	VPMOVSXBW X1, Y0
	VMOVUPD Y0, 96(AX)
	VPMOVSXBD X1, Y0
	VMOVUPD Y0, 128(AX)
	VPMOVSXBQ X1, Y0
	VMOVUPD Y0, 160(AX)
	VPMOVSXWD X1, Y0
	VMOVUPD Y0, 192(AX)
	VPMOVSXWQ X1, Y0
	VMOVUPD Y0, 224(AX)
	VPMOVSXDQ X1, Y0
	VMOVUPD Y0, 256(AX)
	VZEROUPPER
	RET

// packedSignExtendMoveMaskSemantics validates register-source merge masking
// and exact-width memory-source zero masking for all six EVEX instructions at
// Z width. It is executed only after LLVM lowering because it requires AVX-512.
TEXT ·packedSignExtendMoveMaskSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ old+16(FP), CX
	MOVQ $0xa55aa55a, DX
	KMOVQ DX, K1
	VMOVUPD (BX), Y1
	VMOVUPD (CX), Z0
	VPMOVSXBW Y1, K1, Z0
	VMOVUPD Z0, 0(AX)
	VPMOVSXBW.Z (BX), K1, Z0
	VMOVUPD Z0, 64(AX)
	MOVOU (BX), X1
	VMOVUPD (CX), Z0
	VPMOVSXBD X1, K1, Z0
	VMOVUPD Z0, 128(AX)
	VPMOVSXBD.Z (BX), K1, Z0
	VMOVUPD Z0, 192(AX)
	VMOVUPD (CX), Z0
	VPMOVSXBQ X1, K1, Z0
	VMOVUPD Z0, 256(AX)
	VPMOVSXBQ.Z (BX), K1, Z0
	VMOVUPD Z0, 320(AX)
	VMOVUPD (CX), Z0
	VPMOVSXWD Y1, K1, Z0
	VMOVUPD Z0, 384(AX)
	VPMOVSXWD.Z (BX), K1, Z0
	VMOVUPD Z0, 448(AX)
	VMOVUPD (CX), Z0
	VPMOVSXWQ X1, K1, Z0
	VMOVUPD Z0, 512(AX)
	VPMOVSXWQ.Z (BX), K1, Z0
	VMOVUPD Z0, 576(AX)
	VMOVUPD (CX), Z0
	VPMOVSXDQ Y1, K1, Z0
	VMOVUPD Z0, 640(AX)
	VPMOVSXDQ.Z (BX), K1, Z0
	VMOVUPD Z0, 704(AX)
	VZEROUPPER
	RET

// goHexVectorOps covers the packed integer forms used by go-hex. Each result
// occupies one 16-byte block in out, in the order documented by its Go test.
TEXT ·goHexVectorOps(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	MOVOU (BX), X0
	POR ·goHexORMask<>(SB), X0
	MOVOU X0, 0(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	POR X1, X0
	MOVOU X0, 16(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	PCMPGTB X1, X0
	MOVOU X0, 32(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	VPCMPGTB X1, X0, X2
	MOVOU X2, 48(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	PSUBB X1, X0
	MOVOU X0, 64(AX)

	MOVOU (BX), X0
	PSLLW $4, X0
	MOVOU X0, 80(AX)

	MOVOU (BX), X0
	PSRLW $4, X0
	MOVOU X0, 96(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	PUNPCKHBW X1, X0
	MOVOU X0, 112(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	VPUNPCKHBW X1, X0, X2
	MOVOU X2, 128(AX)

	MOVOU (BX), X0
	MOVOU (CX), X1
	VPAND X1, X0, X2
	MOVOU X2, 144(AX)
	RET

TEXT ·goHexWordOps(SB), NOSPLIT, $0-24
	MOVQ value+0(FP), DX
	MOVQ count+8(FP), CX
	SHRW CX, DX
	MOVQ $0, AX
	BSFW DX, AX
	SHLQ $16, AX
	ORQ AX, DX
	MOVQ DX, ret+16(FP)
	RET

// packedArithmeticShift32 covers PSRAL's saturating immediate-count rule.
// Counts at or above the 32-bit lane width must fill each lane with its sign.
TEXT ·packedArithmeticShift32(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVOU (BX), X0
	PSRAL $31, X0
	MOVOU X0, 0(AX)
	MOVOU (BX), X0
	PSRAL $32, X0
	MOVOU X0, 16(AX)
	RET

// packedSubtractSemantics covers wrapping and signed/unsigned saturation,
// including the non-commutative rm,v,destination order of the V forms.
TEXT ·packedSubtractSemantics(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX
	MOVOU (BX), X0
	MOVOU (CX), X1
	PSUBSB X1, X0
	MOVOU X0, 0(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	PSUBSW X1, X0
	MOVOU X0, 16(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	VPSUBUSB X1, X0, X2
	MOVOU X2, 32(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	VPSUBUSW X1, X0, X2
	MOVOU X2, 48(AX)
	MOVOU (BX), X0
	MOVOU (CX), X1
	VPSUBQ X1, X0, X2
	MOVOU X2, 64(AX)
	RET

// parityBranches validates both halves of the Go assembler's parity branch
// alias family against TESTB's low-byte even-parity flag.
TEXT ·parityBranches(SB), NOSPLIT, $0-16
	MOVBLZX value+0(FP), AX
	MOVQ $0, DX
	TESTB AL, AL
	JP parity_even
	JMP parity_even_done
parity_even:
	ORQ $1, DX
parity_even_done:
	TESTB AL, AL
	JNP parity_odd
	JMP parity_odd_done
parity_odd:
	ORQ $2, DX
parity_odd_done:
	MOVQ DX, ret+8(FP)
	RET

// unorderedBranch validates that UCOMISD sets PF for NaN inputs.
TEXT ·unorderedBranch(SB), NOSPLIT, $0-16
	MOVSD value+0(FP), X0
	UCOMISD X0, X0
	JP unordered
	MOVQ $0, ret+8(FP)
	RET
unordered:
	MOVQ $1, ret+8(FP)
	RET

// packedFloatToDwordModes covers CVTPS2PL's four MXCSR rounding modes and
// CVTTPS2PL's rounding-mode-independent truncation. It also exercises the
// STMXCSR/LDMXCSR memory forms through a real Go assembly stack frame.
TEXT ·packedFloatToDwordModes(SB), NOSPLIT, $8-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVOU (BX), X0

	STMXCSR mxcsrOrig-8(SP)
	MOVL mxcsrOrig-8(SP), DX
	ANDL $0xffff9fff, DX

	MOVL DX, mxcsrMode-4(SP)
	LDMXCSR mxcsrMode-4(SP)
	CVTPS2PL X0, X1
	MOVOU X1, 0(AX)

	ORL $0x2000, DX
	MOVL DX, mxcsrMode-4(SP)
	LDMXCSR mxcsrMode-4(SP)
	CVTPS2PL X0, X1
	MOVOU X1, 16(AX)

	ANDL $0xffff9fff, DX
	ORL $0x4000, DX
	MOVL DX, mxcsrMode-4(SP)
	LDMXCSR mxcsrMode-4(SP)
	CVTPS2PL X0, X1
	MOVOU X1, 32(AX)

	ORL $0x2000, DX
	MOVL DX, mxcsrMode-4(SP)
	LDMXCSR mxcsrMode-4(SP)
	CVTPS2PL X0, X1
	MOVOU X1, 48(AX)

	CVTTPS2PL X0, X1
	MOVOU X1, 64(AX)
	LDMXCSR mxcsrOrig-8(SP)
	RET

// sameWidthPackedConversionSemantics covers the five opcodes sharing Go
// 1.27's _yvcvtdq2ps table. It verifies every conversion mode, both square
// root lane widths, and all four EVEX explicit-rounding controls.
TEXT ·sameWidthPackedConversionSemantics(SB), NOSPLIT, $8-40
	MOVQ out+0(FP), AX
	MOVQ ints+8(FP), BX
	MOVQ floats+16(FP), CX
	MOVQ squares32+24(FP), DX
	MOVQ squares64+32(FP), SI

	STMXCSR sameWidthMXCSROrig-8(SP)
	MOVL sameWidthMXCSROrig-8(SP), R9
	ANDL $0xffff9fff, R9
	MOVL R9, sameWidthMXCSRNearest-4(SP)
	LDMXCSR sameWidthMXCSRNearest-4(SP)

	VMOVDQU32 (BX), Z0
	VCVTDQ2PS Z0, Z1
	VMOVDQU32 Z1, 0(AX)

	VMOVUPS (CX), Z0
	VCVTPS2DQ Z0, Z1
	VMOVDQU32 Z1, 64(AX)
	VCVTTPS2DQ Z0, Z1
	VMOVDQU32 Z1, 128(AX)

	VMOVUPS (DX), Z0
	VSQRTPS Z0, Z1
	VMOVDQU32 Z1, 192(AX)
	VMOVUPD (SI), Z0
	VSQRTPD Z0, Z1
	VMOVDQU64 Z1, 256(AX)

	VMOVUPS (CX), Z0
	VCVTPS2DQ.RN_SAE Z0, Z1
	VMOVDQU32 Z1, 320(AX)
	VCVTPS2DQ.RD_SAE Z0, Z1
	VMOVDQU32 Z1, 384(AX)
	VCVTPS2DQ.RU_SAE Z0, Z1
	VMOVDQU32 Z1, 448(AX)
	VCVTPS2DQ.RZ_SAE Z0, Z1
	VMOVDQU32 Z1, 512(AX)

	LDMXCSR sameWidthMXCSROrig-8(SP)
	RET

// packedSingleToDouble validates both register and exact-width memory inputs.
TEXT ·packedSingleToDouble(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVOU (BX), X0
	CVTPS2PD X0, X1
	MOVOU X1, 0(AX)
	CVTPS2PD 8(BX), X1
	MOVOU X1, 16(AX)
	RET

// conditionalMoveCodes establishes CF=0, PF=1, ZF=0, SF=1, OF=1, then
// checks all 16 condition codes using the yml_rl memory-source form.
TEXT ·conditionalMoveCodes(SB), NOSPLIT, $0-16
	MOVQ out+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ $0x7fffffffffffffff, R8
	ADDQ $1, R8
	MOVQ $-1, CX
	CMOVQCC 0(BX), CX
	MOVQ CX, 0(AX)
	MOVQ $-1, CX
	CMOVQCS 8(BX), CX
	MOVQ CX, 8(AX)
	MOVQ $-1, CX
	CMOVQEQ 16(BX), CX
	MOVQ CX, 16(AX)
	MOVQ $-1, CX
	CMOVQGE 24(BX), CX
	MOVQ CX, 24(AX)
	MOVQ $-1, CX
	CMOVQGT 32(BX), CX
	MOVQ CX, 32(AX)
	MOVQ $-1, CX
	CMOVQHI 40(BX), CX
	MOVQ CX, 40(AX)
	MOVQ $-1, CX
	CMOVQLE 48(BX), CX
	MOVQ CX, 48(AX)
	MOVQ $-1, CX
	CMOVQLS 56(BX), CX
	MOVQ CX, 56(AX)
	MOVQ $-1, CX
	CMOVQLT 64(BX), CX
	MOVQ CX, 64(AX)
	MOVQ $-1, CX
	CMOVQMI 72(BX), CX
	MOVQ CX, 72(AX)
	MOVQ $-1, CX
	CMOVQNE 80(BX), CX
	MOVQ CX, 80(AX)
	MOVQ $-1, CX
	CMOVQOC 88(BX), CX
	MOVQ CX, 88(AX)
	MOVQ $-1, CX
	CMOVQOS 96(BX), CX
	MOVQ CX, 96(AX)
	MOVQ $-1, CX
	CMOVQPC 104(BX), CX
	MOVQ CX, 104(AX)
	MOVQ $-1, CX
	CMOVQPL 112(BX), CX
	MOVQ CX, 112(AX)
	MOVQ $-1, CX
	CMOVQPS 120(BX), CX
	MOVQ CX, 120(AX)
	RET

// fma3Semantics validates all three operand orders, all six arithmetic modes,
// packed single/double lanes, and scalar upper-lane copying using VEX forms
// that execute on both the native oracle and the lowered LLVM binary.
TEXT ·fma3Semantics(SB), NOSPLIT, $0-56
	MOVQ out+0(FP), AX
	MOVQ a64+8(FP), BX
	MOVQ b64+16(FP), CX
	MOVQ c64+24(FP), DX
	MOVQ a32+32(FP), SI
	MOVQ b32+40(FP), DI
	MOVQ c32+48(FP), R8

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMADD132PD X0, X1, X2
	VMOVUPD X2, 0(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMADD213PD X0, X1, X2
	VMOVUPD X2, 16(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMADD231PD X0, X1, X2
	VMOVUPD X2, 32(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMSUB132PD X0, X1, X2
	VMOVUPD X2, 48(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFNMADD213PD X0, X1, X2
	VMOVUPD X2, 64(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFNMSUB231PD X0, X1, X2
	VMOVUPD X2, 80(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMADDSUB132PD X0, X1, X2
	VMOVUPD X2, 96(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMSUBADD231PD X0, X1, X2
	VMOVUPD X2, 112(AX)

	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFMADD132PS X0, X1, X2
	VMOVUPS X2, 128(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFMSUB213PS X0, X1, X2
	VMOVUPS X2, 144(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFNMADD231PS X0, X1, X2
	VMOVUPS X2, 160(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFNMSUB132PS X0, X1, X2
	VMOVUPS X2, 176(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFMADDSUB213PS X0, X1, X2
	VMOVUPS X2, 192(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFMSUBADD231PS X0, X1, X2
	VMOVUPS X2, 208(AX)

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMADD132SD X0, X1, X2
	VMOVUPD X2, 224(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMOVUPD (DX), X2
	VFMSUB213SD X0, X1, X2
	VMOVUPD X2, 240(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFNMADD231SS X0, X1, X2
	VMOVUPS X2, 256(AX)
	VMOVUPS (SI), X0
	VMOVUPS (DI), X1
	VMOVUPS (R8), X2
	VFNMSUB132SS X0, X1, X2
	VMOVUPS X2, 272(AX)
	VZEROUPPER
	RET

// binaryFloatingSemantics covers every operation in the VADD/VSUB/VMUL/
// VDIV/VMAX/VMIN family for packed and scalar f32/f64 VEX forms. Scalar
// results also verify that upper lanes come from the second source operand.
TEXT ·binaryFloatingSemantics(SB), NOSPLIT, $0-40
	MOVQ out+0(FP), AX
	MOVQ a64+8(FP), BX
	MOVQ b64+16(FP), CX
	MOVQ a32+24(FP), DX
	MOVQ b32+32(FP), SI

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VADDPD X0, X1, X2
	VMOVUPD X2, 0(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VSUBPD X0, X1, X2
	VMOVUPD X2, 16(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMULPD X0, X1, X2
	VMOVUPD X2, 32(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VDIVPD X0, X1, X2
	VMOVUPD X2, 48(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMAXPD X0, X1, X2
	VMOVUPD X2, 64(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMINPD X0, X1, X2
	VMOVUPD X2, 80(AX)

	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VADDPS X0, X1, X2
	VMOVUPS X2, 96(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VSUBPS X0, X1, X2
	VMOVUPS X2, 112(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMULPS X0, X1, X2
	VMOVUPS X2, 128(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VDIVPS X0, X1, X2
	VMOVUPS X2, 144(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMAXPS X0, X1, X2
	VMOVUPS X2, 160(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMINPS X0, X1, X2
	VMOVUPS X2, 176(AX)

	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VADDSD X0, X1, X2
	VMOVUPD X2, 192(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VSUBSD X0, X1, X2
	VMOVUPD X2, 208(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMULSD X0, X1, X2
	VMOVUPD X2, 224(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VDIVSD X0, X1, X2
	VMOVUPD X2, 240(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMAXSD X0, X1, X2
	VMOVUPD X2, 256(AX)
	VMOVUPD (BX), X0
	VMOVUPD (CX), X1
	VMINSD X0, X1, X2
	VMOVUPD X2, 272(AX)

	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VADDSS X0, X1, X2
	VMOVUPS X2, 288(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VSUBSS X0, X1, X2
	VMOVUPS X2, 304(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMULSS X0, X1, X2
	VMOVUPS X2, 320(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VDIVSS X0, X1, X2
	VMOVUPS X2, 336(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMAXSS X0, X1, X2
	VMOVUPS X2, 352(AX)
	VMOVUPS (DX), X0
	VMOVUPS (SI), X1
	VMINSS X0, X1, X2
	VMOVUPS X2, 368(AX)
	VZEROUPPER
	RET

// horizontalFloatingSemantics verifies the 128-bit lane grouping and Plan 9
// source order for every legacy and VEX horizontal add/subtract operation.
TEXT ·horizontalFloatingSemantics(SB), NOSPLIT, $0-40
	MOVQ out+0(FP), AX
	MOVQ a32+8(FP), BX
	MOVQ b32+16(FP), CX
	MOVQ a64+24(FP), DX
	MOVQ b64+32(FP), SI

	VMOVUPS (BX), Y0
	VMOVUPS (CX), Y1
	VHADDPS Y0, Y1, Y2
	VMOVUPS Y2, 0(AX)
	VMOVUPS (BX), Y0
	VMOVUPS (CX), Y1
	VHSUBPS Y0, Y1, Y2
	VMOVUPS Y2, 32(AX)
	VMOVUPD (DX), Y0
	VMOVUPD (SI), Y1
	VHADDPD Y0, Y1, Y2
	VMOVUPD Y2, 64(AX)
	VMOVUPD (DX), Y0
	VMOVUPD (SI), Y1
	VHSUBPD Y0, Y1, Y2
	VMOVUPD Y2, 96(AX)

	MOVUPS (BX), X0
	MOVUPS (CX), X1
	HADDPS X0, X1
	MOVUPS X1, 128(AX)
	MOVUPS (BX), X0
	MOVUPS (CX), X1
	HSUBPS X0, X1
	MOVUPS X1, 144(AX)
	MOVUPD (DX), X0
	MOVUPD (SI), X1
	HADDPD X0, X1
	MOVUPD X1, 160(AX)
	MOVUPD (DX), X0
	MOVUPD (SI), X1
	HSUBPD X0, X1
	MOVUPD X1, 176(AX)
	VZEROUPPER
	RET

// expandedEcosystemVectors covers the packed min/max family plus the scalar
// VEX move and packed-qword shift forms found by the ecosystem scan.
TEXT ·expandedEcosystemVectors(SB), NOSPLIT, $0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), BX
	MOVQ b+16(FP), CX

	MOVOU (BX), X0
	PMINUB (CX), X0
	MOVOU X0, 0(AX)
	MOVOU (BX), X0
	PMINSB (CX), X0
	MOVOU X0, 16(AX)
	MOVOU (BX), X0
	PMINUW (CX), X0
	MOVOU X0, 32(AX)
	MOVOU (BX), X0
	PMINSW (CX), X0
	MOVOU X0, 48(AX)
	MOVOU (BX), X0
	PMINUD (CX), X0
	MOVOU X0, 64(AX)
	MOVOU (BX), X0
	PMINSD (CX), X0
	MOVOU X0, 80(AX)

	MOVOU (BX), X0
	PMAXUB (CX), X0
	MOVOU X0, 96(AX)
	MOVOU (BX), X0
	PMAXSB (CX), X0
	MOVOU X0, 112(AX)
	MOVOU (BX), X0
	PMAXUW (CX), X0
	MOVOU X0, 128(AX)
	MOVOU (BX), X0
	PMAXSW (CX), X0
	MOVOU X0, 144(AX)
	MOVOU (BX), X0
	PMAXUD (CX), X0
	MOVOU X0, 160(AX)
	MOVOU (BX), X0
	PMAXSD (CX), X0
	MOVOU X0, 176(AX)

	MOVOU (BX), X0
	PSLLQ $13, X0
	MOVOU X0, 192(AX)
	MOVOU (BX), X0
	PSRLQ $64, X0
	MOVOU X0, 208(AX)

	MOVQ $0x0123456789abcdef, DX
	VMOVQ DX, X0
	VMOVQ X0, DX
	MOVQ DX, 224(AX)
	VMOVD DX, X0
	VMOVD X0, DX
	MOVQ DX, 232(AX)
	MOVOU X0, 240(AX)
	MOVOU (BX), X0
	VMOVQ X0, X1
	MOVOU X1, 256(AX)

	MOVOU (BX), X0
	PAVGB (CX), X0
	MOVOU X0, 272(AX)
	MOVOU (BX), X0
	PAVGW (CX), X0
	MOVOU X0, 288(AX)

	MOVOU (BX), X0
	PCMPGTB (CX), X0
	MOVOU X0, 304(AX)
	MOVOU (BX), X0
	PCMPGTW (CX), X0
	MOVOU X0, 320(AX)
	MOVOU (BX), X0
	PCMPGTL (CX), X0
	MOVOU X0, 336(AX)
	MOVOU (BX), X0
	PCMPGTQ (CX), X0
	MOVOU X0, 352(AX)

	MOVOU (BX), X0
	PSRAW $3, X0
	MOVOU X0, 368(AX)
	MOVOU (BX), X0
	PSRAW (CX), X0
	MOVOU X0, 384(AX)

	MOVOU (BX), X0
	UNPCKLPS (CX), X0
	MOVOU X0, 400(AX)
	MOVOU (BX), X0
	UNPCKHPS (CX), X0
	MOVOU X0, 416(AX)
	MOVOU (BX), X0
	UNPCKLPD (CX), X0
	MOVOU X0, 432(AX)
	MOVOU (BX), X0
	UNPCKHPD (CX), X0
	MOVOU X0, 448(AX)

	PMOVZXBW (BX), X0
	MOVOU X0, 464(AX)
	PMOVZXBD (BX), X0
	MOVOU X0, 480(AX)
	PMOVZXBQ (BX), X0
	MOVOU X0, 496(AX)
	PMOVZXWD (BX), X0
	MOVOU X0, 512(AX)
	PMOVZXWQ (BX), X0
	MOVOU X0, 528(AX)
	PMOVZXDQ (BX), X0
	MOVOU X0, 544(AX)

	MOVOU (BX), X0
	PHADDD (CX), X0
	MOVOU X0, 560(AX)
	MOVOU (BX), X0
	PHADDSW (CX), X0
	MOVOU X0, 576(AX)
	MOVOU (BX), X0
	PHADDW (CX), X0
	MOVOU X0, 592(AX)
	MOVOU (BX), X0
	PHSUBD (CX), X0
	MOVOU X0, 608(AX)
	MOVOU (BX), X0
	PHSUBSW (CX), X0
	MOVOU X0, 624(AX)
	MOVOU (BX), X0
	PHSUBW (CX), X0
	MOVOU X0, 640(AX)

	PHMINPOSUW (BX), X0
	MOVOU X0, 656(AX)

	MOVOU (CX), X0
	MOVOU X0, 672(AX)
	MOVOU (CX), X0
	MOVOU (BX), X1
	LEAQ 672(AX), DI
	MASKMOVDQU X0, X1
	MOVOU (CX), X0
	MOVOU X0, 688(AX)
	MOVOU (CX), X0
	MOVOU (BX), X1
	LEAQ 688(AX), DI
	VMASKMOVDQU X0, X1

	MOVQ $3, 800(AX)
	MOVQ $0, 808(AX)
	MOVOU 800(AX), X1
	MOVOU (BX), X0
	PSLLW X1, X0
	MOVOU X0, 704(AX)
	MOVOU (BX), X0
	PSLLL X1, X0
	MOVOU X0, 720(AX)
	MOVOU (BX), X0
	PSLLQ X1, X0
	MOVOU X0, 736(AX)
	MOVOU (BX), X0
	PSRLW X1, X0
	MOVOU X0, 752(AX)
	MOVOU (BX), X0
	PSRLL X1, X0
	MOVOU X0, 768(AX)
	MOVOU (BX), X0
	PSRLQ X1, X0
	MOVOU X0, 784(AX)
	VZEROUPPER
	RET
