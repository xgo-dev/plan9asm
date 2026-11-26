#include "textflag.h"

// Batched amd64 machine-code differential gate kernels.
// Every function in this file is compiled BOTH by Go's native amd64 assembler
// AND by plan9asm.TranslateGoModule -> LLVM 22 opt -O2 -> llc, and their
// outputs (return values, memory buffers, and ISA-defined flags) are compared
// bit-for-bit on identical input vectors.
//
// Flag packing helper conventions:
//   - For ADD/ADC/SUB/SBB/CMP/NEG/INC/DEC: LAHF bitmask 0xd7 covers all defined
//     low-byte flags (SF:7, ZF:6, AF:4, PF:2, 1:1, CF:0), plus SETOS at bit 8 (OF).
//   - For AND/OR/XOR/TEST/SHL/SHR/SAR: AF is architecturally undefined on x86,
//     so LAHF is masked to 0xc7 (SF, ZF, PF, 1, CF).

// diffArith64 tests 64-bit arithmetic, CMP, Jcc/SETcc/CMOVcc, PF, SF vs OF, INC/DEC CF preservation.
TEXT ·diffArith64(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// [0] ADDQ result, [1] ADDQ flags (LAHF&0xd7 | OF<<8)
	MOVQ R8, R10
	ADDQ R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 0(DI)
	MOVQ AX, 8(DI)

	// [2] SUBQ result, [3] SUBQ flags
	MOVQ R8, R10
	SUBQ R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 16(DI)
	MOVQ AX, 24(DI)

	// [4] CMPQ R8, R9 flags (LAHF&0xd7 | OF<<8), [5] Jcc/SETcc bitmask (JMI/JPL/JLT/JLE/JGT/JGE/JPS/JPC/JCS/JCC/JHI/JLS/JEQ/JNE)
	CMPQ R8, R9
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 32(DI)

	MOVQ $0, R11
	CMPQ R8, R9
	JMI cmp_mi
	JMP cmp_mi_done
cmp_mi:
	ORQ $1, R11
cmp_mi_done:
	CMPQ R8, R9
	JLT cmp_lt
	JMP cmp_lt_done
cmp_lt:
	ORQ $2, R11
cmp_lt_done:
	CMPQ R8, R9
	JLE cmp_le
	JMP cmp_le_done
cmp_le:
	ORQ $4, R11
cmp_le_done:
	CMPQ R8, R9
	JGT cmp_gt
	JMP cmp_gt_done
cmp_gt:
	ORQ $8, R11
cmp_gt_done:
	CMPQ R8, R9
	JGE cmp_ge
	JMP cmp_ge_done
cmp_ge:
	ORQ $16, R11
cmp_ge_done:
	CMPQ R8, R9
	JPS cmp_ps
	JMP cmp_ps_done
cmp_ps:
	ORQ $32, R11
cmp_ps_done:
	CMPQ R8, R9
	JPC cmp_pc
	JMP cmp_pc_done
cmp_pc:
	ORQ $64, R11
cmp_pc_done:
	CMPQ R8, R9
	JCS cmp_cs
	JMP cmp_cs_done
cmp_cs:
	ORQ $128, R11
cmp_cs_done:
	CMPQ R8, R9
	JHI cmp_hi
	JMP cmp_hi_done
cmp_hi:
	ORQ $256, R11
cmp_hi_done:
	CMPQ R8, R9
	JLS cmp_ls
	JMP cmp_ls_done
cmp_ls:
	ORQ $512, R11
cmp_ls_done:
	CMPQ R8, R9
	JEQ cmp_eq
	JMP cmp_eq_done
cmp_eq:
	ORQ $1024, R11
cmp_eq_done:
	CMPQ R8, R9
	MOVQ $0x1111, R12
	MOVQ $0x2222, R13
	CMOVQLT R13, R12
	CMPQ R12, $0x2222
	JNE cmp_cmov_done
	ORQ $2048, R11
cmp_cmov_done:
	MOVQ R11, 40(DI)

	// [6] ADCQ (with CF=1) result, [7] ADCQ flags
	STC
	MOVQ R8, R10
	ADCQ R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 48(DI)
	MOVQ AX, 56(DI)

	// [8] SBBQ (with CF=1) result, [9] SBBQ flags
	STC
	MOVQ R8, R10
	SBBQ R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 64(DI)
	MOVQ AX, 72(DI)

	// [10] INCQ result, [11] INCQ flags (CF=1 must be preserved!)
	STC
	MOVQ R8, R10
	INCQ R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 80(DI)
	MOVQ AX, 88(DI)

	// [12] DECQ result, [13] DECQ flags (CF=0 must be preserved!)
	CLC
	MOVQ R8, R10
	DECQ R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 96(DI)
	MOVQ AX, 104(DI)

	// [14] NEGQ result, [15] NEGQ flags
	MOVQ R8, R10
	NEGQ R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 112(DI)
	MOVQ AX, 120(DI)

	// [16] TESTQ R8, R8 parity/sign/zero (LAHF&0xc7 | OF<<8), [17] JPS taken flag
	TESTQ R8, R8
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 128(DI)
	MOVQ $0, R10
	TESTQ R8, R8
	JPS test_ps
	JMP test_ps_done
test_ps:
	MOVQ $1, R10
test_ps_done:
	MOVQ R10, 136(DI)

	// [18] ANDQ result, [19] XORQ flags (LAHF&0xc7 | OF<<8)
	MOVQ R8, R10
	ANDQ R9, R10
	MOVQ R10, 144(DI)
	MOVQ R8, R10
	XORQ R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 152(DI)
	RET

// diffArithWidths tests 8-bit, 16-bit, and 32-bit arithmetic & defined flags (incl. partial-reg preservation).
TEXT ·diffArithWidths(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// 8-bit ADDB: preserves upper 56 bits of dst
	MOVQ $0x1122334455667700, R10
	ORQ R8, R10
	MOVQ R9, CX
	ADDB CL, R10B
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 0(DI)
	MOVQ AX, 8(DI)

	// 8-bit SUBB
	MOVQ R8, R10
	MOVQ R9, CX
	SUBB CL, R10B
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 16(DI)
	MOVQ AX, 24(DI)

	// 8-bit INCB (CF=1 preserved) + NEGB
	STC
	MOVQ R8, R10
	INCB R10B
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 32(DI)
	MOVQ AX, 40(DI)

	MOVQ R8, R10
	NEGB R10B
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 48(DI)
	MOVQ AX, 56(DI)

	// 16-bit ADDW (preserves upper 48 bits)
	MOVQ $0xaabbccdd00000000, R10
	MOVQ R8, R11
	ANDQ $0xffff, R11
	ORQ R11, R10
	ADDW R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 64(DI)
	MOVQ AX, 72(DI)

	// 16-bit SUBW
	MOVQ R8, R10
	SUBW R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 80(DI)
	MOVQ AX, 88(DI)

	// 16-bit DECW (CF=1 preserved) + NEGW
	STC
	MOVQ R8, R10
	DECW R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 96(DI)
	MOVQ AX, 104(DI)

	MOVQ R8, R10
	NEGW R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 112(DI)
	MOVQ AX, 120(DI)

	// 32-bit ADDL (zero-extends upper 32 bits!)
	MOVQ $0xffffffff00000000, R10
	ORQ R8, R10
	ADDL R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 128(DI)
	MOVQ AX, 136(DI)

	// 32-bit SUBL
	MOVQ R8, R10
	SUBL R9, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 144(DI)
	MOVQ AX, 152(DI)

	// 32-bit INCL (CF=1 preserved) + NEGL
	STC
	MOVQ R8, R10
	INCL R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 160(DI)
	MOVQ AX, 168(DI)

	MOVQ R8, R10
	NEGL R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 176(DI)
	MOVQ AX, 184(DI)
	RET

// diffMulDiv tests 8/16/32/64-bit MUL, IMUL, DIV, IDIV, CBW, CWDE, CDQE, CWD, CDQ, CQO.
TEXT ·diffMulDiv(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// [0..1] MULQ (DX:AX = R8 * R9)
	MOVQ R8, AX
	MULQ R9
	MOVQ AX, 0(DI)
	MOVQ DX, 8(DI)

	// [2..3] IMULQ 1-op (signed DX:AX = R8 * R9)
	MOVQ R8, AX
	IMULQ R9
	MOVQ AX, 16(DI)
	MOVQ DX, 24(DI)

	// [4] IMUL3Q $13, R8, R10; [5] IMULW 2-op
	IMUL3Q $13, R8, R10
	MOVQ R10, 32(DI)
	MOVQ R8, R10
	IMULW R9, R10
	MOVWQZX R10, R10
	MOVQ R10, 40(DI)

	// [6..7] DIVQ: (0:R8) / safeDiv
	MOVQ R9, BX
	ORQ $1, BX
	MOVQ $0, DX
	MOVQ R8, AX
	DIVQ BX
	MOVQ AX, 48(DI)
	MOVQ DX, 56(DI)

	// [8..9] IDIVQ: sign-extended R8 / safeDiv (force |div| >= 2 to prevent MinInt/-1 overflow)
	MOVQ R9, BX
	ANDQ $0x7fffffff, BX
	ADDQ $2, BX
	MOVQ R8, AX
	CQO
	IDIVQ BX
	MOVQ AX, 64(DI)
	MOVQ DX, 72(DI)

	// [10..11] DIVL + IDIVL
	MOVQ R9, BX
	ANDQ $0x7fff, BX
	ADDQ $2, BX
	MOVL R8, AX
	MOVL $0, DX
	DIVL BX
	MOVL AX, 80(DI)
	MOVL DX, 84(DI)
	MOVL R8, AX
	CDQ
	IDIVL BX
	MOVL AX, 88(DI)
	MOVL DX, 92(DI)

	// [12..13] DIVW + IDIVW (keep dividend small via 16-bit sign-extend CWD)
	MOVQ R9, BX
	ANDQ $0xff, BX
	ADDQ $2, BX
	MOVWQZX R8, AX
	MOVQ $0, DX
	DIVW BX
	MOVW AX, 96(DI)
	MOVW DX, 98(DI)
	MOVWQZX R8, AX
	CWD
	IDIVW BX
	MOVW AX, 104(DI)
	MOVW DX, 106(DI)

	// [14] DIVB + IDIVB (safe small dividend so quotient fits in 8 bits)
	MOVQ R8, AX
	ANDQ $0xff, AX
	MOVQ R9, BX
	ANDQ $0x1f, BX
	ADDQ $2, BX
	DIVB BL
	MOVWQZX AX, R10
	MOVQ R10, 112(DI)

	// [15] CBW / CWDE / CDQE chain
	MOVQ R8, AX
	CBW
	CWDE
	CDQE
	MOVQ AX, 120(DI)
	RET

// diffShiftsRotates tests 8/16/32/64-bit SHL/SHR/SAR/ROL/ROR/RCL/RCR across imm & CL counts,
// including count==0 / count==64 flag preservation, count==1 OF/CF, and SHLW/ROLQ CF writeback.
TEXT ·diffShiftsRotates(SB), NOSPLIT, $0-24
	MOVQ val+0(FP), R8
	MOVQ cnt+8(FP), R9
	MOVQ out+16(FP), DI

	// [0] SHLQ $1 result, [1] SHLQ $1 flags (LAHF&0xc7 | OF<<8) + JLT (SF!=OF)
	CLC
	MOVQ R8, R10
	SHLQ $1, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	MOVQ $0, DX
	SETLT DL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	SHLQ $16, DX
	ORQ BX, AX
	ORQ DX, AX
	MOVQ R10, 0(DI)
	MOVQ AX, 8(DI)

	// [2] SHLQ CL result, [3] SHLQ CL flags (only compare SF/ZF/PF/CF when cnt&63 != 0, all when cnt&63 == 0)
	// Seed known flags with CMPQ $0x8000000000000000, $1 (OF=1, SF=0, ZF=0, CF=0)
	MOVQ $0x8000000000000000, R11
	MOVQ $1, R12
	CMPQ R11, R12
	MOVQ R8, R10
	MOVQ R9, CX
	SHLQ CL, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	// When (cnt&63)==0, OF is preserved; when (cnt&63)==1, OF is defined; otherwise mask OF out.
	MOVQ R9, DX
	ANDQ $63, DX
	CMPQ DX, $1
	JHI shlq_no_of
	SHLQ $8, BX
	ORQ BX, AX
shlq_no_of:
	MOVQ R10, 16(DI)
	MOVQ AX, 24(DI)

	// [4] SHRQ CL result, [5] SHRQ CL flags
	STC
	MOVQ R8, R10
	MOVQ R9, CX
	SHRQ CL, R10
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R10, 32(DI)
	MOVQ AX, 40(DI)

	// [6] SARQ CL result, [7] SARQ CL flags
	STC
	MOVQ R8, R10
	MOVQ R9, CX
	SARQ CL, R10
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R10, 48(DI)
	MOVQ AX, 56(DI)

	// [8] SHLW $1 result, [9] SHLW $1 CF + SF/ZF/PF + OF (Round 5 P1: AX=0x8000, SHLW $1 -> CF=1)
	CLC
	MOVQ R8, R10
	SHLW $1, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 64(DI)
	MOVQ AX, 72(DI)

	// [10] SHLB $1 result, [11] SHLB $1 flags
	CLC
	MOVQ R8, R10
	SHLB $1, R10B
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 80(DI)
	MOVQ AX, 88(DI)

	// [12] SHLL $1 result (zero-extends upper 32), [13] SHRL $1 result
	MOVQ R8, R10
	SHLL $1, R10
	MOVQ R10, 96(DI)
	MOVQ R8, R10
	SHRL $1, R10
	MOVQ R10, 104(DI)

	// [14] ROLQ $1 result, [15] ROLQ $1 CF|OF (Round 5 P1: MinInt64 ROLQ $1 -> CF=1)
	CLC
	MOVQ R8, R10
	ROLQ $1, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ $0, BX
	SETOS BL
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 112(DI)
	MOVQ AX, 120(DI)

	// [16] RORQ $1 result, [17] RORQ $1 CF|OF
	CLC
	MOVQ R8, R10
	RORQ $1, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ $0, BX
	SETOS BL
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 128(DI)
	MOVQ AX, 136(DI)

	// [18] ROLQ CL result, [19] RORQ CL result + CF (preserving SF/ZF/PF via CMPQ)
	MOVQ R8, R10
	MOVQ R9, CX
	CLC
	ROLQ CL, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ R10, 144(DI)
	MOVQ R8, R10
	MOVQ R9, CX
	CLC
	RORQ CL, R10
	MOVQ $0, BX
	SETCS BL
	SHLQ $1, BX
	ORQ BX, AX
	// pack RORQ result in [19] and CF bits in [20]
	MOVQ R10, 152(DI)
	MOVQ AX, 160(DI)

	// [21] RCLQ $1 (CF=1) result + CF, [22] RCRQ $1 (CF=1) result + CF
	STC
	MOVQ R8, R10
	RCLQ $1, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ R10, 168(DI)
	STC
	MOVQ R8, R10
	RCRQ $1, R10
	MOVQ $0, BX
	SETCS BL
	SHLQ $1, BX
	ORQ BX, AX
	MOVQ R10, 176(DI)
	MOVQ AX, 184(DI)
	RET

// diffDoubleShift16 tests 16-bit SHLW/SHRW 3-op (SHLDW/SHRDW) across ISA-defined counts 0..16,
// explicitly including count == 16 (Round 6 P1) and register CL counts!
TEXT ·diffDoubleShift16(SB), NOSPLIT, $0-32
	MOVQ dst+0(FP), R8
	MOVQ src+8(FP), R9
	MOVQ cnt+16(FP), R10
	MOVQ out+24(FP), DI

	// [0] SHLW $0, R9, R11 (must preserve R11 and flags!)
	STC
	MOVQ R8, R11
	SHLW $0, R9, R11
	MOVQ $0, AX
	SETCS AL
	MOVQ R11, 0(DI)
	MOVQ AX, 8(DI)

	// [2] SHLW $1, R9, R11 + flags (LAHF&0xc7 | OF<<8)
	CLC
	MOVQ R8, R11
	SHLW $1, R9, R11
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R11, 16(DI)
	MOVQ AX, 24(DI)

	// [4] SHLW $16, R9, R11 + defined flags (LAHF&0xc7) — exact Round 6 P1!
	CLC
	MOVQ R8, R11
	SHLW $16, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 32(DI)
	MOVQ AX, 40(DI)

	// [6] SHRW $16, R9, R11 + defined flags (LAHF&0xc7) — exact Round 6 P1!
	CLC
	MOVQ R8, R11
	SHRW $16, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 48(DI)
	MOVQ AX, 56(DI)

	// [8] SHLW CL, R9, R11 + defined flags (caller passes cnt in 0..16)
	CLC
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHLW CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 64(DI)
	MOVQ AX, 72(DI)

	// [10] SHRW CL, R9, R11 + defined flags (caller passes cnt in 0..16)
	CLC
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHRW CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 80(DI)
	MOVQ AX, 88(DI)

	// [12] SHLW $16 memory dest, [13] SHRW $16 memory dest
	MOVQ R8, 96(DI)
	SHLW $16, R9, 96(DI)
	MOVQ R8, 104(DI)
	SHRW $16, R9, 104(DI)

	// [14] SHLW $7, R9, R11, [15] SHRW $7, R9, R11
	MOVQ R8, R11
	SHLW $7, R9, R11
	MOVQ R11, 112(DI)
	MOVQ R8, R11
	SHRW $7, R9, R11
	MOVQ R11, 120(DI)
	RET

// diffDoubleShift3264 tests 32/64-bit 3-op SHLL/SHRL/SHLQ/SHRQ with imm & CL counts + defined flags.
TEXT ·diffDoubleShift3264(SB), NOSPLIT, $0-32
	MOVQ dst+0(FP), R8
	MOVQ src+8(FP), R9
	MOVQ cnt+16(FP), R10
	MOVQ out+24(FP), DI

	// [0..1] SHLL CL, R9, R11 + flags (LAHF&0xc7)
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHLL CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 0(DI)
	MOVQ AX, 8(DI)

	// [2..3] SHRL CL, R9, R11 + flags
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHRL CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 16(DI)
	MOVQ AX, 24(DI)

	// [4..5] SHLQ CL, R9, R11 + flags
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHLQ CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 32(DI)
	MOVQ AX, 40(DI)

	// [6..7] SHRQ CL, R9, R11 + flags
	CMPQ R8, R8
	MOVQ R8, R11
	MOVQ R10, CX
	SHRQ CL, R9, R11
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xc7, AX
	MOVQ R11, 48(DI)
	MOVQ AX, 56(DI)

	// [8..11] SHLQ $1 / SHRQ $1 with OF+CF
	MOVQ R8, R11
	SHLQ $1, R9, R11
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R11, 64(DI)
	MOVQ AX, 72(DI)

	MOVQ R8, R11
	SHRQ $1, R9, R11
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xc7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R11, 80(DI)
	MOVQ AX, 88(DI)

	// [12..15] SHLQ $0 / SHRQ $64 preserve dst & CF
	STC
	MOVQ R8, R11
	SHLQ $0, R9, R11
	MOVQ $0, AX
	SETCS AL
	MOVQ R11, 96(DI)
	MOVQ AX, 104(DI)

	STC
	MOVQ R8, R11
	MOVQ $64, CX
	SHRQ CL, R9, R11
	MOVQ $0, AX
	SETCS AL
	MOVQ R11, 112(DI)
	MOVQ AX, 120(DI)
	RET

// diffFlagsSaveRestore tests PUSHFQ/POPFQ (via POPQ & 0(SP)), PUSHFW/POPFW, LAHF/SAHF (incl. AF!),
// CLC/STC/CMC, and CLD/STD — directly covering Round 6 P1 #2 and #3.
TEXT ·diffFlagsSaveRestore(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// [0] STC -> PUSHFQ -> POPQ AX -> mask 0x0cd7 (CF=1, bit1=1)
	CLD
	CMPQ R8, R8
	STC
	PUSHFQ
	POPQ AX
	ANDQ $0x0cd7, AX
	MOVQ AX, 0(DI)

	// [1] STC -> PUSHFQ -> MOVQ 0(SP), AX -> POPQ BX (unified SP stack!)
	CMPQ R8, R8
	STC
	PUSHFQ
	MOVQ 0(SP), AX
	POPQ BX
	ANDQ $0x0cd7, AX
	MOVQ AX, 8(DI)

	// [2] STC -> PUSHFQ -> CLC -> POPFQ -> SETCS (must restore CF=1)
	STC
	PUSHFQ
	CLC
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, 16(DI)

	// [3] CLC -> PUSHFQ -> STC -> POPFQ -> SETCS (must restore CF=0)
	CLC
	PUSHFQ
	STC
	POPFQ
	MOVQ $0, AX
	SETCS AL
	MOVQ AX, 24(DI)

	// [4] CMPQ a, b -> PUSHFQ -> POPQ & 0x0cd7
	CMPQ R8, R9
	PUSHFQ
	POPQ AX
	ANDQ $0x0cd7, AX
	MOVQ AX, 32(DI)

	// [5] CMPQ a, b -> PUSHFQ -> clobber flags -> POPFQ -> LAHF&0xd7 | OF<<8
	CMPQ R8, R9
	PUSHFQ
	XORQ R10, R10
	POPFQ
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 40(DI)

	// [6] PUSHFW -> POPW & 0x0cd7
	CMPQ R8, R9
	PUSHFW
	MOVQ $0, AX
	POPW AX
	ANDQ $0x0cd7, AX
	MOVQ AX, 48(DI)

	// [7] CMPQ a, b -> PUSHFW -> clobber flags -> POPFW -> LAHF&0xd7 | OF<<8
	CMPQ R8, R9
	PUSHFW
	XORQ R10, R10
	POPFW
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ AX, 56(DI)

	// [8] Round 6 P1 #3: AX=15; ADDQ $1, AX; LAHF; return AH & 0x10 (must be 16!)
	MOVQ $15, AX
	ADDQ $1, AX
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0x10, AX
	MOVQ AX, 64(DI)

	// [9] General ADDQ a+b -> LAHF & 0xd7 (covers AF carry from bit 3->4)
	MOVQ R8, R10
	ADDQ R9, R10
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xd7, AX
	MOVQ AX, 72(DI)

	// [10] General SUBQ a-b -> LAHF & 0xd7 (covers AF borrow from bit 4->3)
	MOVQ R8, R10
	SUBQ R9, R10
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xd7, AX
	MOVQ AX, 80(DI)

	// [11] SAHF -> LAHF round-trip of SF|ZF|AF|PF|CF from input a
	MOVQ R8, AX
	ANDQ $0xd5, AX
	ORQ $0x02, AX
	SHLQ $8, AX
	SAHF
	MOVQ $0, AX
	LAHF
	SHRQ $8, AX
	ANDQ $0xd7, AX
	MOVQ AX, 88(DI)

	// [12] CMC toggling CF (STC; CMC -> 0, CLC; CMC -> 1)
	STC
	CMC
	MOVQ $0, AX
	SETCS AL
	CLC
	CMC
	MOVQ $0, BX
	SETCS BL
	SHLQ $1, BX
	ORQ BX, AX
	MOVQ AX, 96(DI)

	// [13] STD -> PUSHFQ -> CLD -> POPQ & 0x0400 (DF bit 10 = 0x400)
	STD
	PUSHFQ
	CLD
	POPQ AX
	ANDQ $0x0400, AX
	MOVQ AX, 104(DI)

	// [14] PUSHQ / POPQ via unified SP stack
	PUSHQ R8
	MOVQ 0(SP), R10
	POPQ R11
	XORQ R10, R11
	ORQ R10, R11
	MOVQ R11, 112(DI)

	// [15] PUSHW / POPW via unified SP stack
	PUSHW R9
	MOVQ $0, R10
	POPW R10
	MOVQ R10, 120(DI)
	RET

// diffBitCond tests BT*/BTS*/BTR*/BTC* (incl. ZF preservation), BSF*/BSR*, BSWAP*, NOT*.
TEXT ·diffBitCond(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// [0] BTQ bit (R9&63) preserves ZF=1 set by CMPQ R8, R8
	CMPQ R8, R8
	MOVQ R9, CX
	ANDQ $63, CX
	BTQ CX, R8
	MOVQ $0, AX
	SETCS AL
	MOVQ $0, BX
	SETEQ BL
	SHLQ $1, BX
	ORQ BX, AX
	MOVQ AX, 0(DI)

	// [1] BTSQ result, [2] BTSQ CF
	MOVQ R8, R10
	BTSQ CX, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ R10, 8(DI)
	MOVQ AX, 16(DI)

	// [3] BTRQ result, [4] BTRQ CF
	MOVQ R8, R10
	BTRQ CX, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ R10, 24(DI)
	MOVQ AX, 32(DI)

	// [5] BTCQ result, [6] BTCQ CF
	MOVQ R8, R10
	BTCQ CX, R10
	MOVQ $0, AX
	SETCS AL
	MOVQ R10, 40(DI)
	MOVQ AX, 48(DI)

	// [7] BSFQ on (R8 | 1) so result is always defined, [8] BSRQ on (R8 | 1)
	MOVQ R8, R10
	ORQ $1, R10
	BSFQ R10, R11
	MOVQ R11, 56(DI)
	BSRQ R10, R11
	MOVQ R11, 64(DI)

	// [9] BSFQ on 0 sets ZF=1
	MOVQ $0, R10
	BSFQ R10, R11
	MOVQ $0, AX
	SETEQ AL
	MOVQ AX, 72(DI)

	// [10] BSFL / BSRL on (uint32(R8) | 1)
	MOVL R8, R10
	ORL $1, R10
	BSFL R10, R11
	MOVQ R11, 80(DI)
	BSRL R10, R11
	MOVQ R11, 88(DI)

	// [11] BSWAPQ, [12] BSWAPL
	MOVQ R8, R10
	BSWAPQ R10
	MOVQ R10, 96(DI)
	MOVQ R8, R10
	BSWAPL R10
	MOVQ R10, 104(DI)

	// [13] NOTQ, [14] NOTL, [15] NOTW
	MOVQ R8, R10
	NOTQ R10
	MOVQ R10, 112(DI)
	MOVQ R8, R10
	NOTL R10
	MOVQ R10, 120(DI)
	MOVQ R8, R10
	NOTW R10
	MOVQ R10, 128(DI)
	RET

// diffAtomicAndString tests LOCK XADD*/CMPXCHG*/XCHG* and REP MOVS*/STOS*/LODS*/SCAS*/CMPS* (CLD & STD).
TEXT ·diffAtomicAndString(SB), NOSPLIT, $0-24
	MOVQ buf+0(FP), R8
	MOVQ val+8(FP), R9
	MOVQ out+16(FP), DI

	// [0] LOCK XADDQ on buf[0..7], [1] new mem val
	MOVQ R9, AX
	LOCK
	XADDQ AX, 0(R8)
	MOVQ AX, 0(DI)
	MOVQ 0(R8), R10
	MOVQ R10, 8(DI)

	// [2] LOCK CMPXCHGQ match (ZF=1), [3] LOCK CMPXCHGQ mismatch (ZF=0, AX updated)
	MOVQ R10, AX
	MOVQ $0x123456789abcdef0, BX
	LOCK
	CMPXCHGQ BX, 0(R8)
	MOVQ $0, CX
	SETEQ CL
	MOVQ CX, 16(DI)

	MOVQ $0, AX
	MOVQ $0xdeadbeef, BX
	LOCK
	CMPXCHGQ BX, 0(R8)
	MOVQ $0, CX
	SETEQ CL
	MOVQ AX, 24(DI)
	MOVQ CX, 32(DI)

	// [5] XCHGL on buf[8..11]
	MOVL $0xaabbccdd, AX
	XCHGL AX, 8(R8)
	MOVQ AX, 40(DI)

	// [6] REP STOSQ: fill buf[16..47] (4 qwords) with val
	CLD
	LEAQ 16(R8), R11
	MOVQ R11, R12
	MOVQ DI, R13
	MOVQ R11, DI
	MOVQ R9, AX
	MOVQ $4, CX
	REP
	STOSQ
	MOVQ R13, DI
	MOVQ 16(R8), R10
	MOVQ R10, 48(DI)
	MOVQ 40(R8), R10
	MOVQ R10, 56(DI)

	// [8] REP MOVSB forward: copy 8 bytes buf[16..23] -> buf[48..55]
	CLD
	MOVQ DI, R13
	LEAQ 16(R8), SI
	LEAQ 48(R8), DI
	MOVQ $8, CX
	REP
	MOVSB
	MOVQ R13, DI
	MOVQ 48(R8), R10
	MOVQ R10, 64(DI)

	// [9] REP MOVSB backward (STD ... CLD): copy 4 bytes buf[19..16] -> buf[59..56]
	STD
	MOVQ DI, R13
	LEAQ 19(R8), SI
	LEAQ 59(R8), DI
	MOVQ $4, CX
	REP
	MOVSB
	CLD
	MOVQ R13, DI
	MOVL 56(R8), R10
	MOVQ R10, 72(DI)

	// [10] REPN SCASB: find low byte of val in buf[48..55]
	CLD
	MOVQ DI, R13
	LEAQ 48(R8), DI
	MOVQ R9, AX
	MOVQ $8, CX
	REPN
	SCASB
	MOVQ $0, BX
	SETEQ BL
	MOVQ R13, DI
	MOVQ CX, 80(DI)
	MOVQ BX, 88(DI)

	// [12] REP CMPSB: compare buf[16..23] with buf[48..55] (equal -> CX=0, ZF=1)
	CLD
	MOVQ DI, R13
	LEAQ 16(R8), SI
	LEAQ 48(R8), DI
	MOVQ $8, CX
	REP
	CMPSB
	MOVQ $0, BX
	SETEQ BL
	MOVQ R13, DI
	MOVQ CX, 96(DI)
	MOVQ BX, 104(DI)

	// [14] LODSQ from buf[48..55]
	CLD
	LEAQ 48(R8), SI
	LODSQ
	MOVQ AX, 112(DI)
	// [15] LOCK XADDB on buf[60]
	MOVQ $5, AX
	LOCK
	XADDB AL, 60(R8)
	MOVBQZX AL, AX
	MOVQ AX, 120(DI)
	RET

// diffZeroArgCallee + diffZeroArgCaller: exact Round 4 P1 (zero-arg ABI0 CALL returning 42 on 0(SP)).
TEXT ·diffZeroArgCallee(SB), NOSPLIT, $0-8
	MOVQ $42, ret+0(FP)
	RET

TEXT ·diffZeroArgCaller(SB), NOSPLIT, $8-8
	CALL ·diffZeroArgCallee(SB)
	MOVQ 0(SP), AX
	MOVQ AX, ret+0(FP)
	RET

// diffADX tests independent CF vs OF tracking for ADCXQ and ADOXQ (Round 3 P1).
TEXT ·diffADX(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R9
	MOVQ out+16(FP), DI

	// Set OF=1 via CMPQ MinInt64, 1; clear CF=0 via CLC.
	// ADCXQ must see CF=0 and preserve OF=1!
	MOVQ $0x8000000000000000, R10
	MOVQ $1, R11
	CMPQ R10, R11
	CLC
	MOVQ R8, R12
	ADCXQ R9, R12
	MOVQ $0, AX
	SETCS AL
	MOVQ $0, BX
	SETOS BL
	SHLQ $1, BX
	ORQ BX, AX
	MOVQ R12, 0(DI)
	MOVQ AX, 8(DI)

	// Now ADOXQ sees OF=1 (preserved by ADCXQ!) and preserves CF!
	STC
	MOVQ R8, R12
	ADOXQ R9, R12
	MOVQ $0, AX
	SETCS AL
	MOVQ $0, BX
	SETOS BL
	SHLQ $1, BX
	ORQ BX, AX
	MOVQ R12, 16(DI)
	MOVQ AX, 24(DI)

	// Clear both CF and OF via XORQ, then STC -> ADCXQ sees CF=1, ADOXQ sees OF=0.
	XORQ R10, R10
	STC
	MOVQ R8, R12
	ADCXQ R9, R12
	MOVQ R12, 32(DI)
	MOVQ R8, R12
	ADOXQ R9, R12
	MOVQ R12, 40(DI)
	RET

// diffPCMPESTRI0C tests SSE4.2 PCMPESTRI $0x0c (reg-reg & mem-reg) including short EDX/EAX and exact flags.
TEXT ·diffPCMPESTRI0C(SB), NOSPLIT, $0-40
	MOVQ needle+0(FP), R8
	MOVQ hay+8(FP), R9
	MOVQ nLen+16(FP), AX
	MOVQ hLen+24(FP), DX
	MOVQ out+32(FP), DI

	// [0] reg-reg ECX, [1] flags (LAHF&0xd7 | OF<<8)
	MOVOU (R8), X0
	MOVOU (R9), X1
	PCMPESTRI $0x0c, X1, X0
	MOVQ $0, R10
	MOVL CX, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 0(DI)
	MOVQ AX, 8(DI)

	// [2] mem-reg ECX, [3] flags
	MOVQ nLen+16(FP), AX
	MOVQ hLen+24(FP), DX
	MOVOU (R8), X0
	PCMPESTRI $0x0c, (R9), X0
	MOVQ $0, R10
	MOVL CX, R10
	MOVQ $0, AX
	LAHF
	MOVQ $0, BX
	SETOS BL
	SHRQ $8, AX
	ANDQ $0xd7, AX
	SHLQ $8, BX
	ORQ BX, AX
	MOVQ R10, 16(DI)
	MOVQ AX, 24(DI)

	// [4..7] SSSE3 PALIGNR boundary verification ($4, $16, $20, $33) against native amd64!
	MOVOU (R8), X0
	MOVOU (R9), X1
	MOVOA X1, X2
	PALIGNR $4, X0, X2
	MOVQ X2, 32(DI)
	MOVOA X1, X2
	PALIGNR $16, X0, X2
	MOVQ X2, 40(DI)
	MOVOA X1, X2
	PALIGNR $20, X0, X2
	MOVQ X2, 48(DI)
	MOVOA X1, X2
	PALIGNR $33, X0, X2
	MOVQ X2, 56(DI)
	RET

// Standard FIPS 180-4 SHA-256 K constants (64 uint32 words) and byte-swap shuffle mask.
DATA diffSHABswap<>+0(SB)/8, $0x0405060700010203
DATA diffSHABswap<>+8(SB)/8, $0x0c0d0e0f08090a0b
GLOBL diffSHABswap<>(SB), RODATA|NOPTR, $16

DATA diffSHA1Bswap<>+0(SB)/8, $0x08090a0b0c0d0e0f
DATA diffSHA1Bswap<>+8(SB)/8, $0x0001020304050607
GLOBL diffSHA1Bswap<>(SB), RODATA|NOPTR, $16

DATA diffSHA1UpperMask<>+0(SB)/8, $0x0000000000000000
DATA diffSHA1UpperMask<>+8(SB)/8, $0xffffffff00000000
GLOBL diffSHA1UpperMask<>(SB), RODATA|NOPTR, $16

DATA diffK256<>+0(SB)/4, $0x428a2f98
DATA diffK256<>+4(SB)/4, $0x71374491
DATA diffK256<>+8(SB)/4, $0xb5c0fbcf
DATA diffK256<>+12(SB)/4, $0xe9b5dba5
DATA diffK256<>+16(SB)/4, $0x3956c25b
DATA diffK256<>+20(SB)/4, $0x59f111f1
DATA diffK256<>+24(SB)/4, $0x923f82a4
DATA diffK256<>+28(SB)/4, $0xab1c5ed5
DATA diffK256<>+32(SB)/4, $0xd807aa98
DATA diffK256<>+36(SB)/4, $0x12835b01
DATA diffK256<>+40(SB)/4, $0x243185be
DATA diffK256<>+44(SB)/4, $0x550c7dc3
DATA diffK256<>+48(SB)/4, $0x72be5d74
DATA diffK256<>+52(SB)/4, $0x80deb1fe
DATA diffK256<>+56(SB)/4, $0x9bdc06a7
DATA diffK256<>+60(SB)/4, $0xc19bf174
DATA diffK256<>+64(SB)/4, $0xe49b69c1
DATA diffK256<>+68(SB)/4, $0xefbe4786
DATA diffK256<>+72(SB)/4, $0x0fc19dc6
DATA diffK256<>+76(SB)/4, $0x240ca1cc
DATA diffK256<>+80(SB)/4, $0x2de92c6f
DATA diffK256<>+84(SB)/4, $0x4a7484aa
DATA diffK256<>+88(SB)/4, $0x5cb0a9dc
DATA diffK256<>+92(SB)/4, $0x76f988da
DATA diffK256<>+96(SB)/4, $0x983e5152
DATA diffK256<>+100(SB)/4, $0xa831c66d
DATA diffK256<>+104(SB)/4, $0xb00327c8
DATA diffK256<>+108(SB)/4, $0xbf597fc7
DATA diffK256<>+112(SB)/4, $0xc6e00bf3
DATA diffK256<>+116(SB)/4, $0xd5a79147
DATA diffK256<>+120(SB)/4, $0x06ca6351
DATA diffK256<>+124(SB)/4, $0x14292967
DATA diffK256<>+128(SB)/4, $0x27b70a85
DATA diffK256<>+132(SB)/4, $0x2e1b2138
DATA diffK256<>+136(SB)/4, $0x4d2c6dfc
DATA diffK256<>+140(SB)/4, $0x53380d13
DATA diffK256<>+144(SB)/4, $0x650a7354
DATA diffK256<>+148(SB)/4, $0x766a0abb
DATA diffK256<>+152(SB)/4, $0x81c2c92e
DATA diffK256<>+156(SB)/4, $0x92722c85
DATA diffK256<>+160(SB)/4, $0xa2bfe8a1
DATA diffK256<>+164(SB)/4, $0xa81a664b
DATA diffK256<>+168(SB)/4, $0xc24b8b70
DATA diffK256<>+172(SB)/4, $0xc76c51a3
DATA diffK256<>+176(SB)/4, $0xd192e819
DATA diffK256<>+180(SB)/4, $0xd6990624
DATA diffK256<>+184(SB)/4, $0xf40e3585
DATA diffK256<>+188(SB)/4, $0x106aa070
DATA diffK256<>+192(SB)/4, $0x19a4c116
DATA diffK256<>+196(SB)/4, $0x1e376c08
DATA diffK256<>+200(SB)/4, $0x2748774c
DATA diffK256<>+204(SB)/4, $0x34b0bcb5
DATA diffK256<>+208(SB)/4, $0x391c0cb3
DATA diffK256<>+212(SB)/4, $0x4ed8aa4a
DATA diffK256<>+216(SB)/4, $0x5b9cca4f
DATA diffK256<>+220(SB)/4, $0x682e6ff3
DATA diffK256<>+224(SB)/4, $0x748f82ee
DATA diffK256<>+228(SB)/4, $0x78a5636f
DATA diffK256<>+232(SB)/4, $0x84c87814
DATA diffK256<>+236(SB)/4, $0x8cc70208
DATA diffK256<>+240(SB)/4, $0x90befffa
DATA diffK256<>+244(SB)/4, $0xa4506ceb
DATA diffK256<>+248(SB)/4, $0xbef9a3f7
DATA diffK256<>+252(SB)/4, $0xc67178f2
GLOBL diffK256<>(SB), RODATA|NOPTR, $256

// diffSHA256Block executes a complete 64-round FIPS 180-4 SHA-256 block compression
// using SHA256RNDS2, SHA256MSG1, and SHA256MSG2.
TEXT ·diffSHA256Block(SB), NOSPLIT, $0-16
	MOVQ state+0(FP), DI
	MOVQ block+8(FP), SI
	LEAQ diffK256<>(SB), AX
	MOVOU diffSHABswap<>(SB), X8

	// Load state: X1 = [F, E, B, A], X2 = [H, G, D, C]
	MOVOU (DI), X1
	MOVOU 16(DI), X2
	PSHUFD $0xb1, X1, X1
	PSHUFD $0x1b, X2, X2
	MOVOA X1, X7
	PALIGNR $8, X2, X1
	PBLENDW $0xf0, X7, X2
	MOVOA X1, X9
	MOVOA X2, X10

	// Rounds 0..3
	MOVOU 0(SI), X0
	PSHUFB X8, X0
	MOVOA X0, X3
	PADDD 0(AX), X0
	SHA256RNDS2 X0, X1, X2
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1

	// Rounds 4..7
	MOVOU 16(SI), X0
	PSHUFB X8, X0
	MOVOA X0, X4
	PADDD 16(AX), X0
	SHA256RNDS2 X0, X1, X2
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X4, X3

	// Rounds 8..11
	MOVOU 32(SI), X0
	PSHUFB X8, X0
	MOVOA X0, X5
	PADDD 32(AX), X0
	SHA256RNDS2 X0, X1, X2
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X5, X4

	// Rounds 12..15
	MOVOU 48(SI), X0
	PSHUFB X8, X0
	MOVOA X0, X6
	PADDD 48(AX), X0
	SHA256RNDS2 X0, X1, X2
	MOVOA X6, X7
	PALIGNR $4, X5, X7
	PADDD X7, X3
	SHA256MSG2 X6, X3
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X6, X5

	// Loop rounds 16..51 (9 groups of 4 = 36 rounds, wait: unroll 12 groups of 4 for 16..63 in a 3-iteration loop of 16 rounds!)
	ADDQ $64, AX
	MOVQ $3, CX
sha256_loop:
	// Group +0 (msg in X3, prev X6, X5)
	MOVOA X3, X0
	PADDD 0(AX), X0
	SHA256RNDS2 X0, X1, X2
	MOVOA X3, X7
	PALIGNR $4, X6, X7
	PADDD X7, X4
	SHA256MSG2 X3, X4
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X3, X6

	// Group +4 (msg in X4, prev X3, X6)
	MOVOA X4, X0
	PADDD 16(AX), X0
	SHA256RNDS2 X0, X1, X2
	MOVOA X4, X7
	PALIGNR $4, X3, X7
	PADDD X7, X5
	SHA256MSG2 X4, X5
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X4, X3

	// Group +8 (msg in X5, prev X4, X3)
	MOVOA X5, X0
	PADDD 32(AX), X0
	SHA256RNDS2 X0, X1, X2
	MOVOA X5, X7
	PALIGNR $4, X4, X7
	PADDD X7, X6
	SHA256MSG2 X5, X6
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X5, X4

	// Group +12 (msg in X6, prev X5, X4)
	MOVOA X6, X0
	PADDD 48(AX), X0
	SHA256RNDS2 X0, X1, X2
	MOVOA X6, X7
	PALIGNR $4, X5, X7
	PADDD X7, X3
	SHA256MSG2 X6, X3
	PSHUFD $0x0e, X0, X0
	SHA256RNDS2 X0, X2, X1
	SHA256MSG1 X6, X5

	ADDQ $64, AX
	DECQ CX
	JNE sha256_loop

	// Add saved state and unpack [A,B,C,D], [E,F,G,H]
	PADDD X9, X1
	PADDD X10, X2
	PSHUFD $0x1b, X1, X1
	PSHUFD $0xb1, X2, X2
	MOVOA X1, X7
	PBLENDW $0xf0, X2, X1
	PALIGNR $8, X7, X2
	MOVOU X1, (DI)
	MOVOU X2, 16(DI)
	RET

// diffSHA1Block executes a complete 80-round FIPS 180-4 SHA-1 block compression
// using SHA1RNDS4, SHA1NEXTE, SHA1MSG1, and SHA1MSG2.
TEXT ·diffSHA1Block(SB), NOSPLIT, $0-16
	MOVQ state+0(FP), DI
	MOVQ block+8(FP), SI
	MOVOU diffSHA1Bswap<>(SB), X7
	MOVOU diffSHA1UpperMask<>(SB), X8

	// Load state: X0 = [D, C, B, A], X5 = [0, 0, 0, E]
	MOVOU (DI), X0
	PXOR X5, X5
	PINSRD $3, 16(DI), X5
	PAND X8, X5
	PSHUFD $0x1b, X0, X0
	MOVOA X0, X9
	MOVOA X5, X10

	// Rounds 0..3
	MOVOU 0(SI), X1
	PSHUFB X7, X1
	PADDD X1, X5
	MOVOA X0, X6
	SHA1RNDS4 $0, X5, X0

	// Rounds 4..7
	MOVOU 16(SI), X2
	PSHUFB X7, X2
	SHA1NEXTE X2, X6
	MOVOA X0, X5
	SHA1RNDS4 $0, X6, X0
	SHA1MSG1 X2, X1

	// Rounds 8..11
	MOVOU 32(SI), X3
	PSHUFB X7, X3
	SHA1NEXTE X3, X5
	MOVOA X0, X6
	SHA1RNDS4 $0, X5, X0
	SHA1MSG1 X3, X2
	PXOR X3, X1

	// Rounds 12..15
	MOVOU 48(SI), X4
	PSHUFB X7, X4
	SHA1NEXTE X4, X6
	MOVOA X0, X5
	SHA1MSG2 X4, X1
	SHA1RNDS4 $0, X6, X0
	SHA1MSG1 X4, X3
	PXOR X4, X2

	// Rounds 16..19
	SHA1NEXTE X1, X5
	MOVOA X0, X6
	SHA1MSG2 X1, X2
	SHA1RNDS4 $0, X5, X0
	SHA1MSG1 X1, X4
	PXOR X1, X3

	// Rounds 20..39 (func=1)
	MOVQ $1, CX
sha1_r20:
	SHA1NEXTE X2, X6
	MOVOA X0, X5
	SHA1MSG2 X2, X3
	SHA1RNDS4 $1, X6, X0
	SHA1MSG1 X2, X1
	PXOR X2, X4

	SHA1NEXTE X3, X5
	MOVOA X0, X6
	SHA1MSG2 X3, X4
	SHA1RNDS4 $1, X5, X0
	SHA1MSG1 X3, X2
	PXOR X3, X1

	SHA1NEXTE X4, X6
	MOVOA X0, X5
	SHA1MSG2 X4, X1
	SHA1RNDS4 $1, X6, X0
	SHA1MSG1 X4, X3
	PXOR X4, X2

	SHA1NEXTE X1, X5
	MOVOA X0, X6
	SHA1MSG2 X1, X2
	SHA1RNDS4 $1, X5, X0
	SHA1MSG1 X1, X4
	PXOR X1, X3

	SHA1NEXTE X2, X6
	MOVOA X0, X5
	SHA1MSG2 X2, X3
	SHA1RNDS4 $1, X6, X0
	SHA1MSG1 X2, X1
	PXOR X2, X4
	DECQ CX
	JNE sha1_r20

	// Rounds 40..59 (func=2)
	SHA1NEXTE X3, X5
	MOVOA X0, X6
	SHA1MSG2 X3, X4
	SHA1RNDS4 $2, X5, X0
	SHA1MSG1 X3, X2
	PXOR X3, X1

	SHA1NEXTE X4, X6
	MOVOA X0, X5
	SHA1MSG2 X4, X1
	SHA1RNDS4 $2, X6, X0
	SHA1MSG1 X4, X3
	PXOR X4, X2

	SHA1NEXTE X1, X5
	MOVOA X0, X6
	SHA1MSG2 X1, X2
	SHA1RNDS4 $2, X5, X0
	SHA1MSG1 X1, X4
	PXOR X1, X3

	SHA1NEXTE X2, X6
	MOVOA X0, X5
	SHA1MSG2 X2, X3
	SHA1RNDS4 $2, X6, X0
	SHA1MSG1 X2, X1
	PXOR X2, X4

	SHA1NEXTE X3, X5
	MOVOA X0, X6
	SHA1MSG2 X3, X4
	SHA1RNDS4 $2, X5, X0
	SHA1MSG1 X3, X2
	PXOR X3, X1

	// Rounds 60..79 (func=3)
	SHA1NEXTE X4, X6
	MOVOA X0, X5
	SHA1MSG2 X4, X1
	SHA1RNDS4 $3, X6, X0
	SHA1MSG1 X4, X3
	PXOR X4, X2

	SHA1NEXTE X1, X5
	MOVOA X0, X6
	SHA1MSG2 X1, X2
	SHA1RNDS4 $3, X5, X0
	SHA1MSG1 X1, X4
	PXOR X1, X3

	SHA1NEXTE X2, X6
	MOVOA X0, X5
	SHA1MSG2 X2, X3
	SHA1RNDS4 $3, X6, X0
	SHA1MSG1 X2, X1
	PXOR X2, X4

	SHA1NEXTE X3, X5
	MOVOA X0, X6
	SHA1MSG2 X3, X4
	SHA1RNDS4 $3, X5, X0

	SHA1NEXTE X4, X6
	MOVOA X0, X5
	SHA1RNDS4 $3, X6, X0

	// Combine with saved state
	SHA1NEXTE X10, X5
	PADDD X9, X0
	PSHUFD $0x1b, X0, X0
	MOVOU X0, (DI)
	PEXTRD $3, X5, 16(DI)
	RET
