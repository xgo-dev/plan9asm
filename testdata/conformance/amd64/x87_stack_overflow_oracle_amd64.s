#include "textflag.h"

// Native amd64 hardware oracle for Round 14 P1 (x87 stack overflow across
// CFG branch joins with differing stack depths) and Round 16 P1 (cross-CALL
// x87 TOP divergence between CALL reset vs CALL nop).
//
// These functions are compiled ONLY by Go's native amd64 assembler so
// amd64-diff-gate records real silicon results for:
//   - fixed 8 pushes:                  SF|IE == 0x00
//   - fixed 9 pushes:                  SF|IE == 0x41
//   - dynamic 7/8 + 1 (x != 0 extra):  x=0 -> 0x00, x!=0 -> 0x41
//   - dynamic 7/8 + 1 swapped (x == 0): x=0 -> 0x41, x!=0 -> 0x00
//   - inline FINIT vs CALL reset:      M7 == 0x8000000000000000, TOP == 0x3800
//   - CALL nop (RET only):             M7 == 123,                TOP == 0x3000
//
// Each function resets the x87 FPU with FINIT before RET so the Go runtime
// observes a clean x87 register stack.

TEXT ·x87OracleFixed8(SB), NOSPLIT, $0-8
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
	ANDQ $0x41, AX
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleFixed9(SB), NOSPLIT, $0-8
	FINIT
	FLD1
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
	ANDQ $0x41, AX
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleDynBranch78(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	FINIT
	MOVQ AX, ret+8(FP)
	RET

TEXT ·x87OracleDynBranch78Swapped(SB), NOSPLIT, $0-16
	MOVQ x+0(FP), CX
	FINIT
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	FLD1
	CMPQ CX, $0
	JNE skip
	FLD1
skip:
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x41, AX
	FINIT
	MOVQ AX, ret+8(FP)
	RET

TEXT x87OracleReset<>(SB), NOSPLIT, $0-0
	FINIT
	RET

TEXT x87OracleNop<>(SB), NOSPLIT, $0-0
	RET

TEXT ·x87OracleInlineFinit(SB), NOSPLIT, $0-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	FINIT
	FLD1
	MOVQ M7, AX
	EMMS
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleCallReset(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	CALL x87OracleReset<>(SB)
	FLD1
	MOVQ M7, AX
	EMMS
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleCallNop(SB), NOSPLIT, $8-8
	MOVQ $123, AX
	MOVQ AX, M7
	FDECSTP
	CALL x87OracleNop<>(SB)
	FLD1
	MOVQ M7, AX
	EMMS
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleCallResetEmptyTop(SB), NOSPLIT, $8-8
	FINIT
	FDECSTP
	CALL x87OracleReset<>(SB)
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	FINIT
	MOVQ AX, ret+0(FP)
	RET

TEXT ·x87OracleCallNopEmptyTop(SB), NOSPLIT, $8-8
	FINIT
	FDECSTP
	CALL x87OracleNop<>(SB)
	FLD1
	MOVQ $0, AX
	FSTSW AX
	ANDQ $0x3800, AX
	FINIT
	MOVQ AX, ret+0(FP)
	RET
