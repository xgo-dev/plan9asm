#include "textflag.h"

// diffCPUID executes CPUID(leaf, subleaf) and stores EAX, EBX, ECX, EDX in out.
TEXT ·diffCPUID(SB), NOSPLIT, $0-16
	MOVL leaf+0(FP), AX
	MOVL subleaf+4(FP), CX
	CPUID
	MOVQ out+8(FP), DI
	MOVL AX, 0(DI)
	MOVL BX, 4(DI)
	MOVL CX, 8(DI)
	MOVL DX, 12(DI)
	RET
