package plan9asm

import (
	"strings"
	"testing"
)

func x86MOVBERepairedRuntimeSource(t *testing.T) string {
	t.Helper()
	source := strings.Replace(x86MOVBEOriginalRuntimeSource, "MOVQ $0xefcdab8967452301, 32(DI)",
		"MOVQ $0xefcdab8967452301, R9\n\tMOVQ R9, 32(DI)", 1)
	if source == x86MOVBEOriginalRuntimeSource {
		t.Fatal("original MOVBE fixture lost its identified invalid imm64 store")
	}
	return source
}

const x86MOVBEOriginalRuntimeSource = `TEXT movesemantics(SB),NOSPLIT,$0-8
	MOVQ out+0(FP), DI
	MOVL $0x7fffffff, R8
	ADDL $1, R8
	STC

	MOVW $0x3412, 0(DI)
	MOVQ $0x1122334455667788, AX
	MOVBEW 0(DI), AX
	MOVQ AX, 8(DI)

	MOVL $0x78563412, 16(DI)
	MOVBEL 16(DI), BX
	MOVQ BX, 24(DI)

	MOVQ $0xefcdab8967452301, 32(DI)
	MOVBEQ 32(DI), CX
	MOVQ CX, 40(DI)

	MOVQ $0x1122334455667788, AX
	MOVBEW AX, 48(DI)
	MOVBEL AX, 50(DI)
	MOVBEQ AX, 54(DI)

	SETCS 62(DI)
	SETOS 63(DI)
	SETEQ 64(DI)
	SETMI 65(DI)
	RET
`
