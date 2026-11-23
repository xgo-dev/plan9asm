package plan9asm

import (
	"fmt"
	"strings"
)

func x86DirectTailInteriorCallFixture() (source, declarations string) {
	return `TEXT ·Entry(SB),516,$0-4
 CALL helper<>(SB)
 MOVL AX,ret+0(FP)
 RET
TEXT ·Interior(SB),516,$0-4
 CALL helper<>+6(SB)
 MOVL AX,ret+0(FP)
 RET
TEXT ·Grouped(SB),516,$0-4
 CALL helper<>+6(SB)(AX*4)
 MOVL AX,ret+0(FP)
 RET
TEXT ·Starred(SB),516,$0-4
 CALL *helper<>+6(SB)(AX*4)
 MOVL AX,ret+0(FP)
 RET
TEXT helper<>(SB),516,$0-0
 MOVL $11,AX
 RET
alternate:
 MOVL $73,AX
 RET
`, "func Entry() uint32\nfunc Interior() uint32\nfunc Grouped() uint32\nfunc Starred() uint32\n"
}

func x86DirectTailNamedInteriorCallFixture(arch, symbol string, flags int) (source, declarations string) {
	resultOffset := goWordSize(arch)
	return fmt.Sprintf(`TEXT ·Interior(SB),516,$0-%d
 MOVL value+0(FP),AX
 CALL %s+4(SB)(AX*4)
 MOVL AX,ret+%d(FP)
 RET
TEXT %s(SB),%d,$0-0
 XORL AX,AX
 XORL BX,BX
 ADDL $73,AX
 RET
`, resultOffset+4, symbol, resultOffset, symbol, flags),
		"func Interior(value uint32) uint32\nfunc " + strings.TrimPrefix(symbol, "·") + "()\n"
}

// One complete ordinary source file composes the three independent roles.
// Two differently typed roots share a helper and retain distinct result slots.
func x86DirectTailFollowupFixture(arch string) (source, declarations string) {
	word, width, typ := "Q", 8, "uint64"
	if arch == "386" {
		word, width, typ = "L", 4, "uint32"
	}
	declarations = fmt.Sprintf("func Forward(a %s) %s\nfunc Address(a %s) %s\nfunc Alternate(a,b %s) %s\nfunc Backward(a %s) %s\nfunc ordinary(a %s) %s\n", typ, typ, typ, typ, typ, typ, typ, typ, typ, typ)
	source = fmt.Sprintf(`TEXT ·Forward(SB),NOSPLIT,$0-%d
 MOVWORD a+0(FP),SI
 CMPWORD SI,$0
 JEQ $1,2(PC)
 JMP ·ordinary(SB)
 LEAWORD ret+%d(FP),DI
 JMP shared<>(SB)
TEXT ·Address(SB),NOSPLIT,$0-%d
 MOVWORD a+0(FP),SI
 LEAWORD ret+%d(FP),DI
 JMP shared<>(SB)
TEXT ·Alternate(SB),NOSPLIT,$0-%d
 MOVWORD a+0(FP),SI
 MOVWORD b+%d(FP),BX
 ADDWORD BX,SI
 LEAWORD ret+%d(FP),DI
 JMP shared<>(SB)
TEXT ·Backward(SB),NOSPLIT,$0-%d
 MOVWORD a+0(FP),SI
 MOVWORD $0,BX
start:
 ADDWORD $1,BX
 SUBWORD $1,SI
 JNE -2(PC)
 LEAWORD ret+%d(FP),DI
 MOVWORD BX,SI
 JMP shared<>(SB)
TEXT shared<>(SB),NOSPLIT,$0-0
 MOVWORD DI,CX
 LEAWORD 1(CX),DX
 LEAWORD -1(DX),CX
 ADDWORD $7,SI
 MOVWORD SI,(CX)
 MOVWORD (CX),BX
 CMPWORD BX,$0
 JEQ 2(PC)
 MOVWORD BX,(CX)
 RET
`, 2*width, width, 2*width, width, 3*width, width, 2*width, 2*width, width)
	// A numeric NOSPLIT flag keeps this independently assembled fixture free
	// of an implicit textflag.h input; the complete original source is retained.
	return strings.ReplaceAll(strings.ReplaceAll(source, "WORD", word), "NOSPLIT", "4"), declarations
}
