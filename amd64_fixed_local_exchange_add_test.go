package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalExchangeOriginalObjects(t *testing.T) {
	for _, family := range []string{"XADD", "XCHG"} {
		t.Run(family, func(t *testing.T) {
			rows := []string{
				family + "W DX, (BX)", family + "L DX, (BX)", family + "Q DX, (BX)",
				family + "B DL, (BX)", family + "B R11, (BX)",
			}
			var assembly, declarations strings.Builder
			for index, row := range rows {
				name := fmt.Sprintf("Value%d", index)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\nMOVQ a+0(FP),AX\n", name)
				assembly.WriteString("MOVQ AX,64(SP)\nNOTQ AX\nMOVQ AX,DX\nROLQ $13,AX\nMOVQ AX,R11\nLEAQ 64(SP),BX\n")
				fmt.Fprintf(&assembly, "%s\nMOVQ 64(SP),AX\nXORQ DX,AX\nXORQ R11,AX\nMOVQ AX,ret+8(FP)\nRET\n", row)
				fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			}
			fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
		})
	}
}

func TestGoAMD64FixedLocalXADDExactReadWriteAndFlags(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"byte", "MOVB $7,127(SP)\nMOVQ AX,DX\nXADDB DL,127(SP)", true},
		{"word", "MOVW $7,126(SP)\nMOVQ AX,DX\nXADDW DX,126(SP)", true},
		{"dword", "MOVL $7,124(SP)\nMOVQ AX,DX\nXADDL DX,124(SP)", true},
		{"unaligned qword", "MOVQ $7,119(SP)\nMOVQ AX,DX\nXADDQ DX,119(SP)", true},
		{"register overlap", "MOVQ AX,DX\nXADDB DL,DH", true},
		{"register self", "MOVQ AX,DX\nXADDQ DX,DX", true},
		{"undefined source", "MOVB $7,127(SP)\nXADDB DL,127(SP)", false},
		{"undefined destination byte", "MOVB $7,126(SP)\nMOVQ AX,DX\nXADDW DX,126(SP)", false},
		{"overrun destination", "MOVQ $7,120(SP)\nMOVQ AX,DX\nXADDQ DX,121(SP)", false},
		{"relocated input bits", "MOVQ $7,120(SP)\nLEAQ 64(SP),DX\nXADDQ DX,120(SP)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\n" + row.body +
				"\nSETOS CL\nMOVQ DX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private exchange-add source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
