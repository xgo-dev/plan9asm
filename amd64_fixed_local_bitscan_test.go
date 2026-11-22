package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalBitScanOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	count := 0
	for _, family := range []string{"BSF", "BSR"} {
		for _, suffix := range []string{"W", "L", "Q"} {
			for _, source := range []string{"(BX)", "R11"} {
				name := fmt.Sprintf("Value%d", count)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\n", name)
				assembly.WriteString("MOVQ a+0(FP),R11\nMOVQ R11,64(SP)\nLEAQ 64(SP),BX\n")
				assembly.WriteString("MOVQ $0x1122334455667788,DX\nXORQ CX,CX\n")
				fmt.Fprintf(&assembly, "%s%s %s,DX\nSETEQ CL\nXORQ CX,DX\nMOVQ DX,ret+8(FP)\nRET\n", family, suffix, source)
				fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
				count++
			}
		}
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalBitScanSourceAndFlags(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"word exact span", "MOVW AX,126(SP)\nMOVQ AX,DX\nBSFW 126(SP),DX\nSETEQ CL", true},
		{"dword exact span", "MOVL AX,124(SP)\nMOVQ AX,DX\nBSRL 124(SP),DX\nSETEQ CL", true},
		{"qword unaligned", "MOVQ AX,119(SP)\nMOVQ AX,DX\nBSRQ 119(SP),DX\nSETEQ CL", true},
		{"register alias", "MOVQ AX,DX\nBSFW DX,DX\nSETEQ CL", true},
		{"missing prior upper", "MOVW AX,DX\nBSFW AX,DX\nSETEQ CL", false},
		{"missing source byte", "MOVB AX,126(SP)\nMOVQ AX,DX\nBSFW 126(SP),DX\nSETEQ CL", false},
		{"overrun source", "MOVQ AX,120(SP)\nMOVQ AX,DX\nBSRQ 121(SP),DX\nSETEQ CL", false},
		{"undefined carry", "MOVQ AX,DX\nSTC\nBSFQ AX,DX\nSETCS CL", false},
		{"address as prior", "LEAQ 64(SP),DX\nBSFQ AX,DX\nSETEQ CL", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			file, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\nXORQ CX,CX\n"+row.body+"\nMOVQ DX,ret+8(FP)\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private bit-scan source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
