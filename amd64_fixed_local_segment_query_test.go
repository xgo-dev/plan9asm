package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalSegmentQueryOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	count := 0
	for _, group := range []struct {
		operations []string
		suffix     string
	}{
		{[]string{"VERR", "VERW"}, ""},
		{[]string{"LARW", "LARL", "LARQ", "LSLW", "LSLL", "LSLQ"}, ",DX"},
	} {
		for _, op := range group.operations {
			for _, selector := range []string{"(BX)", "R11"} {
				name := fmt.Sprintf("Value%d", count)
				fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\n", name)
				assembly.WriteString("MOVQ a+0(FP),R11\nMOVW R11,63(SP)\nLEAQ 63(SP),BX\n")
				assembly.WriteString("MOVQ $0x1122334455667788,DX\nXORQ CX,CX\nSTC\n")
				fmt.Fprintf(&assembly, "%s %s%s\nSETEQ CL\nSETCS CH\nXORQ CX,DX\nMOVQ DX,ret+8(FP)\nRET\n", op, selector, group.suffix)
				fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
				count++
			}
		}
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), count)
}

func TestGoAMD64FixedLocalSegmentQuerySelectorAndFlags(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"qword destination m16 source", "MOVW AX,126(SP)\nMOVQ AX,DX\nLARQ 126(SP),DX\nSETEQ CL", true},
		{"word upper bytes preserved", "MOVQ AX,DX\nLSLW AX,DX\nSETEQ CL", true},
		{"dword old upper bytes", "MOVQ AX,DX\nLARL AX,DX\nSETEQ CL", true},
		{"readability defines ZF", "VERR AX\nSETEQ CL\nMOVQ AX,DX", true},
		{"writability retains CF", "STC\nVERW AX\nSETCS CL\nMOVQ AX,DX", true},
		{"unknown prior upper", "MOVW AX,DX\nLSLL AX,DX", false},
		{"missing selector byte", "MOVB AX,126(SP)\nMOVQ AX,DX\nLARQ 126(SP),DX", false},
		{"overrun selector", "MOVW AX,126(SP)\nVERW 127(SP)\nMOVQ AX,DX", false},
		{"relocated destination", "LEAQ 64(SP),DX\nLSLQ AX,DX", false},
		{"relocated selector", "MOVQ AX,DX\nLEAQ 64(SP),AX\nVERR AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),AX\nXORQ CX,CX\n" +
				row.body + "\nMOVQ DX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private selector query source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
