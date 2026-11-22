package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalCompareExchangeOriginalObjects(t *testing.T) {
	var assembly, declarations strings.Builder
	rows := []string{
		"CMPXCHGW DX,(BX)", "CMPXCHGL DX,(BX)", "CMPXCHGQ DX,(BX)",
		"CMPXCHGB DL,(BX)", "CMPXCHGB R11,(BX)",
		"CMPXCHG8B (SI)", "CMPXCHG16B (SI)",
	}
	for index, row := range rows {
		name := fmt.Sprintf("Value%d", index)
		fmt.Fprintf(&assembly, "TEXT ·%s(SB),4,$128-16\n", name)
		assembly.WriteString("MOVQ a+0(FP),AX\nXORQ CX,CX\n")
		if index < 5 {
			assembly.WriteString("MOVQ AX,63(SP)\nLEAQ 63(SP),BX\n")
			assembly.WriteString("MOVQ AX,DX\nNOTQ DX\nMOVQ DX,R11\n")
			fmt.Fprintf(&assembly, "%s\nSETEQ CL\nMOVQ 63(SP),R8\n", row)
		} else {
			assembly.WriteString("LEAQ 64(SP),SI\nANDQ $-16,SI\nMOVQ AX,(SI)\nMOVQ CX,8(SI)\n")
			assembly.WriteString("MOVQ AX,BX\nNOTQ BX\nXORQ DX,DX\nSTC\n")
			fmt.Fprintf(&assembly, "%s\nSETEQ CL\nSETCS CH\nMOVQ (SI),R8\n", row)
		}
		assembly.WriteString("XORQ R8,AX\nXORQ CX,AX\nMOVQ AX,ret+8(FP)\nRET\n")
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
	}
	fixedLocalCompleteVectorObjects(t, assembly.String(), declarations.String(), len(rows))
}

func TestGoAMD64FixedLocalCompareExchangeSourceAndFlags(t *testing.T) {
	_, _, sig, _ := x86ResultInitializationFixture(t, "amd64", "func Value(a uint64) uint64", "RET")
	for _, row := range []struct {
		name, body string
		accept     bool
	}{
		{"byte initialized", "MOVQ R11,AX\nMOVB R11,127(SP)\nCMPXCHGB R11,127(SP)\nSETEQ CL", true},
		{"byte accumulator only", "MOVB R11,AL\nMOVB R11,127(SP)\nCMPXCHGB R11,127(SP)\nMOVBLZX AL,AX", true},
		{"word initialized", "MOVQ R11,AX\nMOVW R11,126(SP)\nCMPXCHGW R11,126(SP)\nSETCS CL", true},
		{"dword conditional accumulator", "MOVQ R11,AX\nMOVL R11,124(SP)\nCMPXCHGL R11,124(SP)", true},
		{"unaligned qword", "MOVQ R11,AX\nMOVQ R11,119(SP)\nCMPXCHGQ R11,119(SP)", true},
		{"register old value", "MOVQ R11,AX\nMOVQ R11,DX\nCMPXCHGQ R11,DX", true},
		{"pair qword retains CF", "MOVQ R11,AX\nMOVQ R11,BX\nMOVQ R11,DX\nMOVQ R11,119(SP)\nSTC\nCMPXCHG8B 119(SP)\nSETCS CL", true},
		{"pair oword aligned", "MOVQ R11,AX\nMOVQ R11,BX\nMOVQ R11,DX\nLEAQ 64(SP),SI\nANDQ $-16,SI\n" +
			"MOVQ AX,(SI)\nMOVQ DX,8(SI)\nCMPXCHG16B (SI)", true},
		{"unknown implicit accumulator", "MOVQ R11,120(SP)\nCMPXCHGQ R11,120(SP)", false},
		{"unknown memory byte", "MOVQ R11,AX\nMOVL R11,120(SP)\nCMPXCHGQ R11,120(SP)", false},
		{"crosses frame", "MOVQ R11,AX\nMOVQ R11,120(SP)\nCMPXCHGQ R11,121(SP)", false},
		{"relocated compare value", "LEAQ 64(SP),AX\nMOVQ R11,120(SP)\nCMPXCHGQ R11,120(SP)", false},
		{"unknown pair desired word", "MOVQ R11,AX\nMOVQ R11,DX\nMOVQ R11,120(SP)\nCMPXCHG8B 120(SP)", false},
		{"pair oword unaligned", "MOVQ R11,AX\nMOVQ R11,BX\nMOVQ R11,DX\nLEAQ 64(SP),SI\nANDQ $-16,SI\nADDQ $1,SI\n" +
			"MOVQ AX,(SI)\nMOVQ DX,8(SI)\nCMPXCHG16B (SI)", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "TEXT ·Value(SB),4,$128-16\nMOVQ a+0(FP),R11\nXORQ CX,CX\n" +
				row.body + "\nMOVQ AX,ret+8(FP)\nRET\n"
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = proveX86FixedLocal(file.Funcs[0], sig)
			if row.accept && err != nil || !row.accept && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("private compare-exchange source, accept=%t: %v", row.accept, err)
			}
		})
	}
}
