package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

// The arithmetic carrier must retain the same lane type as the horizontal
// shuffles. These are the complete register rows of Go's yxm/_yvaddsubpd
// tables, independently enumerated rather than derived from the emitter.
func TestX86HorizontalFloatArithmeticPreservesTypedLaneWidth(t *testing.T) {
	for _, opcode := range []string{
		"HADDPS", "HADDPD", "HSUBPS", "HSUBPD",
		"VHADDPS", "VHADDPD", "VHSUBPS", "VHSUBPD",
	} {
		banks := []string{"X"}
		vector := strings.HasPrefix(opcode, "V")
		if vector {
			banks = append(banks, "Y")
		}
		for _, bank := range banks {
			t.Run(opcode+"/"+bank, func(t *testing.T) {
				row := fmt.Sprintf("%s %s0,%s1", opcode, bank, bank)
				if vector {
					row += "," + bank + "2"
				}
				source := "TEXT f(SB),4,$0-0\n" + row + "\nRET\n"
				requireX86GoAssemblerResult(t, "amd64", source, true)
				ir := x86UnboundVoidScalarFormatObject(t, source, "f", "amd64", "x86_64-unknown-linux-gnu")
				width := 16
				if bank == "Y" {
					width = 32
				}
				call := fmt.Sprintf("call <%d x float> asm sideeffect", width/4)
				if strings.Count(ir, call) != 1 || !strings.Contains(ir, strings.ToLower(opcode)+" ") || !strings.Contains(ir, "~{fpsr}") {
					t.Fatalf("%s lost its complete typed arithmetic carrier %q", row, call)
				}
			})
		}
	}
}
