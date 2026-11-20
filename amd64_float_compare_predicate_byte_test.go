package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86FloatingCompareGrammarPreservesWholePredicateByte(t *testing.T) {
	for _, opcode := range []string{"CMPPS", "CMPPD", "CMPSS", "CMPSD", "VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"} {
		t.Run(opcode, func(t *testing.T) {
			for immediate := 0; immediate < 256; immediate++ {
				row := fmt.Sprintf("%s X1,X0,$%d", opcode, int8(immediate))
				if strings.HasPrefix(opcode, "V") {
					row = fmt.Sprintf("%s $%d,X1,X0,X2", opcode, immediate)
				}
				file, err := Parse(ArchAMD64, "TEXT f(SB),4,$0-0\n"+row+"\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				form, known, err := x86FloatCompareProperties(file.Funcs[0].Instrs[1], "amd64")
				if !known || err != nil {
					t.Fatalf("accepted predicate byte %d was not represented: %s: %v", immediate, row, err)
				}
				if form.immediate != uint8(immediate) {
					t.Fatalf("typed grammar folded source predicate byte: %s: got=%d want=%d", row, form.immediate, immediate)
				}
			}
		})
	}
}
