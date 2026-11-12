//go:build go1.27

package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type fixedLocalCountedLoopAliasCase struct {
	offsets []int
}

func fixedLocalCountedLoopAliasProgram(t *testing.T) (string, string, []fixedLocalCountedLoopAliasCase) {
	t.Helper()
	var assembly, declarations strings.Builder
	var cases []fixedLocalCountedLoopAliasCase
	for _, step := range []int{1, 4} {
		for _, descending := range []bool{false, true} {
			first, limit, update, branch := 0, 4*step, "ADDQ", "JB"
			if descending {
				first, limit, update, branch = 4*step, 0, "SUBQ", "JA"
			}
			var body strings.Builder
			body.WriteString("MOVQ $77,248(SP)\nMOVQ a+0(FP),DI\nANDQ $1,DI\nADDQ $1,DI\nMOVQ $0,DX\nouter:\n")
			fmt.Fprintf(&body, "MOVQ $%d,SI\nloop:\nMOVQ AX,BX\nADDQ SI,BX\n"+
				"MOVQ BX,16(SP)(SI*1)\nADDQ $2,16(SP)(SI*1)\n"+
				"%s $%d,SI\nCMPQ SI,$%d\n%s loop\n"+
				"ADDQ $1,DX\nCMPQ DX,DI\nJB outer\nMOVQ $0,AX\n", first, update, step, limit, branch)
			var offsets []int
			for iteration := 0; iteration < 4; iteration++ {
				offset := iteration * step
				if descending {
					offset = (4 - iteration) * step
				}
				offsets = append(offsets, offset)
				fmt.Fprintf(&body, "ADDQ %d(SP),AX\n", 16+offset)
			}
			body.WriteString("ADDQ 248(SP),AX")
			_, _, source := fixedLocalCountedLoopFixture(t, body.String())
			name := fmt.Sprintf("Value%d", len(cases))
			assembly.WriteString(strings.Replace(source, "·Value", "·"+name, 1))
			fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
			cases = append(cases, fixedLocalCountedLoopAliasCase{offsets})
		}
	}
	if len(cases) != 4 {
		t.Fatal("overlapping-iteration inventory changed", len(cases))
	}
	return assembly.String(), declarations.String(), cases
}

func TestGoAMD64FixedLocalCountedLoopAliasObjects(t *testing.T) {
	assembly, declarations, cases := fixedLocalCountedLoopAliasProgram(t)
	fixedLocalCountedLoopObjects(t, assembly, declarations, len(cases))
}
