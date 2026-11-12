package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalFiveWayPointerBody(final string, spill bool) string {
	var body strings.Builder
	join := "JMP joined\n"
	if spill {
		join = "MOVQ CX,8(SP)\n" + join
	}
	for index := 0; index < 4; index++ {
		fmt.Fprintf(&body, "CMPQ AX,$%d\nJE choice%d\n", index, index)
	}
	body.WriteString("LEAQ choice<>+32(SB),CX\n" + join)
	for index := 0; index < 4; index++ {
		fmt.Fprintf(&body, "choice%d:\nLEAQ choice<>+%d(SB),CX\n%s", index, index*8, join)
	}
	body.WriteString("joined:\n" + final)
	return body.String()
}

type fixedLocalPointerChoiceCFGCase struct {
	name, final  string
	spill, fails bool
}

func fixedLocalPointerChoiceCFGCases() []fixedLocalPointerChoiceCFGCase {
	return []fixedLocalPointerChoiceCFGCase{
		{"dead address", "", false, false},
		{"fully overwritten address", "MOVQ $99,CX\nMOVQ CX,AX", false, false},
		{"unknown address is not NUM", "MOVQ CX,AX", false, true},
		{"more than four addresses remain readable", "MOVQ (CX),AX", false, false},
		{"dead pointer spill", "", true, false},
		{"fully overwritten spill", "MOVQ $99,8(SP)\nMOVQ 8(SP),AX", true, false},
		{"unknown spill is not NUM", "MOVQ 8(SP),AX", true, true},
		{"more than four spilled addresses remain readable", "MOVQ 8(SP),CX\nMOVQ (CX),AX", true, false},
	}
}

func fixedLocalPointerChoiceAllPositiveCases() []fixedLocalPointerChoiceCase {
	rows := fixedLocalPointerChoiceCases()
	for _, row := range fixedLocalPointerChoiceCFGCases() {
		if !row.fails {
			rows = append(rows, fixedLocalPointerChoiceCase{row.name, fixedLocalFiveWayPointerBody(row.final, row.spill)})
		}
	}
	return rows
}

func TestGoAMD64FixedLocalPointerChoiceDeadCFGOrigins(t *testing.T) {
	var original strings.Builder
	original.WriteString(fixedLocalChoiceData)
	for index, row := range fixedLocalPointerChoiceCFGCases() {
		fn, sig, source := fixedLocalPointerChoiceFixture(t, fixedLocalFiveWayPointerBody(row.final, row.spill))
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			_, err := proveX86FixedLocal(fn, sig)
			if row.fails {
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("CFG address acquired a numerical value", err)
				}
			} else if err != nil {
				t.Fatal("unused or overwritten CFG address became a new rejection", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
