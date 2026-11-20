package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalCountedLoopUpdateGapCases() []fixedLocalCountedLoopCase {
	var cases []fixedLocalCountedLoopCase
	for _, register := range strings.Fields("AX BX CX DX SI DI BP R8 R9 R10 R11 R12 R13 R14 R15") {
		scratch := "AX"
		if register == scratch {
			scratch = "BX"
		}
		for _, operation := range []string{"ADDQ", "SUBQ", "INCQ", "DECQ"} {
			first, bound, branch := 0, 3, "JB"
			if operation == "SUBQ" || operation == "DECQ" {
				first, bound, branch = 3, 0, "JA"
			}
			update := operation + " " + register
			if operation == "ADDQ" || operation == "SUBQ" {
				update = operation + " $1," + register
			}
			for _, gap := range []struct{ name, initialize, body string }{
				{"NOP", "", "NOP"},
				{"GP and flags", "", fmt.Sprintf("MOVQ %s,%s\nADDQ $3,%s", register, scratch, scratch)},
				{"two vector moves", "MOVQ $0,64(SP)\nMOVQ $0,72(SP)\nMOVQ $0,80(SP)\nMOVQ $0,88(SP)\n" +
					"VMOVDQU 64(SP),Y6\nVMOVDQU Y6,Y7\n", "VMOVDQU Y6,Y4\nVMOVDQU Y7,Y5"},
				{"private word", "", "MOVQ $7,64(SP)\nMOVQ 64(SP)," + scratch},
			} {
				body := gap.initialize + fmt.Sprintf("MOVQ $%d,%s\nloop:\n"+
					"MOVQ $7,16(SP)(%s*8)\n%s\n%s\nCMPQ %s,$%d\n%s loop\nMOVQ 24(SP),AX",
					first, register, register, update, gap.body, register, bound, branch)
				name := register + "/" + operation + "/" + gap.name
				cases = append(cases, fixedLocalCountedLoopCase{name, body, 3})
			}
		}
	}
	return cases
}

func TestGoAMD64FixedLocalCountedLoopUpdateGap(t *testing.T) {
	cases := fixedLocalCountedLoopUpdateGapCases()
	if len(cases) != 240 {
		t.Fatal("15 counters by four updates and four typed gaps changed", len(cases))
	}
	var original strings.Builder
	for index, row := range cases {
		_, _, source := fixedLocalCountedLoopFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
	for _, row := range cases {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalCountedLoopFixture(t, row.body)
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("typed instructions preserving the counter must not hide its unique update", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalCountedLoopUpdateGapRejectsCounterChanges(t *testing.T) {
	const prefix = "MOVQ $0,SI\nloop:\nMOVQ $7,16(SP)(SI*8)\n"
	const suffix = "CMPQ SI,$3\nJB loop\nMOVQ 32(SP),AX"
	type example struct{ name, body string }
	var cases []example
	for _, row := range []struct{ name, middle string }{
		{"changed before update", "MOVQ $7,SI\nADDQ $1,SI\nNOP\n"},
		{"changed after update", "ADDQ $1,SI\nMOVQ $7,SI\n"},
		{"partial before update", "ADDB $1,SI\nADDQ $1,SI\nNOP\n"},
		{"partial after update", "ADDQ $1,SI\nADDB $1,SI\n"},
		{"zero-extended counter", "ADDQ $1,SI\nMOVL SI,SI\n"},
		{"two updates", "ADDQ $1,SI\nNOP\nINCQ SI\nNOP\n"},
		{"canceling updates", "ADDQ $1,SI\nNOP\nSUBQ $1,SI\nNOP\n"},
		{"partial counter alias", "MOVQ SI,AX\nADDQ $1,SI\nMOVB AL,SI\n"},
		{"unknown counter replacement", "ADDQ $1,SI\nMOVQ a+0(FP),SI\n"},
	} {
		cases = append(cases, example{row.name, prefix + row.middle + suffix})
	}
	// LAHF has a typed implicit AH write; FLAGS are initialized by CMP.
	// An otherwise unsupported string instruction would fail too early to
	// establish that the counter guard sees implicit register writes.
	implicit := prefix + "ADDQ $1,SI\nCMPQ SI,SI\nLAHF\n" + suffix
	cases = append(cases, example{"implicit counter write", strings.ReplaceAll(implicit, "SI", "AX")})
	var original strings.Builder
	for index, row := range cases {
		fn, sig, source := fixedLocalCountedLoopFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			for _, instruction := range fn.Instrs {
				if !fixedLocalInstructionShape(instruction) {
					t.Fatal("counter negative needs registered typed instructions", instruction.Raw)
				}
			}
			if _, err := proveX86FixedLocal(fn, sig); err == nil {
				t.Fatal("a changed counter or latch comparison acquired complete iteration authority")
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
