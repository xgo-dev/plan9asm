package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func fixedLocalMachineBitCases() []fixedLocalPointerChoiceCase {
	var rows []fixedLocalPointerChoiceCase
	for _, width := range []string{"B", "W", "L", "Q"} {
		for _, stem := range []string{"ADD", "ADC", "SUB", "SBB", "AND", "OR", "XOR"} {
			for _, destination := range []string{"AX", "SI"} {
				for _, source := range []string{"AX", "DI"} {
					body := "MOVQ " + destination + ",BX\nMOVQ " + source + ",CX\nCMPQ AX,AX\n" +
						stem + width + " CX,BX\nXORQ $0,BX\nMOVQ BX,AX"
					rows = append(rows, fixedLocalPointerChoiceCase{
						fmt.Sprintf("%s%s/%s/%s", stem, width, destination, source), body,
					})
				}
			}
		}
		for _, stem := range []string{"NEG", "NOT", "INC", "DEC"} {
			rows = append(rows, fixedLocalPointerChoiceCase{stem + width,
				"MOVQ SI,BX\n" + stem + width + " BX\nXORQ $0,BX\nMOVQ BX,AX"})
		}
		for _, stem := range []string{"CMP", "TEST"} {
			rows = append(rows, fixedLocalPointerChoiceCase{stem + width,
				stem + width + " SI,AX\nSETCS AL"})
		}
		rows = append(rows,
			fixedLocalPointerChoiceCase{"spill source/" + width,
				"MOVQ SI,8(SP)\nSUB" + width + " 8(SP),AX"},
			fixedLocalPointerChoiceCase{"spill destination/" + width,
				"MOVQ SI,8(SP)\nSUB" + width + " AX,8(SP)\nMOVQ 8(SP),AX"},
		)
	}
	for _, row := range []fixedLocalPointerChoiceCase{
		{"aliased full address", "SUBQ SI,SI\nMOVQ SI,AX"},
		{"high byte alias", "MOVQ SI,AX\nSUBB AH,AL\nXORQ $0,AX"},
		{"typed pointer FP", "SUBQ q+8(FP),SI\nMOVQ SI,AX"},
		{"typed pointer FP mixed", "SUBQ p+0(FP),AX"},
		{"first address from typed FP", "XORQ SI,SI\nXORQ DI,DI\nMOVQ $0,CX\nADDQ p+0(FP),CX\nMOVQ (CX),AX"},
		{"typed numeric FP affine", "ADDQ a+16(FP),SI\nSUBQ DI,SI\nMOVQ SI,AX"},
		{"pointer FP multiply", "MULQ p+0(FP)"},
		{"address multiply", "MULQ SI"},
		{"address shift", "MOVQ SI,AX\nSHRQ $3,AX"},
		{"pointer compare native numeric", "CMPQ SI,AX\nSETCS AL"},
		{"carry consumed", "STC\nSBBQ SI,AX\nSETCS CL\nMOVBQZX CL,CX\nADDQ CX,AX"},
		{"address flags branch", "SUBQ DI,SI\nJCS done\nINCQ AX\ndone:"},
		{"unaligned spill interior", "MOVQ SI,3(SP)\nSUBL 4(SP),AX"},
		{"unaligned spill partial RMW", "MOVQ SI,3(SP)\nSUBB AX,7(SP)\nMOVQ 3(SP),AX"},
		{"two spill boundary", "MOVQ SI,8(SP)\nMOVQ DI,16(SP)\nSUBQ 12(SP),AX"},
		{"vector machine input", "MOVQ SI,8(SP)\nMOVQ AX,16(SP)\nMOVQ AX,24(SP)\nMOVQ AX,32(SP)\nVPXOR Y0,Y0,Y0\nVPADDQ 8(SP),Y0,Y0\nMOVQ X0,AX"},
	} {
		rows = append(rows, row)
	}
	return append(rows, fixedLocalMachineAddressCases()...)
}

// Inputs point inside the native oracle's buffers, so both +/- one-byte paths
// remain valid for every original input and alias choice.
func fixedLocalMachineAddressCases() []fixedLocalPointerChoiceCase {
	return []fixedLocalPointerChoiceCase{
		{"ADC native CF0", "CLC\nADCQ $0,SI\nMOVQ (SI),AX"},
		{"ADC native CF1", "STC\nADCQ $0,SI\nMOVQ (SI),AX"},
		{"SBB native CF0", "CLC\nSBBQ $0,SI\nMOVQ (SI),AX"},
		{"SBB native CF1", "STC\nSBBQ $0,SI\nMOVQ (SI),AX"},
		{"ADC reversed CF0", "MOVQ $0,CX\nCLC\nADCQ SI,CX\nMOVQ (CX),AX"},
		{"ADC reversed CF1", "MOVQ $0,CX\nSTC\nADCQ SI,CX\nMOVQ (CX),AX"},
	}
}

func TestGoAMD64FixedLocalMachineBitsCompleteSources(t *testing.T) {
	rows := fixedLocalMachineBitCases()
	if len(rows) != 166 {
		t.Fatal("independent machine-bit source inventory changed", len(rows))
	}
	var assembly strings.Builder
	for index, row := range rows {
		fn, sig, source := fixedLocalInputFixture(t, row.body)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("initialized machine input rejected", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
}

func TestGoAMD64FixedLocalMachineBitsRetainCapabilities(t *testing.T) {
	for _, row := range []fixedLocalPointerChoiceCase{
		{"difference is not address", "SUBQ DI,SI\nMOVQ (SI),AX"},
		{"sum is not address", "ADDQ DI,SI\nMOVQ (SI),AX"},
		{"number minus address", "SUBQ SI,AX\nMOVQ (AX),AX"},
		{"truncated result is not address", "SUBL AX,SI\nMOVQ (SI),AX"},
		{"private source", "MOVQ SP,CX\nSUBQ CX,AX"},
		{"private destination", "MOVQ SP,CX\nSUBQ SI,CX"},
		{"private source spill", "MOVQ SP,8(SP)\nSUBQ 8(SP),AX"},
		{"private destination spill", "MOVQ SP,8(SP)\nSUBQ AX,8(SP)"},
		{"unknown source", "SUBQ R12,SI"},
		{"unknown byte", "MOVB $1,R12\nSUBQ R12,SI"},
		{"partial revoked spill", "MOVQ SI,8(SP)\nMOVB $1,9(SP)\nSUBQ 8(SP),AX"},
		{"missing carry", "SBBQ SI,AX"},
		{"multiply does not define zero", "MULQ SI\nJE done\ndone:"},
		{"private index", "SUBQ (DI)(SP*1),AX"},
		{"native index", "SUBQ (DI)(SI*1),AX"},
		{"NUM is not address", "SUBQ DI,SI\nSUBQ (SI),AX"},
		{"partial FP pointer", "SUBL p+0(FP),AX"},
		{"changed SP FP", "ADDQ $8,SP\nSUBQ p+0(FP),AX\nADDQ $-8,SP"},
		{"FP padding", "SUBQ p+1(FP),AX"},
		{"FP destination", "SUBQ SI,a+16(FP)"},
		{"undefined spill boundary", "MOVQ SI,8(SP)\nSUBQ 12(SP),AX"},
		{"vector private source", "MOVQ SP,8(SP)\nMOVQ AX,16(SP)\nMOVQ AX,24(SP)\nMOVQ AX,32(SP)\nVPXOR Y0,Y0,Y0\nVPADDQ 8(SP),Y0,Y0"},
		{"vector undefined source", "MOVQ SI,8(SP)\nVPXOR Y0,Y0,Y0\nVPADDQ 8(SP),Y0,Y0"},
		{"carry sum is not address", "STC\nADCQ DI,SI\nMOVQ (SI),AX"},
		{"carry difference is not address", "CLC\nSBBQ DI,SI\nMOVQ (SI),AX"},
		{"carry number minus address", "STC\nSBBQ SI,AX\nMOVQ (AX),AX"},
		{"missing address carry", "ADCQ $0,SI\nMOVQ (SI),AX"},
		{"conditional FP pointer is not NUM", "CMPQ AX,AX\nCMOVQEQ p+0(FP),AX"},
		{"conditional FP number is not address", "CMPQ AX,AX\nCMOVQEQ a+16(FP),SI\nXORQ $0,SI\nMOVQ SI,AX"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalInputFixture(t, row.body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("machine input acquired unrelated storage, flags or ABI", err)
			}
		})
	}
}

func TestGoAMD64FixedLocalMachineBitsCompleteObjects(t *testing.T) {
	rows := fixedLocalMachineBitCases()
	assembly, declarations := fixedLocalPointerChoiceProgram(t, "", rows)
	fixedLocalCompleteVectorObjects(t, assembly, declarations, len(rows))
}
