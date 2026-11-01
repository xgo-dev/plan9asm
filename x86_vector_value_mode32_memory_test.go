package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86VectorValueMemoryGrammarError(ins Instr, arch string) error {
	if _, _, known, err := x86IndexedPermuteProperties(ins.Op, ins, arch); known {
		return err
	}
	if _, known, err := x86GFNIProperties(ins.Op, ins, arch); known {
		return err
	}
	if _, known, err := x86PackedBitCountProperties(ins.Op, ins, arch); known {
		return err
	}
	return fmt.Errorf("unregistered vector value fixture %s", ins.Op)
}

func TestX86VectorValueMode32HighGPAddressesNeedPhysicalContext(t *testing.T) {
	for _, bank := range []string{"X", "Y", "Z"} {
		var instructions []string
		for _, op := range x86IndexedPermuteResultNames {
			instructions = append(instructions, fmt.Sprintf("%s ADDRESS,%s1,%s2", op, bank, bank))
		}
		instructions = append(instructions, fmt.Sprintf("VGF2P8MULB ADDRESS,%s1,%s2", bank, bank))
		for _, member := range x86BitCountResultOracle {
			instructions = append(instructions, fmt.Sprintf("%s ADDRESS,%s2", member.name, bank))
		}
		if len(instructions) != 21 {
			t.Fatal("complete named mode32 value family changed", len(instructions))
		}
		for _, template := range instructions {
			for _, memory := range []string{"8(R9)", "8(R14)", "16(R15)"} {
				instruction := strings.Replace(template, "ADDRESS", memory, 1)
				t.Run(bank+"/"+instruction, func(t *testing.T) {
					goAssemblerOracleOutput(t, "386", "TEXT ·Value(SB),4,$0-0\n"+instruction+"\nRET\n", "", true)
					ins := x86ScalarLaneInstruction(t, instruction)
					if err := x86VectorValueMemoryGrammarError(ins, "386"); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("Go-accepted extended address must retain its unbound physical mode32 role", err)
					}
					if err := x86VectorValueMemoryGrammarError(ins, "amd64"); err != nil {
						t.Fatal("valid AMD64 address lost its complete operand grammar", err)
					}
				})
			}
		}
	}
}

func TestX86VectorValueMode32AddressContextDoesNotHideInvalidFormats(t *testing.T) {
	for _, instruction := range []string{
		"VPERMB.BAD 8(R9),X1,X2",
		"VPERMB 8(R9),X1,K0,X2",
		"VGF2P8MULB.BCST 8(R9),X1,X2",
		"VGF2P8AFFINEQB $0,8(R9),X1,X2",
		"VPLZCNTD.BAD 8(R9),X1",
		"VPOPCNTB.BCST 8(R9),X1",
		"VPOPCNTB 8(R9),AX",
		"VPOPCNTB 8(AX)(R9*3),X1",
		"VPOPCNTB 8(AX)(R9*2),X1",
		"VPOPCNTB 8(R12),X1",
		"VPLZCNTD 8(R9)(CX*2),X1",
		"VPOPCNTQ 8(R9),K0,X1",
	} {
		t.Run(instruction, func(t *testing.T) {
			if strings.Contains(instruction, "*3)") {
				_, err := Parse(ArchAMD64, "TEXT ·Value(SB),4,$0-0\n"+instruction+"\nRET\n")
				if err == nil || errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "(R9*3)") {
					t.Fatal("invalid source scale did not retain its fixture-bound parser rejection", err)
				}
				return
			}
			ins := x86ScalarLaneInstruction(t, instruction)
			if err := x86VectorValueMemoryGrammarError(ins, "386"); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("invalid format was hidden by an unrelated address context", err)
			}
		})
	}
}
