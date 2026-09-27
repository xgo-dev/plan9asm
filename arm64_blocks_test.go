package plan9asm

import "testing"

func TestARM64SplitBlocksRecognizesEveryConditionalBranchTerminator(t *testing.T) {
	ops := []Op{
		"BEQ", "BNE", "BLO", "BLT", "BHI", "BHS", "BLS", "BGE", "BGT", "BLE",
		"BCC", "BCS", "BMI", "BPL", "BVS", "BVC",
		"CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ",
	}
	for _, op := range ops {
		t.Run(string(op), func(t *testing.T) {
			blocks := arm64SplitBlocks(Func{Instrs: []Instr{
				{Op: op, Raw: string(op)},
				{Op: "NOP", Raw: "NOP"},
				{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: "target"}}},
				{Op: "NOP", Raw: "NOP"},
			}})
			if len(blocks) != 3 || len(blocks[0].instrs) != 1 || len(blocks[1].instrs) != 1 || blocks[2].name != "target" {
				t.Fatalf("arm64SplitBlocks(%s) = %#v, want branch/fallthrough/target blocks", op, blocks)
			}
		})
	}
}
