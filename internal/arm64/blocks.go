package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

type arm64Block struct {
	name   string // source label (or "entry")
	instrs []asm.Instr
}

func arm64SplitBlocks(fn asm.Func) []arm64Block {
	blocks := []arm64Block{{name: "entry"}}
	cur := 0
	anon := 0

	startAnon := func() {
		anon++
		blocks = append(blocks, arm64Block{name: fmt.Sprintf("anon_%d", anon)})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins asm.Instr) bool {
		if ins.Op == asm.OpRET {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch asm.Op(op) {
		case "B", "JMP", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS", "BMI", "BPL", "BVS", "BVC",
			"BCC", "CBZ", "CBNZ", "TBZ", "TBNZ":
			return true
		default:
			return false
		}
	}

	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpLabel {
			lbl := ins.Args[0].Sym
			// Labels start a new basic block. If we previously created an empty
			// synthetic fallthrough block, reuse it by renaming.
			if len(blocks[cur].instrs) == 0 && strings.HasPrefix(blocks[cur].name, "anon_") {
				blocks[cur].name = lbl
				continue
			}
			blocks = append(blocks, arm64Block{name: lbl})
			cur = len(blocks) - 1
			continue
		}

		blocks[cur].instrs = append(blocks[cur].instrs, ins)
		if isTerminator(ins) {
			// Create a fresh fallthrough block for subsequent instructions.
			startAnon()
		}
	}

	// Drop trailing empty synthetic block if present.
	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && strings.HasPrefix(blocks[len(blocks)-1].name, "anon_") {
		blocks = blocks[:len(blocks)-1]
	}
	return blocks
}

// Avoid collisions with "entry:" / "ret:" that some tools special-case.

func arm64BranchTarget(op asm.Operand) (string, bool) {
	switch op.Kind {
	case asm.OpIdent:
		return op.Ident, true
	case asm.OpSym:
		// Local labels sometimes appear with "<>" suffix.
		s := strings.TrimSuffix(strings.TrimSuffix(op.Sym, "(SB)"), "<>")
		if s == "" {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}
