package arm64

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"github.com/xgo-dev/plan9asm/internal/exclusive"
	"strings"
)

type arm64Block struct {
	startPC int64
	name    string // source label (or "entry")
	instrs  []asm.Instr
}

func arm64SplitBlocks(fn asm.Func) []arm64Block {
	blocks := []arm64Block{{name: "entry"}}
	cur := 0
	anon := 0
	var pc int64

	startAnon := func() {
		anon++
		blocks = append(blocks, arm64Block{name: fmt.Sprintf("anon_%d", anon), startPC: pc})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins asm.Instr) bool {
		if ins.Op == asm.OpRET || ins.Op == exclusive.ExitOpcode {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch asm.Op(op) {
		case "B", "JMP", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS", "BMI", "BPL", "BVS", "BVC",
			"BCC", "BCS", "CBZW", "CBNZW", "CBZ", "CBNZ", "TBZ", "TBNZ":
			return true
		default:
			return false
		}
	}

	// Go asm counts programs (including TEXT, PCDATA and FUNCDATA), not
	// machine words. Labels never advance the assembler's PC.
	var splitAt map[int64]bool
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			continue
		}
		if len(ins.Args) > 0 {
			var last asm.Operand
			if isTerminator(ins) {
				last = ins.Args[len(ins.Args)-1]
			} else if ins.Op == "ADR" || ins.Op == "ADRP" {
				last = ins.Args[0]
			}
			if last.Kind == asm.OpMem && last.Mem.Base == asm.PC {
				if splitAt == nil {
					splitAt = make(map[int64]bool)
				}
				splitAt[pc+last.Mem.Off] = true
			}
		}
		pc++
	}
	pc = 0
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpLabel {
			lbl := ins.Args[0].Sym
			// Labels start a new basic block. If we previously created an empty
			// synthetic fallthrough block, reuse it by renaming.
			if len(blocks[cur].instrs) == 0 && strings.HasPrefix(blocks[cur].name, "anon_") {
				blocks[cur].name = lbl
				continue
			}
			blocks = append(blocks, arm64Block{name: lbl, startPC: pc})
			cur = len(blocks) - 1
			continue
		}

		if splitAt[pc] && len(blocks[cur].instrs) != 0 {
			startAnon()
		}
		blocks[cur].instrs = append(blocks[cur].instrs, ins)
		pc++
		if isTerminator(ins) {
			// Create a fresh fallthrough block for subsequent instructions.
			startAnon()
		}
	}

	// Drop trailing empty synthetic block if present.
	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && strings.HasPrefix(blocks[len(blocks)-1].name, "anon_") {
		previous := blocks[len(blocks)-2].instrs
		if len(previous) > 0 && previous[len(previous)-1].Op == exclusive.ExitOpcode {
			return blocks
		}
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
