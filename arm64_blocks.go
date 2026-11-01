package plan9asm

import (
	"fmt"
	"strings"
)

type arm64Block struct {
	name      string
	instrs    []Instr
	synthetic bool
}

func arm64SplitBlocks(fn Func) []arm64Block {
	names := newAssemblyBlockNames(fn)
	blocks := []arm64Block{{name: names.fresh("entry"), synthetic: true}}
	cur := 0
	anon := 0

	startAnon := func() {
		anon++
		blocks = append(blocks, arm64Block{name: names.fresh(fmt.Sprintf("anon_%d", anon)), synthetic: true})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins Instr) bool {
		ins = arm64ControlDecode(ins)
		if ins.Op == OpRET {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch Op(op) {
		case "BL", "BLR", "CALL":
			return true
		case "B", "JMP", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS", "BMI", "BPL", "BVS", "BVC",
			"BCC", "BCS", "CBZ", "CBNZ", "CBZW", "CBNZW", "TBZ", "TBNZ":
			return true
		default:
			return false
		}
	}

	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			lbl := ins.Args[0].Sym
			// Labels start a new basic block. If we previously created an empty
			// synthetic fallthrough block, reuse it by renaming.
			if cur != 0 && len(blocks[cur].instrs) == 0 && blocks[cur].synthetic {
				blocks[cur].name = lbl
				blocks[cur].synthetic = false
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
	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && blocks[len(blocks)-1].synthetic {
		previous := blocks[len(blocks)-2]
		lastOp := Op("")
		if len(previous.instrs) != 0 {
			lastOp = arm64ControlOp(arm64ControlDecode(previous.instrs[len(previous.instrs)-1]))
		}
		if lastOp != "BL" && lastOp != "BLR" && lastOp != "CALL" {
			blocks = blocks[:len(blocks)-1]
		}
	}
	return blocks
}

func arm64IsLocalBranchLink(ins Instr) bool {
	op := strings.ToUpper(string(ins.Op))
	if dot := strings.IndexByte(op, '.'); dot >= 0 {
		op = op[:dot]
	}
	if op != "BL" && op != "BLR" && op != "CALL" || len(ins.Args) != 1 {
		return false
	}
	target := ins.Args[0]
	switch target.Kind {
	case OpIdent:
		return true
	case OpSym:
		return !strings.HasSuffix(target.Sym, "(SB)")
	case OpMem:
		return target.Mem.Base == PC
	default:
		return false
	}
}

func arm64LLVMBlockName(src string) string {
	// Encode every non-alphanumeric byte injectively, including underscores.
	// The block namespace is disjoint from register and SSA temporary names.
	return "bb_" + amd64LLVMSafeName(src)
}

func arm64BranchTarget(op Operand) (string, bool) {
	switch op.Kind {
	case OpIdent:
		return op.Ident, true
	case OpSym:
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
