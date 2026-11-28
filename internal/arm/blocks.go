package arm

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type armBlock struct {
	name   string
	instrs []asm.Instr
}

var armCondCodes = map[string]bool{
	"EQ": true,
	"NE": true,
	"CS": true,
	"HS": true,
	"CC": true,
	"LO": true,
	"MI": true,
	"PL": true,
	"VS": true,
	"VC": true,
	"HI": true,
	"LS": true,
	"GE": true,
	"LT": true,
	"GT": true,
	"LE": true,
	"AL": true,
}

func armSplitBlocks(fn asm.Func) []armBlock {
	blocks := []armBlock{{name: "entry"}}
	cur := 0
	anon := 0

	startAnon := func() {
		anon++
		blocks = append(blocks, armBlock{name: fmt.Sprintf("anon_%d", anon)})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins asm.Instr) bool {
		if ins.Op == asm.OpRET {
			return true
		}
		baseOp, cond, _, _ := armDecodeOp(strings.ToUpper(string(ins.Op)))
		switch baseOp {
		case "B", "JMP":
			return true
		case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
			return true
		}
		return baseOp == "B" && cond != ""
	}
	isPCRelTarget := func(ins asm.Instr) (int64, bool) {
		baseOp, _, _, _ := armDecodeOp(strings.ToUpper(string(ins.Op)))
		if baseOp == "JMP" {
			baseOp = "B"
		}
		switch baseOp {
		case "B", "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		default:
			return 0, false
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpMem || ins.Args[0].Mem.Base != asm.PC {
			return 0, false
		}
		return ins.Args[0].Mem.Off, true
	}

	linear := make([]asm.Instr, 0, len(fn.Instrs))
	for _, ins := range fn.Instrs {
		if ins.Op != asm.OpLABEL {
			linear = append(linear, ins)
		}
	}
	splitAt := map[int]bool{}
	for i, ins := range linear {
		if off, ok := isPCRelTarget(ins); ok {
			target := i + int(off)
			if target >= 0 && target < len(linear) {
				splitAt[target] = true
			}
		}
	}

	li := 0
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == asm.OpLabel {
			lbl := ins.Args[0].Sym
			if len(blocks[cur].instrs) == 0 && strings.HasPrefix(blocks[cur].name, "anon_") {
				blocks[cur].name = lbl
				continue
			}
			blocks = append(blocks, armBlock{name: lbl})
			cur = len(blocks) - 1
			continue
		}

		if splitAt[li] && len(blocks[cur].instrs) != 0 {
			startAnon()
		}
		blocks[cur].instrs = append(blocks[cur].instrs, ins)
		li++
		if isTerminator(ins) {
			startAnon()
		}
	}

	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && strings.HasPrefix(blocks[len(blocks)-1].name, "anon_") {
		prev := blocks[len(blocks)-2].instrs
		if len(prev) != 0 {
			op, cond, _, _ := armDecodeOp(string(prev[len(prev)-1].Op))
			if armIsConditionalBranch(op) || (op == "B" || op == "JMP") && cond != "" && cond != "AL" {
				return blocks
			}
		}
		blocks = blocks[:len(blocks)-1]
	}
	return blocks
}

func armBranchTarget(op asm.Operand) (string, bool) {
	switch op.Kind {
	case asm.OpIdent:
		return op.Ident, true
	case asm.OpSym:
		s := strings.TrimSuffix(strings.TrimSuffix(op.Sym, "(SB)"), "<>")
		if s == "" {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func (c *armCtx) resolveBranchTarget(bi int, op asm.Operand) (string, bool) {
	if op.Kind == asm.OpSym && strings.HasSuffix(op.Sym, "(SB)") {
		return "", false
	}
	if target, ok := armBranchTarget(op); ok {
		return target, true
	}
	if op.Kind != asm.OpMem || op.Mem.Base != asm.PC || bi < 0 || bi >= len(c.blocks) {
		return "", false
	}
	current := len(c.blocks[bi].instrs) - 1
	for i := 0; i < bi; i++ {
		current += len(c.blocks[i].instrs)
	}
	target := current + int(op.Mem.Off)
	base := 0
	for i, block := range c.blocks {
		if base == target {
			return c.blocks[i].name, true
		}
		base += len(block.instrs)
	}
	return "", false
}

func armDecodeAddrModes(raw string) (preInc bool, subOff bool) {
	parts := strings.Split(strings.ToUpper(strings.TrimSpace(raw)), ".")
	for _, p := range parts[1:] {
		switch p {
		case "W":
			preInc = true
		case "U":
			subOff = true
		}
	}
	return preInc, subOff
}

func armDecodeOp(raw string) (base string, cond string, postInc bool, setFlags bool) {
	base = strings.ToUpper(strings.TrimSpace(raw))
	if base == "" {
		return "", "", false, false
	}
	parts := strings.Split(base, ".")
	base = parts[0]
	for _, p := range parts[1:] {
		switch p {
		case "P":
			postInc = true
		case "S":
			setFlags = true
		case "":
		default:
			if armCondCodes[p] {
				cond = p
			}
		}
	}
	return base, cond, postInc, setFlags
}
