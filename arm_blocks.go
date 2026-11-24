package plan9asm

import (
	"fmt"
	"strings"
)

type armBlock struct {
	name      string
	instrs    []Instr
	synthetic bool
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

func armSplitBlocks(fn Func) []armBlock {
	names := newAssemblyBlockNames(fn)
	localCall, callerReturn := armLinkControlCandidates(fn)
	linkControl := localCall || callerReturn
	blocks := []armBlock{{name: names.fresh("entry"), synthetic: true}}
	cur := 0
	anon := 0

	startAnon := func() {
		anon++
		blocks = append(blocks, armBlock{name: names.fresh(fmt.Sprintf("anon_%d", anon)), synthetic: true})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins Instr) bool {
		if ins.Op == OpRET {
			return true
		}
		if _, undefined := armRawUndefinedEncoding(ins); undefined {
			return linkControl // Same CFG boundary as named UNDEF.
		}
		baseOp, _, _, _ := armDecodeOp(string(ins.Op))
		switch baseOp {
		case "RET", "UNDEF":
			return linkControl
		case "BL", "CALL":
			return localCall && armNamedLocalCall(ins)
		case "BX":
			return linkControl && armRegisterReturnCandidate(ins)
		case "B", "JMP":
			return true
		case "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
			return true
		}
		return false
	}
	isPCRelTarget := func(ins Instr) (int64, bool) {
		if armNamedLocalCall(ins) {
			return armLocalPCOffset(ins.Args[0])
		}
		baseOp, _, _, _ := armDecodeOp(strings.ToUpper(string(ins.Op)))
		if baseOp == "JMP" {
			baseOp = "B"
		}
		switch baseOp {
		case "B", "BEQ", "BNE", "BLT", "BGE", "BGT", "BLE", "BHS", "BHI", "BLS", "BLO", "BCC", "BCS", "BMI", "BPL", "BVS", "BVC":
		default:
			return 0, false
		}
		if len(ins.Args) != 1 {
			return 0, false
		}
		return armLocalPCOffset(ins.Args[0])
	}

	linear := make([]Instr, 0, len(fn.Instrs))
	for _, ins := range fn.Instrs {
		if ins.Op != OpLABEL {
			linear = append(linear, ins)
		}
	}
	splitAt := map[int]bool{}
	for i, ins := range linear {
		if off, ok := isPCRelTarget(ins); ok && off >= -int64(i) && off < int64(len(linear)-i) {
			splitAt[i+int(off)] = true
		}
	}

	li := 0
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			lbl := ins.Args[0].Sym
			if cur != 0 && len(blocks[cur].instrs) == 0 && blocks[cur].synthetic {
				blocks[cur].name = lbl
				blocks[cur].synthetic = false
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

	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && blocks[len(blocks)-1].synthetic {
		blocks = blocks[:len(blocks)-1]
	}
	return blocks
}

func armBranchTarget(op Operand) (string, bool) {
	switch op.Kind {
	case OpIdent:
		return op.Ident, true
	case OpLabel:
		return op.Sym, true
	case OpSym:
		s := strings.TrimSuffix(strings.TrimSuffix(op.Sym, "(SB)"), "<>")
		if s == "" {
			return "", false
		}
		return s, true
	default:
		return "", false
	}
}

func (c *armCtx) resolveBranchTarget(bi int, op Operand) (string, bool) {
	if target, ok := armBranchTarget(op); ok {
		return target, true
	}
	offset, relative := armLocalPCOffset(op)
	if !relative || bi < 0 || bi >= len(c.blocks) {
		return "", false
	}
	current := len(c.blocks[bi].instrs) - 1
	for i := 0; i < bi; i++ {
		current += len(c.blocks[i].instrs)
	}
	if offset < -int64(current) || offset > int64(^uint(0)>>1)-int64(current) {
		return "", false
	}
	target := current + int(offset)
	base := 0
	for _, block := range c.blocks {
		if base == target {
			return block.name, true
		}
		base += len(block.instrs)
	}
	return "", false
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
		case "P", "PW", "WP":
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
