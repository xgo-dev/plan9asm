package x86

import (
	"fmt"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

type amd64Block struct {
	name   string
	instrs []asm.Instr
}

func amd64SplitBlocks(fn asm.Func) []amd64Block {
	blocks := []amd64Block{{name: "entry"}}
	cur := 0
	anon := 0

	startAnon := func() {
		anon++
		blocks = append(blocks, amd64Block{name: fmt.Sprintf("anon_%d", anon)})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins asm.Instr) bool {
		if ins.Op == asm.OpRET {
			return true
		}
		op := asm.Op(strings.ToUpper(string(ins.Op)))
		return op == "JMP" || isX86FlagCondJumpOp(op)
	}

	linear := make([]asm.Instr, 0, len(fn.Instrs))
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			continue
		}
		linear = append(linear, ins)
	}
	splitAt := map[int]bool{}
	for i, ins := range linear {
		if off, ok := pcBranchOffset(ins); ok {
			t := i + int(off)
			if 0 <= t && t < len(linear) {
				splitAt[t] = true
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
			blocks = append(blocks, amd64Block{name: lbl})
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
		blocks = blocks[:len(blocks)-1]
	}
	return blocks
}

func pcBranchOffset(ins asm.Instr) (off int64, ok bool) {
	if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpMem || ins.Args[0].Mem.Base != asm.PC {
		return 0, false
	}
	if ins.Op != "JMP" && !isX86FlagCondJumpOp(ins.Op) {
		return 0, false
	}
	return ins.Args[0].Mem.Off, true
}

// Bind source instruction ordinals before expanding TLS or decoding runs of
// raw directives. A destination inside a raw run starts a separate decode.
func bindPCBranches(instrs []asm.Instr) ([]asm.Instr, error) {
	hasPC := false
	for _, ins := range instrs {
		if _, ok := pcBranchOffset(ins); ok {
			hasPC = true
			break
		}
	}
	if !hasPC {
		return nil, nil
	}
	var order []int
	names := make(map[string]bool)
	for i, ins := range instrs {
		for _, arg := range ins.Args {
			if arg.Kind == asm.OpLabel {
				names[arg.Sym] = true
			}
			if arg.Kind == asm.OpIdent {
				names[arg.Ident] = true
			}
		}
		if ins.Op == asm.OpLABEL {
			continue
		}
		order = append(order, i)
	}
	targets := map[int]string{}
	branches := map[int]string{}
	id := 0
	for pc, i := range order {
		off, ok := pcBranchOffset(instrs[i])
		if !ok {
			continue
		}
		if off < -int64(pc) || off >= int64(len(order)-pc) {
			return nil, fmt.Errorf("%w: invalid PC-relative target %d(PC)", asm.ErrProbeNeedsContext, off)
		}
		dst := order[pc+int(off)]
		label := targets[dst]
		if label == "" {
			for {
				label = fmt.Sprintf("p9_pc_%d", id)
				id++
				if !names[label] {
					break
				}
			}
			targets[dst] = label
		}
		branches[i] = label
	}
	result := make([]asm.Instr, 0, len(instrs)+len(targets))
	for i, ins := range instrs {
		if l := targets[i]; l != "" {
			result = append(result, asm.Instr{Op: asm.OpLABEL, Args: []asm.Operand{{Kind: asm.OpLabel, Sym: l}}, Raw: l + ":"})
		}
		if l := branches[i]; l != "" {
			ins.Args = []asm.Operand{{Kind: asm.OpIdent, Ident: l}}
		}
		result = append(result, ins)
	}
	return result, nil
}
