package x86

import (
	"fmt"
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
)

type amd64Block struct {
	name   string
	instrs []asm.Instr
}

func amd64SplitBlocks(fn asm.Func) []amd64Block {
	blocks := []amd64Block{{name: "entry"}}
	cur := 0
	anon := 0

	isPCRelTarget := func(ins asm.Instr) (off int64, ok bool) {
		op := asm.Op(strings.ToUpper(string(ins.Op)))
		if op != "JMP" && !isX86FlagCondJumpOp(op) {
			return 0, false
		}
		if len(ins.Args) != 1 || ins.Args[0].Kind != asm.OpMem {
			return 0, false
		}
		if !strings.EqualFold(string(ins.Args[0].Mem.Base), "PC") {
			return 0, false
		}
		return ins.Args[0].Mem.Off, true
	}

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
		if off, ok := isPCRelTarget(ins); ok {
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
