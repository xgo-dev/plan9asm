package plan9asm

import (
	"fmt"
	"strings"
)

type amd64Block struct {
	name      string
	instrs    []Instr
	synthetic bool
}

func isAMD64ConditionalBranch(op Op) bool {
	op = Op(strings.ToUpper(string(op)))
	if _, known := x86CounterControlPropertiesForOpcode(op); known {
		return true
	}
	return x86BranchCondition(op) != ""
}

// Branch lowering, byte dependencies and closed-loop predicates share the
// complete condition-alias family. Counter-zero branches have a different role.
func x86BranchCondition(op Op) string {
	switch op {
	case "JE", "JEQ", "JZ":
		return "EQ"
	case "JNE", "JNZ":
		return "NE"
	case "JL", "JLT", "JNGE":
		return "LT"
	case "JGE", "JNL":
		return "GE"
	case "JS", "JMI":
		return "MI"
	case "JNS", "JPL":
		return "PL"
	case "JLE", "JNG":
		return "LE"
	case "JG", "JGT", "JNLE":
		return "GT"
	case "JB", "JLO", "JC", "JCS", "JNAE":
		return "CS"
	case "JNC", "JCC", "JAE", "JHS", "JNB":
		return "CC"
	case "JBE", "JLS", "JNA":
		return "LS"
	case "JA", "JHI", "JNBE":
		return "HI"
	case "JO", "JOS":
		return "OS"
	case "JNO", "JOC":
		return "OC"
	case "JP", "JPE", "JPS":
		return "PS"
	case "JNP", "JPO", "JPC":
		return "PC"
	}
	return ""
}

func isAMD64CounterZeroBranch(op Op) bool {
	spec, known := x86CounterControlPropertiesForOpcode(op)
	return known && !spec.decrement
}

func amd64SplitBlocks(fn Func) []amd64Block {
	names := newAssemblyBlockNames(fn)
	blocks := []amd64Block{{name: names.fresh("entry"), synthetic: true}}
	cur := 0
	anon := 0

	isPCRelTarget := func(ins Instr) (off int64, ok bool) {
		op := strings.ToUpper(string(ins.Op))
		if op != "JMP" && op != "LOOP" && op != "XBEGIN" && !isAMD64ConditionalBranch(Op(op)) {
			return 0, false
		}
		args := ins.Args
		if op != "JMP" && len(args) == 2 && args[0].Kind == OpImm {
			args = args[1:]
		}
		if len(args) != 1 || args[0].Kind != OpMem {
			return 0, false
		}
		if !strings.EqualFold(string(args[0].Mem.Base), "PC") {
			return 0, false
		}
		return args[0].Mem.Off, true
	}

	startAnon := func() {
		anon++
		blocks = append(blocks, amd64Block{name: names.fresh(fmt.Sprintf("anon_%d", anon)), synthetic: true})
		cur = len(blocks) - 1
	}

	isTerminator := func(ins Instr) bool {
		if ins.Op == OpRET {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		if _, ok := amd64FarReturnSpecs[Op(op)]; ok {
			return true
		}
		if spec, ok := amd64SystemTransferSpecs[Op(op)]; ok && spec.terminates() {
			return true
		}
		if op == "JMP" || op == "LOOP" || op == "XBEGIN" || isAMD64ConditionalBranch(Op(op)) {
			return true
		}
		return false
	}

	linear := make([]Instr, 0, len(fn.Instrs))
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
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
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			lbl := ins.Args[0].Sym
			if cur != 0 && len(blocks[cur].instrs) == 0 && blocks[cur].synthetic {
				blocks[cur].name = lbl
				blocks[cur].synthetic = false
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

	if len(blocks) > 1 && len(blocks[len(blocks)-1].instrs) == 0 && blocks[len(blocks)-1].synthetic {
		blocks = blocks[:len(blocks)-1]
	}
	return blocks
}

func amd64LLVMBlockName(src string) string {
	return "bb_" + amd64LLVMSafeName(src)
}

// Keep block names in a namespace distinct from SSA temporaries and register
// allocas. Go permits local labels such as x1 and t1, which otherwise collide
// with the translator's %x1 and %t1 values in LLVM IR.
func amd64LLVMSafeName(src string) string {
	if src == "" {
		return "empty"
	}
	var out []byte
	for i := 0; i < len(src); i++ {
		ch := src[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') {
			out = append(out, ch)
			continue
		}
		out = append(out, '_')
		out = append(out, "0123456789abcdef"[ch>>4])
		out = append(out, "0123456789abcdef"[ch&0xf])
	}
	s := string(out)
	if s == "" {
		return "empty"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "n_" + s
	}
	return s
}
