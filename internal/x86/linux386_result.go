package x86

import "github.com/xgo-dev/plan9asm/internal/asm"

// linux386SeekOutput recognizes a zero return from Linux _llseek. On this edge
// the kernel has written eight bytes through SI. Match only straight-line
// setup: labels (including normalized PC-relative targets) end the search.
func linux386SeekOutput(instrs []asm.Instr, branch int, resultBytes map[int64]bool) (offset int64, zeroTaken, ok bool) {
	if branch < 4 {
		return
	}
	switch instrs[branch].Op {
	case "JE", "JEQ", "JZ":
		zeroTaken = true
	case "JNE", "JNZ":
	default:
		return
	}
	cmp, trap := instrs[branch-1], instrs[branch-2]
	if len(cmp.Args) != 2 || cmp.Args[0].Kind != asm.OpReg || cmp.Args[0].Reg != asm.AX {
		return
	}
	rhs := cmp.Args[1]
	if !(cmp.Op == "CMPL" && rhs.Kind == asm.OpImm && rhs.ImmRaw == "" && rhs.Imm == 0 ||
		cmp.Op == "TESTL" && rhs.Kind == asm.OpReg && rhs.Reg == asm.AX) {
		return
	}
	if trap.Op != "INT" || len(trap.Args) != 1 || trap.Args[0].Kind != asm.OpImm || trap.Args[0].ImmRaw != "" || trap.Args[0].Imm != 0x80 {
		return
	}
	var number, buffer bool
	for i := branch - 3; i >= 0; i-- {
		ins := instrs[i]
		if (ins.Op != "MOVL" && ins.Op != "LEAL") || len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
			return
		}
		src := ins.Args[0]
		switch ins.Args[1].Reg {
		case asm.AX:
			if !number {
				if ins.Op != "MOVL" || src.Kind != asm.OpImm || src.ImmRaw != "" || src.Imm != 140 {
					return
				}
				number = true
			}
		case asm.SI:
			if !buffer {
				if ins.Op != "LEAL" || src.Kind != asm.OpFP {
					return
				}
				offset, buffer = src.FPOffset, true
			}
		}
		if number && buffer {
			for b := int64(0); b < 8; b++ {
				if !resultBytes[offset+b] {
					return
				}
			}
			return offset, zeroTaken, true
		}
	}
	return
}
