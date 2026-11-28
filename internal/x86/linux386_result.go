package x86

import "github.com/xgo-dev/plan9asm/internal/asm"

// linux386SeekOutput recognizes a successful return from Linux i386 _llseek
// (syscall 140), which only returns 0 (after writing 8 bytes to *SI) or
// -errno in [0xfffff001, 0xffffffff]. Match only straight-line setup with
// exact full-register AX/SI assignments so sub-register clobbers (e.g. AL)
// cannot forge syscall 140.
func linux386SeekOutput(instrs []asm.Instr, branch int, resultBytes map[int64]bool) (offset int64, successTaken, ok bool) {
	if branch < 4 {
		return
	}
	cmp, trap := instrs[branch-1], instrs[branch-2]
	if len(cmp.Args) != 2 || cmp.Args[0].Kind != asm.OpReg || cmp.Args[0].Reg != asm.AX {
		return
	}
	rhs := cmp.Args[1]
	isZeroCmp := cmp.Op == "CMPL" && rhs.Kind == asm.OpImm && rhs.ImmRaw == "" && rhs.Imm == 0 ||
		cmp.Op == "TESTL" && rhs.Kind == asm.OpReg && rhs.Reg == asm.AX
	isErrnoBoundCmp := cmp.Op == "CMPL" && rhs.Kind == asm.OpImm && rhs.ImmRaw == "" && uint32(rhs.Imm) == 0xfffff001
	if !isZeroCmp && !isErrnoBoundCmp {
		return
	}
	switch instrs[branch].Op {
	case "JE", "JEQ", "JZ":
		if !isZeroCmp {
			return
		}
		successTaken = true
	case "JNE", "JNZ":
		if !isZeroCmp {
			return
		}
	case "JLS", "JBE", "JNA", "JLO", "JB", "JNAE", "JC", "JCS":
		if !isErrnoBoundCmp {
			return
		}
		successTaken = true
	case "JHI", "JA", "JNBE", "JHS", "JAE", "JNB", "JNC", "JCC":
		if !isErrnoBoundCmp {
			return
		}
	default:
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
		dstReg := ins.Args[1].Reg
		switch canonicalGP(dstReg) {
		case asm.AX:
			if !number {
				if ins.Op != "MOVL" || dstReg != asm.AX || src.Kind != asm.OpImm || src.ImmRaw != "" || src.Imm != 140 {
					return
				}
				number = true
			}
		case asm.SI:
			if !buffer {
				if ins.Op != "LEAL" || dstReg != asm.SI || src.Kind != asm.OpFP {
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
			return offset, successTaken, true
		}
	}
	return
}
