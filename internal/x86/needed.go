package x86

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	// funcNeedsAMD64CFG decides whether we need the CFG-based amd64 translator.
	// The linear prototype cannot handle labels/branches and most vector ops.
)

func FuncNeedsCFG(fn asm.Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		switch asm.Op(op) {
		case "JMP", "JL", "JLT", "JLE", "JG", "JGT", "JGE",
			"JB", "JLO", "JBE", "JA", "JHI", "JAE", "JHS",
			"JZ", "JE", "JEQ", "JNZ", "JNE", "JNC", "JC", "JCC", "JLS", "JNA", "JS", "JNS":
			return true
		}
		// A handful of amd64 stdlib asm functions are straight-line, but if we
		// see any obvious vector-ish opcode, route through CFG translator.
		if strings.HasPrefix(op, "MOVO") || strings.HasPrefix(op, "PCLMUL") || strings.HasPrefix(op, "CRC32") || strings.HasPrefix(op, "PXOR") {
			return true
		}
		// Keep the linear path only for the tiny subset it currently lowers.
		switch asm.Op(op) {
		case asm.OpTEXT, asm.OpBYTE, asm.OpMOVQ, asm.OpMOVL, asm.OpADDQ, asm.OpSUBQ, asm.OpXORQ, asm.
			// For MOVQ/MOVL, linear lowering supports immediate/reg/FP value flow.
			// Addressing forms (mem/sym) require CFG lowering.
			OpCPUID, asm.OpXGETBV:

			if (op == "MOVQ" || op == "MOVL") && len(ins.Args) == 2 {
				for _, a := range ins.Args {
					switch a.Kind {
					case asm.OpImm, asm.OpReg, asm.OpFP:
						// ok
					default:
						return true
					}
				}
			}
		case asm.OpRET:
			if len(ins.Args) != 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}
