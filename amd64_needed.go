package plan9asm

import "strings"

// funcNeedsAMD64CFG decides whether the direct LLVM-module prototype can
// represent an amd64 function. Textual translation always uses the complete
// architecture-aware x86 CFG lowerer.
func funcNeedsAMD64CFG(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			return true
		}
		op := strings.ToUpper(string(ins.Op))
		for _, operand := range ins.Args {
			if _, _, ok := x86MachineRegisterOperand(operand); ok {
				return true
			}
			if x86SegmentRegisterOperand(operand) {
				return true
			}
		}
		switch Op(op) {
		case "JMP", "JCXZW", "JCXZL", "JCXZQ", "JL", "JLT", "JLE", "JG", "JGT", "JGE",
			"JB", "JLO", "JBE", "JA", "JHI", "JAE", "JHS",
			"JZ", "JE", "JEQ", "JNZ", "JNE", "JNC", "JC", "JCS", "JCC", "JLS", "JNA", "JS", "JNS":
			return true
		}
		// A handful of amd64 stdlib asm functions are straight-line, but if we
		// see any obvious vector-ish opcode, route through CFG translator.
		if strings.HasPrefix(op, "MOVO") || strings.HasPrefix(op, "PCLMUL") || strings.HasPrefix(op, "CRC32") || strings.HasPrefix(op, "PXOR") {
			return true
		}
		// Keep the direct-module path only for the tiny subset it currently lowers.
		switch Op(op) {
		case OpTEXT, OpBYTE, OpMOVQ, OpMOVL, OpADDQ, OpSUBQ, OpXORQ, OpCPUID, OpXGETBV:
			// For MOVQ/MOVL, direct lowering supports immediate/reg/FP value flow.
			// Addressing forms (mem/sym) require CFG lowering.
			if (op == "MOVQ" || op == "MOVL") && len(ins.Args) == 2 {
				for _, a := range ins.Args {
					switch a.Kind {
					case OpImm, OpReg, OpFP:
						// ok
					default:
						return true
					}
				}
			}
		case OpRET:
			if len(ins.Args) != 0 {
				return true
			}
		default:
			return true
		}
	}
	return false
}
