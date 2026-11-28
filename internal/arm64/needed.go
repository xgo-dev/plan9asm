package arm64

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	// funcNeedsARM64CFG decides whether we need the (currently) ARM64-only CFG-based
	// translator. The linear prototype cannot handle labels/branches or opcode
	// suffixes like ".P".
)

func FuncNeedsCFG(fn asm.Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			return true
		}
		rawOp := strings.ToUpper(string(ins.Op))
		if strings.Contains(rawOp, ".") {
			return true
		}
		op := rawOp
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch asm.Op(op) {
		// Keep the linear path only for the tiny subset it can currently lower.
		case asm.OpMRS:
			if len(ins.Args) > 0 {
				if sysreg, ok := SystemRegOperand(ins.Args[0]); ok && sysreg == "NZCV" {
					return true
				}
			}
			continue
		case asm.OpTEXT:
			continue
		case asm.OpRET:
			if len(ins.Args) != 0 {
				return true
			}
			continue
		case asm.OpMOVD:
			// Linear arm64 lowering only supports immediate/reg/FP value moves.
			for _, a := range ins.Args {
				switch a.Kind {
				case asm.OpImm, asm.OpReg, asm.OpFP:
					// ok
				default:
					return true
				}
			}
			continue
		case "B", "JMP", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT",
			"CBZ", "CBNZ", "TBZ", "TBNZ":
			return true
		default:
			// Any other opcode is unsupported by linear arm64 lowering.
			return true
		}
	}
	return false
}

type arm64Flags struct {
	kind  string // "cmp" or "res"
	dst   string // i64 SSA or constant
	src   string // i64 SSA or constant (for cmp)
	width asm.LLVMType
}
