package arm

import (
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

func FuncNeedsCFG(fn asm.Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == asm.OpLABEL {
			return true
		}
		rawOp := strings.ToUpper(string(ins.Op))
		op := rawOp
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch asm.Op(op) {
		case asm.OpTEXT:
			continue
		case asm.OpRET:
			if len(ins.Args) != 0 || rawOp != "RET" {
				return true
			}
			continue
		case "MOVW", "ADD", "SUB", "AND", "ORR", "EOR", "RSB":
			// The linear ARM path cannot handle conditional execution or post-inc.
			if strings.Contains(rawOp, ".") {
				return true
			}
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpTLSOffset || arg.Kind == asm.OpMem || arg.Kind == asm.OpRegShift || arg.Kind == asm.OpIdent ||
					(arg.Kind == asm.OpReg && (arg.Reg == "R15" || arg.Reg == asm.PC)) ||
					(arg.Kind == asm.OpSym && strings.HasSuffix(arg.Sym, "(SB)")) ||
					(arg.Kind == asm.OpReg && strings.HasPrefix(string(arg.Reg), "F")) {
					return true
				}
			}
			continue
		default:
			return true
		}
	}
	return false
}
