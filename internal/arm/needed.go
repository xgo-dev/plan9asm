package arm

import (
	"github.com/xgo-dev/plan9asm/internal/asm"
	"strings"
	// funcNeedsARMCFG decides whether ARM lowering needs the CFG-based path.
	// The linear prototype only handles straight-line arithmetic/data movement.
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
		case asm.OpTEXT, asm.OpBYTE:
			continue
		case asm.OpRET:
			if len(ins.Args) != 0 {
				return true
			}
			continue
		case "MOVW", "MOVB", "MOVBU", "ADD", "SUB", "AND", "ORR", "EOR", "RSB":
			// The linear ARM path cannot handle conditional execution or post-inc.
			if strings.Contains(rawOp, ".") {
				return true
			}
			for _, arg := range ins.Args {
				if arg.Kind == asm.OpIdent {
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
