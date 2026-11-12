package plan9asm

import "strings"

// funcNeedsARMCFG is retained for focused classifier tests and historical
// callers. Translate now always selects the CFG path for supported ARM code so
// straight-line functions cannot bypass architecture-specific form checks.
func funcNeedsARMCFG(fn Func) bool {
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			return true
		}
		rawOp := strings.ToUpper(string(ins.Op))
		op := rawOp
		if dot := strings.IndexByte(op, '.'); dot >= 0 {
			op = op[:dot]
		}
		switch Op(op) {
		case OpTEXT, OpBYTE:
			continue
		case OpRET:
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
				if arg.Kind == OpIdent || arg.Kind == OpFPAddr {
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
