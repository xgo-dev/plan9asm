package x86

import (
	"strings"

	"github.com/xgo-dev/plan9asm/internal/asm"
)

// On x86 the machine CALL pushes its return PC in the pointer-sized word
// immediately below the incoming ABI0 frame. No other negative FP offset is
// implied by this rule.
func readsCallerPC(ins asm.Instr, goarch string) bool {
	if len(ins.Args) != 2 || ins.Args[1].Kind != asm.OpReg {
		return false
	}
	width, off, suffix := asm.OpMOVQ, int64(-8), "-8(FP)"
	if goarch == "386" {
		width, off, suffix = asm.OpMOVL, -4, "-4(FP)"
	}
	if ins.Op != width {
		return false
	}
	src := ins.Args[0]
	if src.Kind == asm.OpFP {
		return src.FPOffset == off
	}
	if src.Kind != asm.OpSym || !strings.HasSuffix(src.Sym, suffix) {
		return false
	}
	name := strings.TrimSuffix(src.Sym, suffix)
	return name != "" && !strings.ContainsAny(name, "()$+-* /")
}
