package plan9asm

import (
	"fmt"
	"strings"
)

// Go's two hardware NOP aliases share ydivl/Yml. Its ModRM operand selects
// encoding bytes only: neither registers nor the described memory are read.
// Go's operand-rich NOP pseudo and normalized raw NOP keep separate grammars.
func x86SizedNOPProperties(ins Instr, arch string) (bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if name != "NOPW" && name != "NOPL" {
		return false, nil
	}
	fail := func() (bool, error) {
		return true, fmt.Errorf("%s %s outside complete Go sized-NOP Yml grammar: %q", arch, ins.Op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 1 {
		return fail()
	}
	operand := ins.Args[0]
	if operand.Kind == OpReg {
		if !isX86YrlRegisterForArch(operand.Reg, arch) {
			return fail()
		}
	} else if !isAMD64MemoryOperand(operand) || !x86PackedShiftMemoryValid(operand, arch) ||
		x86NamedMultiplyMemoryError(operand, arch) != nil {
		return fail()
	}
	if !x86ResultNamedPredicateInstruction(ins) {
		return true, fmt.Errorf("%w: sized NOP requires named source or the separate inert raw handoff", ErrProbeNeedsContext)
	}
	return true, nil
}
