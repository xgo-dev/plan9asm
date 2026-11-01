package plan9asm

import (
	"fmt"
	"strings"
)

// Go's complete FLDENV row is Px / D9 /4 with one Ym source. This is the
// 28-byte environment, not FRSTOR's additional register image or a 16-bit
// operand-size form. Recognizing the shape grants no native memory authority.
func x86X87EnvironmentReadProperties(ins Instr, arch string) (Operand, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	if name != "FLDENV" {
		return Operand{}, false, nil
	}
	if arch != "386" && arch != "amd64" || dotted || len(ins.Args) != 1 || !isX87MemoryOperand(ins.Args[0]) {
		return Operand{}, true, fmt.Errorf("%s FLDENV expects memory source in its unsuffixed Go row: %q", arch, ins.Raw)
	}
	if err := x86NamedMultiplyMemoryError(ins.Args[0], arch); err != nil {
		return Operand{}, true, err
	}
	return ins.Args[0], true, nil
}

// Only the paired Software emitter supplies this conditional observation.
// Its exact volatile read defines CW/SW values, not native bounds, hardware
// Tag/TOP, initialized F0..F7, an empty stack, or the FRSTOR register image.
func (c *amd64Ctx) x87EnvironmentReadResultStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	source, known, err := x86X87EnvironmentReadProperties(ins, arch)
	if !known {
		return false, false
	}
	if err != nil || c.x87Mode != X87Software || state.x87 == nil || state.x87.word == nil ||
		!x86ResultNamedPredicateInstruction(ins) || ins.x86NumericalRead != nil ||
		source.Kind != OpMem || source.Mem.Sym != "" ||
		!x86OrdinaryNativeMemoryOperand(source, arch) ||
		!x86ResultIncomingPointerAddressIdentity(source, state, arch) {
		return false, true
	}
	// Initialized logical FP bytes do not imply a contiguous 28-byte native
	// allocation: each scalar parameter can have its own small alloca. AUTO,
	// DATA and logical FP require their own complete backing adapters and do
	// not inherit the ordinary reaching-pointer read role here.
	if !state.shapeOnly {
		x87 := state.x87
		x87.slots, x87.depth, x87.invalid = 0, 0, true
		x87.integer = [8]uint8{}
		x87.status, x87.word.control = 0xffff, 0xffff
	}
	return true, true
}

func x86X87RawClearInstruction(ins Instr) bool {
	origin := ins.x86SourceRaw
	return origin != nil && origin.op == "FCLEX" && len(origin.args) == 0 &&
		ins.Op == "FCLEX" && len(ins.Args) == 0
}

// Called only after the entire original/decoded/normalized raw source has
// been replayed and bound to the actual function and mode. A local opcode
// spelling or copied raw token cannot establish that source identity.
func x86ResultX87BoundRawClear(ins Instr, state *x86ResultState, owned []bool, resultOffset int64, arch string) bool {
	if !x86X87RawClearInstruction(ins) {
		return false
	}
	named := ins
	named.x86SourceRaw = nil
	accepted, known := x86ResultX87WordStep(named, state, owned, resultOffset, arch)
	return accepted && known
}
