package plan9asm

import (
	"fmt"
	"strings"
)

type x86HorizontalFloatForm struct {
	spec                               amd64HorizontalFloatingSpec
	first, second, destination, memory int
	byteWidth                          int
}

// Each V-prefixed opcode has exactly the two _yvaddsubpd VEX rows, not
// EVEX rows. Sharing that ytab does not confer VADDSUB's alternating effect.
func x86HorizontalFloatProperties(ins Instr, goarch string) (x86HorizontalFloatForm, bool, error) {
	base, _, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, recognized := amd64HorizontalFloatingSpecs[Op(base)]
	if !recognized {
		return x86HorizontalFloatForm{}, false, nil
	}
	form := x86HorizontalFloatForm{spec: spec, first: 0, second: 1, destination: len(ins.Args) - 1, memory: -1, byteWidth: 16}
	fail := func() (x86HorizontalFloatForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go horizontal floating grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if dotted || goarch != "386" && goarch != "amd64" || !spec.vector && len(ins.Args) != 2 || spec.vector && len(ins.Args) != 3 {
		return fail()
	}
	if spec.vector {
		form.byteWidth = amd64VectorByteWidth(ins.Args[form.destination].Reg)
		if form.byteWidth != 16 && form.byteWidth != 32 {
			return fail()
		}
	}
	register := func(operand Operand) bool {
		index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
		return operand.Kind == OpReg && valid && (goarch == "amd64" && index < 16 || goarch == "386" && index < 8)
	}
	if goarch == "386" && spec.vector {
		for _, operand := range ins.Args {
			index, valid := amd64VectorRegisterIndex(operand.Reg, form.byteWidth)
			if operand.Kind == OpReg && valid && index >= 8 && index < 16 {
				// Go's named VEX ytab can emit these encodings in mode32,
				// but that does not establish extra physical SIMD registers.
				return form, true, fmt.Errorf("%w: 386 horizontal VEX register %s has no proved physical mode32 binding", ErrProbeNeedsContext, operand.Reg)
			}
		}
	}
	if !register(ins.Args[form.second]) || !register(ins.Args[form.destination]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) {
		if first.Kind == OpSym {
			symbol := strings.TrimSpace(first.Sym)
			_, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil {
				return fail()
			}
		}
		if first.Kind == OpMem {
			displacement := first.Mem.Off
			if displacement != int64(int32(displacement)) && (goarch != "386" || displacement != int64(uint32(displacement))) ||
				!x86MemoryRegistersValidForArch(first.Mem, goarch) || first.Mem.Index != "" &&
				(first.Mem.Index == SP || first.Mem.Scale != 1 && first.Mem.Scale != 2 && first.Mem.Scale != 4 && first.Mem.Scale != 8) {
				return fail()
			}
		}
		form.memory = 0
	} else if !register(first) {
		return fail()
	}
	return form, true, nil
}
