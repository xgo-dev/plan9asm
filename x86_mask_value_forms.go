package plan9asm

import (
	"fmt"
	"strings"
)

// The complete KADD/KSHIFT/KUNPCK grammar has only two source shapes. Width
// and operation remain independent; sharing a row does not share semantics.
type x86MaskValueForm struct {
	spec   amd64MaskArithmeticSpec
	unpack bool
}

func x86MaskValueProperties(op Op, ins Instr, arch string) (x86MaskValueForm, bool, error) {
	spec, arithmetic := amd64MaskArithmeticSpecs[op]
	bits, unpack := amd64MaskUnpackBits[op]
	if !arithmetic && !unpack {
		return x86MaskValueForm{}, false, nil
	}
	if unpack {
		spec.bits = bits
	}
	form := x86MaskValueForm{spec: spec, unpack: unpack}
	fail := func() (x86MaskValueForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands are outside Go's mask-value table: %q", arch, op, ins.Raw)
	}
	if arch != "386" && arch != "amd64" ||
		ins.Op != "" && Op(strings.ToUpper(string(ins.Op))) != op || len(ins.Args) != 3 {
		return fail()
	}
	first := 0
	if spec.shift != "" {
		immediate := ins.Args[0]
		if !amd64UnsignedImmediate(immediate, 8) {
			return fail()
		}
		first = 1
	}
	for _, operand := range ins.Args[first:] {
		if !amd64IsKOperand(operand) {
			return fail()
		}
	}
	return form, true, nil
}

func x86MaskValueResultStep(ins Instr, state *x86ResultState, arch string) (bool, bool) {
	form, known, err := x86MaskValueProperties(ins.Op, ins, arch)
	if !known || err != nil || !x86ResultNamedPredicateInstruction(ins) {
		return false, known
	}
	first := 0
	if form.spec.shift != "" {
		first = 1
	}
	for _, operand := range ins.Args[first:2] {
		index, _ := amd64ParseKReg(operand.Reg)
		if !state.masks[index] {
			return false, true
		}
	}
	destination, _ := amd64ParseKReg(ins.Args[2].Reg)
	state.masks[destination] = true
	return true, true // All GP, memory, vector and FLAGS knowledge is preserved.
}
