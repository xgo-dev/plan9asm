package plan9asm

import (
	"fmt"
	"strings"
)

type amd64ScalarVectorMoveSpec struct {
	bits    int
	legacy  bool
	rawOnly bool
}

// MOVSS/SD share yxmov; VMOVSS/SD share all twelve _yvmovsd rows.
// VMOVSH is a separate raw-only FP16 encoding, not a named Go instruction.
var amd64ScalarVectorMoveSpecs = map[Op]amd64ScalarVectorMoveSpec{
	"MOVSS": {bits: 32, legacy: true}, "MOVSD": {bits: 64, legacy: true},
	"VMOVSS": {bits: 32}, "VMOVSD": {bits: 64},
	"VMOVSH": {bits: 16, rawOnly: true},
}

type amd64ScalarVectorMoveForm struct {
	spec        amd64ScalarVectorMoveSpec
	low         int
	upper       int // -1 when there is no register upper-lane source
	destination int
	mask        int // -1 when unmasked
	memory      int // -1 for register-to-register forms
	memoryWrite bool
	zeroing     bool
	literal     bool // frontend constant-pool rewrite, not a user memory operand
	legacyZero  bool // obj6.progedit rewrites positive zero in X0-X15 to XORPS
}

// This is operand grammar only. It grants no memory bounds, initialized data,
// K-register value, or source continuation. Both lowerer and source proof use
// the exact same direction/width/merge axes.
func amd64ScalarVectorMoveProperties(ins Instr, goarch string) (amd64ScalarVectorMoveForm, bool, error) {
	name := strings.ToUpper(string(ins.Op))
	base, suffix, _ := strings.Cut(name, ".")
	spec, recognized := amd64ScalarVectorMoveSpecs[Op(base)]
	if !recognized {
		return amd64ScalarVectorMoveForm{}, false, nil
	}
	form := amd64ScalarVectorMoveForm{
		spec: spec, low: 0, upper: -1, destination: len(ins.Args) - 1,
		mask: -1, memory: -1, zeroing: suffix == "Z",
	}
	fail := func() (amd64ScalarVectorMoveForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix are outside the scalar vector-move grammar: %q", goarch, base, ins.Raw)
	}
	if spec.rawOnly && !ins.x86Encoded || suffix != "" && suffix != "Z" ||
		goarch == "386" && len(ins.Args) > 3 && !ins.x86Encoded && !x86RawScalarVectorMoveIdentity(ins, goarch) {
		return fail()
	}
	vector := func(operand Operand) bool {
		if !amd64ScalarXOperand(operand) {
			return false
		}
		if !spec.legacy {
			return true
		}
		index, _ := amd64ParseXReg(operand.Reg)
		return index < 16 && (goarch != "386" || index < 8)
	}
	if len(ins.Args) >= 2 && ins.Args[0].Kind == OpImm {
		literal := ins.Args[0]
		if spec.rawOnly || !literal.ImmIsFloat || literal.ImmRaw != "" || !vector(ins.Args[form.destination]) {
			return fail()
		}
		index, _ := amd64ParseXReg(ins.Args[form.destination].Reg)
		form.literal, form.legacyZero = true, literal.Imm == 0 && index < 16
		if goarch == "386" && form.legacyZero && index >= 8 {
			return fail() // the final legacy XORPS cannot address X8-X15 in mode32
		}
		switch len(ins.Args) {
		case 2:
			if suffix != "" {
				return fail()
			}
		case 3:
			// A pool memory source has no register upper-merge source. The
			// positive-zero rewrite retains RestArgs/Scond, which makes a
			// masked low-register XORPS invalid in Go's final optab.
			if spec.legacy || form.legacyZero || !amd64NonzeroKOperand(ins.Args[1]) {
				return fail()
			}
			form.mask = 1
		default:
			return fail()
		}
		return form, true, nil
	}
	if spec.legacy {
		if suffix != "" || len(ins.Args) != 2 {
			return fail()
		}
		if vector(ins.Args[0]) && (vector(ins.Args[1]) || isAMD64MemoryOperand(ins.Args[1])) {
			if isAMD64MemoryOperand(ins.Args[1]) {
				form.memory, form.memoryWrite = 1, true
			}
			return form, true, nil
		}
		if isAMD64MemoryOperand(ins.Args[0]) && vector(ins.Args[1]) {
			form.memory = 0
			return form, true, nil
		}
		return fail()
	}
	merge := func(mask int) bool {
		return vector(ins.Args[0]) && vector(ins.Args[1]) && vector(ins.Args[form.destination]) &&
			(mask < 0 || amd64NonzeroKOperand(ins.Args[mask]))
	}
	switch len(ins.Args) {
	case 2:
		if form.zeroing {
			return fail()
		}
	case 3:
		if merge(-1) {
			if form.zeroing {
				return fail()
			}
			form.upper = 1
			return form, true, nil
		}
		form.mask = 1
		if !amd64NonzeroKOperand(ins.Args[1]) {
			return fail()
		}
	case 4:
		if !merge(2) {
			return fail()
		}
		form.upper, form.mask = 1, 2
		return form, true, nil
	default:
		return fail()
	}
	if vector(ins.Args[0]) && isAMD64MemoryOperand(ins.Args[form.destination]) && !form.zeroing {
		form.memory, form.memoryWrite = form.destination, true
		return form, true, nil
	}
	if isAMD64MemoryOperand(ins.Args[0]) && vector(ins.Args[form.destination]) {
		form.memory = 0
		return form, true, nil
	}
	return fail()
}
