package plan9asm

import (
	"fmt"
	"strings"
)

type x86MoveHalfForm struct {
	spec                           amd64MoveHalfSpec
	source, base, destination      int
	memory, sourceLane, outputLane int
	store, undocumentedPDRegister  bool
}

// The complete memory and register-half families share numerical lane roles.
// Only the memory forms have an m64 tuple. A register-only alias cannot gain
// that operand shape, a native address, alignment, or backing.
func x86MoveHalfProperties(op Op, ins Instr, arch string) (x86MoveHalfForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64MoveHalfSpecs[Op(name)]
	form := x86MoveHalfForm{spec: spec, source: 0, base: -1, destination: len(ins.Args) - 1, memory: -1}
	if !known {
		return form, false, nil
	}
	if arch == "" {
		arch = "amd64"
	}
	fail := func() (x86MoveHalfForm, bool, error) {
		return form, true, fmt.Errorf("%s %s outside complete Go half-move grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return fail()
	}
	vector := func(operand Operand) bool {
		index, valid := amd64ParseXReg(operand.Reg)
		limit := 16
		if spec.vector {
			limit = 32
		} else if arch == "386" {
			limit = 8
		}
		return operand.Kind == OpReg && valid && index < limit
	}
	if spec.high {
		form.outputLane = 1
	}
	if spec.registerOnly {
		count := 2
		if spec.vector {
			count = 3
		}
		if len(ins.Args) != count || !vector(ins.Args[0]) || !vector(ins.Args[1]) || !vector(ins.Args[form.destination]) {
			return fail()
		}
		form.base = 1
		form.sourceLane = 1 - form.outputLane
	} else if len(ins.Args) == 2 && vector(ins.Args[0]) && isAMD64MemoryOperand(ins.Args[1]) {
		form.store, form.memory, form.sourceLane = true, 1, form.outputLane
	} else if spec.vector {
		if len(ins.Args) != 3 || !isAMD64MemoryOperand(ins.Args[0]) || !vector(ins.Args[1]) || !vector(ins.Args[2]) {
			return fail()
		}
		form.base, form.memory = 1, 0
	} else {
		if len(ins.Args) != 2 || !vector(ins.Args[1]) {
			return fail()
		}
		form.base = 1
		if vector(ins.Args[0]) {
			form.sourceLane = 1 - form.outputLane
			// Intel SDM/XED require ModRM.MOD!=3 for 66 0F12/16.
			// Go's shared yxmov encoder accepts these bytes anyway; this
			// records the format without inventing PS-alias semantics.
			form.undocumentedPDRegister = strings.HasSuffix(name, "PD")
		} else if isAMD64MemoryOperand(ins.Args[0]) {
			form.memory = 0
		} else {
			return fail()
		}
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, true, err
	}
	if form.memory >= 0 {
		operand := ins.Args[form.memory]
		if !x86PackedShiftMemoryValid(operand, arch) {
			return fail()
		}
		if err := x86NamedMultiplyMemoryError(operand, arch); err != nil {
			return form, true, err
		}
	}
	return form, true, nil
}

func x86TypedMoveHalfByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86MoveHalfProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	effect := x86TypedByteEffect{requiresResultProof: true}
	if form.spec.registerOnly {
		effect.vector.upperWrite = x86TypedVectorUpperPreserve
		if form.spec.vector {
			effect.vector.upperWrite = x86TypedVectorUpperZero
		}
	}
	for index, operand := range ins.Args {
		width := int64(16)
		if index == form.memory {
			width = 8
		}
		entry := x86TypedByteOperand{
			index: index, operand: operand, width: width,
			read: index == form.source || index == form.base, write: index == form.destination,
		}
		if form.spec.registerOnly {
			if index == form.source {
				entry.requiredBytes = uint64(0xff) << uint(form.sourceLane*8)
			}
			if index == form.base {
				entry.requiredBytes = uint64(0xff) << uint((1-form.outputLane)*8)
			}
		}
		effect.operands = append(effect.operands, entry)
	}
	return effect, true, nil
}
