package plan9asm

import "strings"

type x86NumericalSBVectorKind uint8

const (
	x86NumericalSBScalar x86NumericalSBVectorKind = iota
	x86NumericalSBAES
	x86NumericalSBLogical
)

// Consume the complete existing Go operand grammars, including all vector
// widths, immediate positions, masks and broadcasts. This selects numerical
// read operands only; a private source/native/owner join still supplies every
// exact byte and confers no permission to store or escape the global address.
func x86NumericalSBVectorReadProperties(ins Instr, arch string) (x86NumericalSBReadForm, bool) {
	form := x86NumericalSBReadForm{}
	if aes, known, err := x86AESProperties(ins.Op, ins, arch); known {
		if err != nil || aes.memory < 0 {
			return form, false
		}
		form.operand, form.partner = aes.memory, aes.destination
		form.spec.sourceBytes, form.spec.vector = int64(aes.byteWidth), x86NumericalSBAES
	} else if logical, known, err := x86PackedLogicalProperties(ins, arch); known {
		if err != nil || logical.memory < 0 || logical.mmx || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
			return form, false
		}
		form.operand, form.partner = logical.memory, logical.destination
		form.spec.sourceBytes, form.spec.vector = int64(logical.memoryBytes), x86NumericalSBLogical
	} else {
		return form, false
	}
	operand := ins.Args[form.operand]
	if operand.Kind != OpSym || strings.HasPrefix(strings.TrimSpace(operand.Sym), "$") {
		return x86NumericalSBReadForm{}, false
	}
	if _, _, valid := parseSBRef(operand.Sym); !valid {
		return x86NumericalSBReadForm{}, false
	}
	return form, true
}

// Use the existing byte dependencies with precisely this operand's certified
// numerical bytes. No incoming vector byte, mask or merge destination is
// manufactured. The temporary state receives no reusable SB memory authority.
func numericalVectorByteUpdate(ins Instr, arch string, form x86NumericalSBReadForm,
	vector func(Reg) uint64, mask func(Reg) bool,
) (destination Reg, width int, known uint64, legacy, valid bool) {
	switch form.spec.vector {
	case x86NumericalSBAES:
		aes, recognized, err := x86AESProperties(ins.Op, ins, arch)
		if !recognized || err != nil {
			return "", 0, 0, false, false
		}
		input := uint64(0)
		if aes.state >= 0 {
			input = vector(ins.Args[aes.state].Reg)
		}
		return ins.Args[aes.destination].Reg, aes.byteWidth,
			x86AESDefinedBytes(aes, x86CallerVectorByteMask(int64(aes.byteWidth)), input), !aes.spec.vector, true
	case x86NumericalSBLogical:
		logical, recognized, err := x86PackedLogicalProperties(ins, arch)
		if !recognized || err != nil || logical.mmx || logical.mask >= 0 && !mask(ins.Args[logical.mask].Reg) {
			return "", 0, 0, false, false
		}
		destination = ins.Args[logical.destination].Reg
		known = x86PackedLogicalDefinedBytes(ins, logical, x86CallerVectorByteMask(int64(logical.byteWidth)),
			vector(ins.Args[logical.second].Reg), vector(destination))
		return destination, logical.byteWidth, known, logical.legacy, true
	}
	return "", 0, 0, false, false
}

func x86ResultNumericalVectorStep(ins Instr, state *x86ResultState, arch string, form x86NumericalSBReadForm) (bool, bool) {
	destination, width, known, legacy, valid := numericalVectorByteUpdate(ins, arch, form,
		func(reg Reg) uint64 {
			index, valid := amd64VectorRegisterIndex(reg, amd64VectorByteWidth(reg))
			if !valid || index >= len(state.xmm) {
				return 0
			}
			return state.vectorBytes(index)
		}, func(reg Reg) bool {
			index, valid := amd64ParseKReg(reg)
			return valid && state.masks[index]
		})
	if !valid {
		return false, true
	}
	index, _ := amd64VectorRegisterIndex(destination, width)
	state.writeVector(index, width, known, legacy)
	return true, true
}

func numericalVectorMapStep(ins Instr, arch string, form x86NumericalSBReadForm, vectors map[Reg]uint64, masks map[Reg]bool) bool {
	destination, width, known, legacy, valid := numericalVectorByteUpdate(ins, arch, form,
		func(reg Reg) uint64 { return vectors[x86CallerVectorRoot(reg)] }, func(reg Reg) bool { return masks[reg] })
	if !valid || vectors == nil {
		return false
	}
	root := x86CallerVectorRoot(destination)
	bytes := x86CallerVectorByteMask(int64(width))
	if legacy {
		vectors[root] = vectors[root]&^bytes | known
	} else {
		vectors[root] = ^bytes | known
	}
	return true
}
