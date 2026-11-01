package plan9asm

import "strings"

// This family-local identity check supplies no numerical bytes or memory
// authority. Validate the complete typed form before consuming it as an effect.
// Both memory directions are checked: a register source cannot hide a symbolic,
// segmented, logical-frame or changed destination address.
func x86RawVectorMoveOperandIdentity(ins Instr, arch string) bool {
	if arch != "386" && arch != "amd64" || !x86RawOrdinaryVectorSource(ins, arch) {
		return false
	}
	for _, operand := range ins.Args {
		if operand.Kind != OpReg && (operand.Kind != OpMem || operand.Mem.Sym != "" ||
			operand.Mem.Segment != "" || !x86OrdinaryNativeMemoryOperand(operand, arch)) {
			return false
		}
		if operand.Kind == OpReg && arch == "386" {
			index, vector := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
			if vector && index >= 8 {
				return false
			}
		}
	}
	return true
}

// A low-bank physical EVEX scalar mask can have four operands in mode32 even
// though Go's named frontend has a three-operand cap. This identifies only that
// exact decoder source; the complete scalar grammar still validates every role.
func x86RawScalarVectorMoveIdentity(ins Instr, arch string) bool {
	name, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64ScalarVectorMoveSpecs[Op(name)]
	return known && !spec.legacy && !spec.rawOnly && (spec.bits == 32 || spec.bits == 64) &&
		x86RawVectorMoveOperandIdentity(ins, arch)
}

func x86RawPackedVectorMoveSourceForm(ins Instr, arch string) (amd64PackedVectorMoveForm, bool) {
	form, known, err := amd64PackedVectorMoveProperties(ins, arch)
	return form, known && err == nil && !form.undefinedOpcode() &&
		x86RawPackedMoveEncodingSource(ins, arch) && x86RawVectorMoveOperandIdentity(ins, arch)
}

func x86RawScalarVectorMoveSourceForm(ins Instr, arch string) (amd64ScalarVectorMoveForm, bool) {
	form, known, err := amd64ScalarVectorMoveProperties(ins, arch)
	return form, known && err == nil && !form.literal && x86RawScalarVectorMoveIdentity(ins, arch)
}

func x86RawVectorMoveSource(ins Instr, arch string) bool {
	if _, valid := x86RawPackedVectorMoveSourceForm(ins, arch); valid {
		return true
	}
	_, valid := x86RawScalarVectorMoveSourceForm(ins, arch)
	return valid
}

// Source-local constants retain their existing bounded literal/replay/DATA and
// raw-return consumer. This is not the ordinary native-read continuation above.
// Aligned packed loads still need their independent original pool alignment;
// a newly materialized DATA global must not invent that physical backing.
func x86RawVectorMoveLiteralSource(ins Instr, arch string) bool {
	if !x86RawLiteralSourceShape(ins, arch) || !x86RawReturnDecodedReadIdentity(ins) ||
		ins.x86RIPMemoryRead.source != 0 {
		return false
	}
	if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		return err == nil && !form.spec.aligned && form.memory == 0 && x86RawPackedMoveEncodingSource(ins, arch) &&
			ins.x86RIPMemoryRead.width == int64(form.byteWidth)
	}
	form, known, err := amd64ScalarVectorMoveProperties(ins, arch)
	return known && err == nil && !form.spec.legacy && !form.spec.rawOnly && form.memory == 0 &&
		ins.x86RIPMemoryRead.width == int64(form.spec.bits/8)
}

func x86ResultRawVectorMoveLiteralStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	if !x86RawVectorMoveLiteralSource(ins, arch) {
		return false, false
	}
	if form, known, _ := amd64PackedVectorMoveProperties(ins, arch); known && form.mask >= 0 && !form.zeroing {
		destination, _ := amd64VectorRegisterIndex(ins.Args[form.destination].Reg, form.byteWidth)
		required := x86CallerVectorByteMask(int64(form.byteWidth))
		if state.vectorBytes(destination)&required != required {
			return false, true // A possible inactive lane still consumes its actual old byte, including Void.
		}
	}
	return x86ScalarFPResultTransfer(ins, state, owned, resultOffset, arch), true
}

// Exact decoded moves compose only in the paired lowering observer. Retain the
// captured physical form while projecting provenance locally; original source,
// native entry, caller, FP/AUTO and standalone declaration roles are unchanged.
func x86LoweredRawVectorMoveStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	if x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	if _, known, _ := amd64PackedVectorMoveProperties(ins, arch); known {
		form, valid := x86RawPackedVectorMoveSourceForm(ins, arch)
		if !valid {
			return false, true
		}
		if form.memory >= 0 {
			memory := ins.Args[form.memory]
			if form.memoryWrite {
				if !x86ResultIncomingPointerAddressIdentity(memory, state, arch) {
					return false, true
				}
			} else if !x86ResultIncomingPointerReadAddressIdentity(memory, state, arch) {
				return false, true
			}
		}
		local := ins
		local.x86Encoded, local.x86SourceRaw = false, nil
		return x86ResultPackedVectorMoveTransfer(local, form, state, owned, resultOffset, arch, true), true
	}
	form, known, _ := amd64ScalarVectorMoveProperties(ins, arch)
	if !known || form.spec.legacy || form.spec.rawOnly {
		return false, false
	}
	var valid bool
	form, valid = x86RawScalarVectorMoveSourceForm(ins, arch)
	if !valid {
		return false, true
	}
	local := ins
	local.x86Encoded, local.x86SourceRaw = false, nil
	return x86ScalarVectorMoveResultTransfer(local, form, state, owned, resultOffset, arch, true), true
}

// Named scalar moves use this continuation only for their actual ordinary
// native memory path. Virtual fields and native stores have distinct effects;
// neither a load nor a defined mask supplies a future-read/backing certificate.
func x86LoweredScalarVectorMoveMemoryStep(ins Instr, state *x86ResultState, owned []bool,
	resultOffset int64, arch string) (bool, bool) {
	form, known, err := amd64ScalarVectorMoveProperties(ins, arch)
	if !known || form.spec.legacy || form.spec.rawOnly || form.memory < 0 ||
		!x86ScalarVectorMoveOrdinaryMemory(ins.Args[form.memory], form.spec.bits, arch) ||
		!x86ResultNamedPredicateInstruction(ins) {
		return false, false
	}
	return err == nil && x86ScalarVectorMoveResultTransfer(ins, form, state, owned, resultOffset, arch, true), true
}
