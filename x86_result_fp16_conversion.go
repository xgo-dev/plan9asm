package plan9asm

import "reflect"

func x86RawFP16ConversionSourceForm(ins Instr, arch string) (x86FP16ConversionForm, bool) {
	f, known, err := x86FP16ConversionProperties(ins, arch)
	return f, known && err == nil && x86RawOrdinaryVectorSource(ins, arch)
}

// A typed family must validate the opcode and operands before using this
// original-source identity check. It grants no standalone or native entry role.
func x86RawOrdinaryVectorSource(ins Instr, arch string) bool {
	return x86RawOrdinaryVectorSourceAt(ins, arch, 0)
}

// Validate the complete original identity before selecting the typed data
// operand. An immediate-first family must not rewrite operands to borrow the
// first-data grammar, or leave its selector outside the original identity.
func x86RawOrdinaryVectorSourceAt(ins Instr, arch string, sourceIndex int) bool {
	if sourceIndex < 0 || sourceIndex >= len(ins.Args) || ins.x86SourceRaw == nil ||
		ins.x86SourceRaw.op != ins.Op || !reflect.DeepEqual(ins.x86SourceRaw.args, ins.Args) ||
		ins.x86SourceRaw.vectorBytes != ins.x86VectorBytes ||
		ins.x86SourceRaw.addressBits != ins.x86AddressBits ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride ||
		ins.x86SegmentPrefix != 0 || ins.x86RIPLiteral || ins.x86NumericalRead != nil {
		return false
	}
	source := ins.Args[sourceIndex]
	return source.Kind == OpReg || source.Kind == OpMem && source.Mem.Sym == "" &&
		source.Mem.Segment == "" && x86OrdinaryNativeMemoryOperand(source, arch)
}

// Numerical bytes are conditional on the exact paired conversion/access.
// They provide neither MXCSR facts nor backing, bounds, entry or caller roles.
func x86LoweredFP16ConversionStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	_, known, _ := x86FP16ConversionProperties(ins, arch)
	if !known {
		return false, false
	}
	f, valid := x86RawFP16ConversionSourceForm(ins, arch)
	if !valid {
		return false, true
	}
	if f.mask >= 0 {
		mask, _ := amd64ParseKReg(ins.Args[f.mask].Reg)
		if !state.masks[mask] {
			return false, true
		}
	}
	input := x86CallerVectorByteMask(int64(f.inputBytes))
	source := ins.Args[0]
	if source.Kind == OpReg {
		index, _ := amd64VectorRegisterIndex(source.Reg, f.sourceBytes)
		if state.vectorBytes(index)&input != input {
			return false, true
		}
	} else {
		local := ins
		local.x86Encoded, local.x86SourceRaw = false, nil
		if !x86ResultReadWithNativeContinuation(local, source, int64(f.memoryBytes), state, owned, arch, true) {
			return false, true
		}
	}
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	output := x86CallerVectorByteMask(int64(f.outputBytes))
	if f.mask >= 0 && !f.controls.zeroing && state.vectorBytes(destination)&output != output {
		return false, true
	}
	value := x86CallerVectorByteMask(int64(f.byteWidth))
	if f.upper >= 0 {
		upper, _ := amd64VectorRegisterIndex(ins.Args[f.upper].Reg, 16)
		value = output | state.vectorBytes(upper)&(0xffff&^output)
	}
	state.writeVector(destination, f.byteWidth, value, false)
	return true, true
}
