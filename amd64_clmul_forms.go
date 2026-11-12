package plan9asm

import (
	"fmt"
	"strings"
)

// Go's yxshuf and _yvpclmulqdq rows select one qword from each 128-bit
// lane. The complete memory tuple is distinct from those numerical inputs.
type x86CLMULForm struct {
	legacy                    bool
	byteWidth, source, second int
	destination, memory       int
	immediate                 uint8
}

func x86CLMULProperties(op Op, ins Instr, arch string) (x86CLMULForm, bool, error) {
	name, _, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	if name != "PCLMULQDQ" && name != "VPCLMULQDQ" {
		return x86CLMULForm{}, false, nil
	}
	f := x86CLMULForm{legacy: name == "PCLMULQDQ", source: 1, second: 2, destination: 3, memory: -1}
	if f.legacy {
		f.destination = 2
	}
	fail := func() (x86CLMULForm, bool, error) {
		return f, true, fmt.Errorf("%s %s outside complete Go carryless-multiply grammar: %q", arch, op, ins.Raw)
	}
	if arch != "amd64" && arch != "386" || dotted ||
		ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) ||
		len(ins.Args) != f.destination+1 || arch == "386" && !f.legacy && !ins.x86Encoded {
		return fail()
	}
	constant, valid := x86ImmediateShuffleConstant(ins.Args[0], arch, ins.x86Encoded)
	if !valid || !amd64UnsignedImmediate(constant, 8) {
		return fail()
	}
	f.immediate = uint8(constant.Imm)
	f.byteWidth = amd64VectorByteWidth(ins.Args[f.destination].Reg)
	if f.legacy && f.byteWidth != 16 || f.byteWidth != 16 && f.byteWidth != 32 && f.byteWidth != 64 {
		return fail()
	}
	register := func(operand Operand) bool {
		index, valid := amd64VectorRegisterIndex(operand.Reg, f.byteWidth)
		limit := 32
		if f.legacy {
			limit = 16
		}
		if arch == "386" {
			limit = 8 // A physical raw binding is not a high-bank or named-frontend permission.
		}
		return operand.Kind == OpReg && valid && index < limit
	}
	if !register(ins.Args[f.second]) || !register(ins.Args[f.destination]) {
		return fail()
	}
	source := ins.Args[f.source]
	if register(source) {
		return f, true, nil
	}
	if !isAMD64MemoryOperand(source) || !x86PackedShiftMemoryValid(source, arch) {
		return fail()
	}
	if source.Kind == OpMem {
		if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
			return f, true, err
		}
		if source.Mem.OffRaw != "" || source.Mem.IndexExt != "" {
			return fail()
		}
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return f, true, fmt.Errorf("%w: carryless multiply has no bound native address-size override", ErrProbeNeedsContext)
	}
	f.memory = f.source
	return f, true, nil
}

func x86TypedLegacyCLMULByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86CLMULProperties(op, ins, arch)
	if !known || err != nil || !form.legacy {
		return x86TypedByteEffect{}, known && (err != nil || form.legacy), err
	}
	return x86CLMULDependencyEffect(ins, form), true, nil
}

func x86CLMULDependencyEffect(ins Instr, form x86CLMULForm) x86TypedByteEffect {
	binary := x86PackedBinaryForm{
		byteWidth: form.byteWidth, first: form.source, second: form.second, destination: form.destination,
		legacy: form.legacy, mask: -1, memory: form.memory, memoryBytes: form.byteWidth,
	}
	effect := x86PackedBinaryDependencyEffect(ins, binary, ins.Args[form.source])
	source, second := x86CLMULSelectedBytes(form)
	if ins.Args[form.source].Kind == OpReg {
		effect.operands[0].requiredBytes = source
	}
	effect.operands[1].requiredBytes = second
	return effect
}

// Selection controls numerical register inputs, never the physical memory
// tuple. Each lane consumes one qword from each of the two source operands.
func x86CLMULSelectedBytes(f x86CLMULForm) (source, second uint64) {
	for lane := 0; lane < f.byteWidth; lane += 16 {
		source |= uint64(255) << uint(lane+int(f.immediate>>4&1)*8)
		second |= uint64(255) << uint(lane+int(f.immediate&1)*8)
	}
	return
}

// Each product requires all bytes of exactly two selected qwords. No mask,
// unselected qword, destination alias or numerical zero supplies a missing input.
func x86CLMULDefinedBytes(f x86CLMULForm, source, second uint64) uint64 {
	var known uint64
	sourceBytes, secondBytes := x86CLMULSelectedBytes(f)
	for lane := 0; lane < f.byteWidth; lane += 16 {
		laneMask := uint64(65535) << uint(lane)
		sourceMask, secondMask := sourceBytes&laneMask, secondBytes&laneMask
		if source&sourceMask == sourceMask && second&secondMask == secondMask {
			known |= laneMask
		}
	}
	return known
}

func x86ResultCLMULStep(ins Instr, state *x86ResultState, owned []bool, arch string) (bool, bool) {
	f, known, err := x86CLMULProperties(ins.Op, ins, arch)
	if !known {
		return false, false
	}
	if err != nil {
		return false, true
	}
	return x86ResultCLMULTransfer(ins, f, state, owned, arch, false)
}

// Keep the complete captured form across a source-local provenance projection.
// Memory always consumes the original full tuple; numerical availability still
// depends only on the two selected qwords of each independent 128-bit lane.
func x86ResultCLMULTransfer(ins Instr, f x86CLMULForm, state *x86ResultState,
	owned []bool, arch string, nativeRead bool) (bool, bool) {
	source := x86CallerVectorByteMask(int64(f.byteWidth))
	if f.memory >= 0 {
		if !x86ResultReadWithNativeContinuation(ins, ins.Args[f.memory], int64(f.byteWidth), state, owned, arch, nativeRead) {
			return false, true
		}
	} else {
		index, _ := amd64VectorRegisterIndex(ins.Args[f.source].Reg, f.byteWidth)
		source = state.vectorBytes(index)
	}
	second, _ := amd64VectorRegisterIndex(ins.Args[f.second].Reg, f.byteWidth)
	destination, _ := amd64VectorRegisterIndex(ins.Args[f.destination].Reg, f.byteWidth)
	state.writeVector(destination, f.byteWidth, x86CLMULDefinedBytes(f, source, state.vectorBytes(second)), f.legacy)
	return true, true
}

func x86CallerCLMULStep(ins Instr, f x86CLMULForm, state *x86SourceStackState) bool {
	if f.memory >= 0 {
		return false // A registered byte effect grants no new native read proof.
	}
	source := state.vectors[x86CallerVectorRoot(ins.Args[f.source].Reg)]
	second := state.vectors[x86CallerVectorRoot(ins.Args[f.second].Reg)]
	destination := x86CallerVectorRoot(ins.Args[f.destination].Reg)
	width := x86CallerVectorByteMask(int64(f.byteWidth))
	known := x86CLMULDefinedBytes(f, source, second)
	if f.legacy {
		state.vectors[destination] = state.vectors[destination]&^width | known
	} else {
		state.vectors[destination] = ^width | known
	}
	return true
}
