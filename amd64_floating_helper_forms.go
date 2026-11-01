package plan9asm

import (
	"fmt"
	"strings"
)

// These families share operand and native-effect axes, not floating-point
// arithmetic. Existing operation registrations remain the mnemonic inventory.
type x86FloatingHelperSpec struct {
	bits, bytes                            int
	scalar, immediate, second              bool
	readDestination, maskResult, round, dq bool
	estimate14, estimate28                 bool
}

func x86FloatingHelperSpecFor(op Op) (x86FloatingHelperSpec, bool) {
	if spec, known := amd64ApproximateMathSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, estimate28: true}, true
	}
	if spec, known := amd64Reciprocal14Specs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, estimate14: true}, true
	}
	if spec, known := amd64GetExpSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar}, true
	}
	if spec, known := amd64GetMantSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, immediate: true}, true
	}
	if spec, known := amd64BinaryFloatingSpecs[op]; known && spec.mode == amd64BinaryFloatingScale {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, second: true, round: true}, true
	}
	if spec, known := amd64FloatingRangeSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, immediate: true, second: true, dq: true}, true
	}
	if spec, known := amd64FixupImmediateSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, immediate: true, second: true, readDestination: true}, true
	}
	if spec, known := amd64ScaledRoundSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, scalar: spec.scalar, immediate: true, dq: spec.mode == amd64Reduce}, true
	}
	if spec, known := amd64FPClassSpecs[op]; known {
		return x86FloatingHelperSpec{bits: spec.laneBits, bytes: spec.bytes, scalar: spec.scalar, immediate: true, maskResult: true, dq: true}, true
	}
	return x86FloatingHelperSpec{}, false
}

type x86FloatingHelperForm struct {
	spec                                     x86FloatingHelperSpec
	first, second, destination, mask, memory int
	byteWidth, memoryBytes                   int
	immediate                                uint8
	properties                               amd64BinaryFloatingSuffix
}

func x86FloatingHelperProperties(ins Instr, arch string) (x86FloatingHelperForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86FloatingHelperSpecFor(Op(base))
	form := x86FloatingHelperForm{spec: spec, second: -1, mask: -1, memory: -1}
	if !known {
		return form, false, nil
	}
	fail := func() (x86FloatingHelperForm, bool, error) {
		return form, true, fmt.Errorf("%s %s operands/suffix outside Go floating-helper grammar: %q", arch, ins.Op, ins.Raw)
	}
	properties, valid := parseAMD64BinaryFloatingSuffix(suffix)
	if !valid || dotted && suffix == "" || arch != "386" && arch != "amd64" ||
		spec.scalar && properties.broadcast || spec.round && properties.sae ||
		!spec.round && properties.rounding != "" || spec.estimate14 && properties.sae || spec.maskResult && (properties.sae || properties.zeroing) {
		return fail()
	}
	form.properties = properties
	if spec.immediate {
		if len(ins.Args) == 0 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmIsFloat || ins.Args[0].ImmRaw != "" ||
			ins.Args[0].Imm < 0 || ins.Args[0].Imm > 255 {
			return fail()
		}
		form.first, form.immediate = 1, uint8(ins.Args[0].Imm)
	}
	operands := form.first + 2
	if !spec.maskResult && (spec.second || spec.scalar) {
		form.second = form.first + 1
		operands++
	}
	if len(ins.Args) != operands && len(ins.Args) != operands+1 || arch == "386" && len(ins.Args) > 3 && !ins.x86Encoded {
		return fail()
	}
	form.destination = len(ins.Args) - 1
	if len(ins.Args) == operands+1 {
		form.mask = form.destination - 1
		if !amd64NonzeroKOperand(ins.Args[form.mask]) {
			return fail()
		}
	} else if properties.zeroing {
		return fail()
	}
	destination := ins.Args[form.destination]
	form.byteWidth = amd64VectorByteWidth(destination.Reg)
	if spec.maskResult {
		if !amd64IsKOperand(destination) {
			return fail()
		}
		form.byteWidth = spec.bytes
	}
	if form.byteWidth != 16 && form.byteWidth != 32 && form.byteWidth != 64 || spec.scalar && form.byteWidth != 16 ||
		spec.estimate28 && !spec.scalar && form.byteWidth != 64 ||
		(properties.sae || properties.rounding != "") && !spec.scalar && form.byteWidth != 64 {
		return fail()
	}
	register := func(operand Operand) bool {
		return amd64GoPackedVectorMoveRegister(operand, form.byteWidth, arch)
	}
	if !spec.maskResult && !register(destination) || form.second >= 0 && !register(ins.Args[form.second]) {
		return fail()
	}
	first := ins.Args[form.first]
	if isAMD64MemoryOperand(first) {
		if properties.sae || properties.rounding != "" {
			return fail()
		}
		if first.Kind == OpMem {
			if x86SymbolIndexedMemoryError(first.Mem, arch) != nil || first.Mem.OffRaw != "" || first.Mem.IndexExt != "" ||
				first.Mem.Off != int64(int32(first.Mem.Off)) && (arch != "386" || first.Mem.Off != int64(uint32(first.Mem.Off))) ||
				!x86MemoryRegistersValidForArch(first.Mem, arch) || first.Mem.Index != "" &&
				(first.Mem.Index == SP || first.Mem.Scale != 1 && first.Mem.Scale != 2 && first.Mem.Scale != 4 && first.Mem.Scale != 8) {
				return fail()
			}
		}
		if first.Kind == OpSym {
			symbol := strings.TrimSpace(first.Sym)
			address, absolute := parseInt(symbol)
			if strings.HasPrefix(symbol, "$") || !strings.HasSuffix(symbol, "(SB)") && absolute != nil ||
				absolute == nil && address != int64(int32(address)) && (arch != "386" || address != int64(uint32(address))) {
				return fail()
			}
		}
		form.memory, form.memoryBytes = form.first, form.byteWidth
		if spec.scalar || properties.broadcast {
			form.memoryBytes = spec.bits / 8
		}
	} else if properties.broadcast || !register(first) {
		return fail()
	}
	// Go's named high banks on 386 are pre-encoding syntax, not initialized
	// physical registers. Check this only after validating the entire grammar.
	if arch == "386" {
		for _, operand := range ins.Args {
			if index, vector := amd64VectorRegisterIndex(operand.Reg, form.byteWidth); operand.Kind == OpReg && vector && index >= 8 {
				return form, true, fmt.Errorf("%w: %s has no physical mode32 binding for %s", ErrProbeNeedsContext, ins.Op, operand.Reg)
			}
		}
	}
	return form, true, nil
}

func (form x86FloatingHelperForm) activeBytes() int {
	if form.spec.scalar {
		return form.spec.bits / 8
	}
	return form.byteWidth
}

func (form x86FloatingHelperForm) nativeMnemonic(ins Instr) string {
	name, _, _ := strings.Cut(strings.ToLower(string(ins.Op)), ".")
	if form.spec.maskResult && !form.spec.scalar && (form.memory < 0 || form.properties.broadcast) {
		name = name[:len(name)-1] // Go specializes FPCLASS's source width.
	}
	return name
}

func x86TypedFloatingHelperByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	local := ins
	local.Op = op
	form, known, err := x86FloatingHelperProperties(local, arch)
	if known && ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		err = fmt.Errorf("floating-helper dispatch/source opcode mismatch")
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	firstWidth := int64(form.activeBytes())
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	outputWidth := int64(form.byteWidth)
	if form.spec.maskResult {
		outputWidth = 8
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
	}}
	if form.spec.estimate14 || form.spec.estimate28 {
		effect.vector.upperWrite = x86TypedVectorUpperZero
		// Native estimates accept unaligned memory. Their original
		// masked access/fault behavior still executes in the native helper;
		// this alignment metadata supplies no private/caller storage authority.
		effect.vector.memoryAlignment = 1
	}
	if form.second >= 0 {
		// A scalar upper source is copied as bits. Sparse numerical knowledge
		// is retained separately by the precise result-byte transfer.
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.second, operand: ins.Args[form.second], width: int64(form.byteWidth), read: true,
		})
		if (form.spec.estimate14 || form.spec.estimate28) && form.spec.scalar {
			effect.operands[len(effect.operands)-1].requiredBytes = 0xffff &^ x86CallerVectorByteMask(int64(form.activeBytes()))
		}
	}
	effect.operands = append(effect.operands, x86TypedByteOperand{
		index: form.destination, operand: ins.Args[form.destination], width: outputWidth,
		read: !form.spec.maskResult && (form.spec.readDestination || form.mask >= 0 && !form.properties.zeroing), write: true,
	})
	if (form.spec.estimate14 || form.spec.estimate28) && form.spec.scalar && form.mask >= 0 && !form.properties.zeroing {
		effect.operands[len(effect.operands)-1].requiredBytes = x86CallerVectorByteMask(int64(form.activeBytes()))
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{
			index: form.mask, operand: ins.Args[form.mask], width: 8, read: true,
		})
	}
	return effect, true, nil
}
