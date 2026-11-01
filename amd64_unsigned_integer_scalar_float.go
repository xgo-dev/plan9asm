package plan9asm

import (
	"fmt"
	"strings"
)

type x86UnsignedIntegerFloatForm struct {
	x86SignedIntegerFloatForm
	nativeSource Operand
}

// All four unsigned names have one EVEX three-operand row. Reuse the signed
// family's operand axes, including mode32 WIG, without registering its caller
// or raw-source permissions. The original Op and physical source stay intact.
func x86UnsignedIntegerFloatProperties(ins Instr, arch string) (x86UnsignedIntegerFloatForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64ScalarIntegerFloatOps[base]
	if !known {
		return x86UnsignedIntegerFloatForm{}, false, nil
	}
	form, _, err := x86IntegerScalarFloatOperandProperties(ins, arch, x86SignedIntegerFloatSpec{
		sourceBits: spec.sourceBits, resultBits: spec.resultBits, rounding: spec.rounding,
	})
	if err == nil {
		err = x86NamedMultiplyMemoryError(ins.Args[0], arch)
	}
	result := x86UnsignedIntegerFloatForm{x86SignedIntegerFloatForm: form}
	if err != nil {
		return result, true, err
	}
	result.nativeSource = ins.Args[0]
	if arch == "386" && spec.sourceBits == 64 && x86ResultNamedPredicateInstruction(ins) &&
		result.nativeSource.Kind == OpMem && result.nativeSource.Mem.Sym == "" && result.nativeSource.Mem.Base != "" {
		// Go's Q row compresses with N8 even in mode32, where hardware
		// ignores W and scales the encoded disp8 by N4. Preserve the actual
		// producer address, not the written offset, in a local projection.
		// A disp32, an absolute/symbolic address and a logical FP field do
		// not acquire that register-addressed compressed-displacement role.
		offset := int64(int32(result.nativeSource.Mem.Off))
		if offset%8 == 0 && offset/8 >= -128 && offset/8 <= 127 {
			result.nativeSource.Mem.Off = offset / 2
		}
	}
	return result, true, nil
}

func x86TypedUnsignedIntegerFloatByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	if _, known := amd64ScalarIntegerFloatOps[base]; !known {
		return x86TypedByteEffect{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return x86TypedByteEffect{}, true, fmt.Errorf("unsigned scalar conversion effect/source mismatch: %s/%s", op, ins.Op)
	}
	ins.Op = op
	form, known, err := x86UnsignedIntegerFloatProperties(ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: form.nativeSource, width: int64(form.sourceBits / 8), read: true},
		{index: form.upper, operand: ins.Args[form.upper], width: 16, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: 16, write: true},
	}}, true, nil
}

func x86ResultUnsignedIntegerFloatStep(ins Instr, state *x86ResultState, owned []bool, arch string, nativeRead bool) (bool, bool) {
	form, known, err := x86UnsignedIntegerFloatProperties(ins, arch)
	if !known || err != nil {
		return false, known
	}
	return x86ResultIntegerScalarFloatInputs(ins, form.x86SignedIntegerFloatForm, state, owned, arch, nativeRead), true
}

func (c *amd64Ctx) lowerUnsignedIntegerScalarFloat(op Op, ins Instr) (bool, bool, error) {
	if ins.Op == "" {
		ins.Op = op
	} else if !strings.EqualFold(string(ins.Op), string(op)) {
		base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
		if _, known := amd64ScalarIntegerFloatOps[base]; known {
			return true, false, fmt.Errorf("unsigned scalar conversion helper opcode %s conflicts with instruction %s", op, ins.Op)
		}
		return false, false, nil
	}
	form, known, err := x86UnsignedIntegerFloatProperties(ins, c.goarch)
	if !known || err != nil {
		return known, false, err
	}
	if !x86ScalarFloatIntegerNativeTarget(c.goarch, c.targetTriple) || !x86ResultNamedPredicateInstruction(ins) {
		return true, false, fmt.Errorf("%w: %s needs its original named native x86 MXCSR target", ErrProbeNeedsContext, op)
	}
	if c.fpScalarSource.x86SourceStack != nil || c.fpScalarSource.x86FixedLocal != nil {
		return true, false, fmt.Errorf("%w: %s retains its independent source/frame owner", ErrProbeNeedsContext, op)
	}
	if form.memory >= 0 && ins.Args[0].Kind != OpFP && !x86OrdinaryNativeMemoryOperand(ins.Args[0], c.goarch) {
		return true, false, fmt.Errorf("%w: %s needs owned FP bits or an original native memory source", ErrProbeNeedsContext, op)
	}
	return true, false, c.emitNativeUnsignedIntegerScalarFloat(ins, form)
}

// One complete native opcode owns MXCSR rounding/precision, embedded SAE and
// exact m32/m64 access, even for dead results. Integer FP is gathered through
// its existing exact-bit consumer, never presented as a native stack address.
func (c *amd64Ctx) emitNativeUnsignedIntegerScalarFloat(ins Instr, form x86UnsignedIntegerFloatForm) error {
	const carrier = "<4 x float>"
	source := form.nativeSource
	width := amd64IntegerTypeForBits(form.sourceBits)
	var value, inputType, constraint, operand string
	var err error
	if source.Kind == OpReg {
		value, err = c.evalIntSized(source, width)
	} else if source.Kind == OpFP {
		var handled bool
		value, handled, err = c.loadIntegerFPBytesMode(source.FPOffset, width, true)
		if err == nil && !handled {
			err = fmt.Errorf("%w: %s lacks exact owned FP integer bits", ErrProbeNeedsContext, ins.Op)
		}
	}
	if source.Kind == OpReg || source.Kind == OpFP {
		inputType, constraint = string(width), "r"
		modifier := "k"
		if form.sourceBits == 64 {
			modifier = "q"
		}
		operand = "${2:" + modifier + "}"
	} else {
		var pointerType string
		value, pointerType, _, err = c.packedVectorMemoryPointer(source)
		inputType = fmt.Sprintf("%s elementtype([%d x i8])", pointerType, form.sourceBits/8)
		constraint, operand = "*m", "$2"
	}
	if err != nil {
		return err
	}
	upper, err := c.loadFloatingVectorOperand(ins.Args[form.upper], 16, 4, 32)
	if err != nil {
		return err
	}
	mnemonic := "vcvtusi2ss"
	if form.spec.resultBits == 64 {
		mnemonic = "vcvtusi2sd"
	}
	mnemonic += map[int]string{32: "l", 64: "q"}[form.sourceBits]
	assembly := mnemonic + " " + operand
	// Mode32 W1 behaves as W0. In particular, double's exact uint32
	// conversion ignores EVEX embedded rounding, rather than acquiring Q data.
	// LLVM's AT&T integer-to-float grammar places RC after the GP source,
	// unlike its floating-source arithmetic and precision conversions.
	if form.rounding != "" && (form.sourceBits == 64 || form.spec.resultBits == 32) {
		assembly += ", {" + strings.ToLower(strings.TrimSuffix(form.rounding, "_SAE")) + "-sae}"
	}
	assembly += ", $1, $0"
	result, bytes := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s asm sideeffect %q, %q(%s %s, %s %s)\n", result, carrier, assembly,
		"=v,v,"+constraint+",~{memory},~{fpsr}", carrier, upper, inputType, value)
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %%%s to <16 x i8>\n", bytes, carrier, result)
	return c.storePackedMoveOperand(ins.Args[form.destination], 16, "%"+bytes)
}
