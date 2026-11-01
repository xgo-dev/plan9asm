package plan9asm

import (
	"errors"
	"fmt"
	"strings"
)

// Reuse pure lane/carrier axes from packed conversion, not its caller or
// numeric-family authority. Narrowing's active low bytes differ from its X/Y
// carrier; the remaining carrier bytes are architectural zeros.
var x86PackedPrecisionSpecs = map[Op]x86PackedConversionSpec{
	"CVTPS2PD": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 64,
		shapes: amd64PackedNumericWiden32To64[:1]}, legacy: true},
	"CVTPD2PS": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32,
		shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}}, legacy: true},
	"VCVTPS2PD": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 32, destinationBits: 64,
		shapes: amd64PackedNumericWiden32To64, explicit: "sae"}, vex: true},
	"VCVTPD2PSX": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32,
		shapes: []amd64PackedNumericShape{{sourceBytes: 16, destinationBytes: 16, lanes: 2}}}, vex: true},
	"VCVTPD2PSY": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32,
		shapes: []amd64PackedNumericShape{{sourceBytes: 32, destinationBytes: 16, lanes: 4}}}, vex: true},
	"VCVTPD2PS": {amd64PackedNumericConversionSpec: amd64PackedNumericConversionSpec{
		sourceKind: amd64PackedNumericFloat, destinationKind: amd64PackedNumericFloat, sourceBits: 64, destinationBits: 32,
		shapes: []amd64PackedNumericShape{{sourceBytes: 64, destinationBytes: 32, lanes: 8}}, explicit: "round"}, vex: true},
}

func x86PackedPrecisionProperties(op Op, ins Instr, arch string) (x86PackedConversionForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedPrecisionSpecs[Op(base)]
	if !known {
		return x86PackedConversionForm{}, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) || dotted && suffix == "" {
		return x86PackedConversionForm{}, true, fmt.Errorf("%s packed precision opcode/control identity mismatch: %s/%s", arch, op, ins.Op)
	}
	ins.Op = op
	local, contextual := x86VectorValueMemoryInput(ins, arch)
	form, _, err := x86PackedConversionOperandProperties(local, arch, spec)
	if err != nil {
		return form, true, err
	}
	if form.memory >= 0 {
		if contextual {
			return form, true, x86VectorValueMemoryContext(ins)
		}
		if err := x86NamedMultiplyMemoryError(ins.Args[0], arch); err != nil {
			return form, true, err
		}
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return form, true, fmt.Errorf("%w: %s needs its original default address mode", ErrProbeNeedsContext, op)
	}
	form.evex = form.evex || !spec.legacy && ins.x86PackedPrecisionEVEX
	return form, true, nil
}

func x86TypedPackedPrecisionByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedPrecisionProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width := form.inputBytes
	if form.memory >= 0 {
		width = form.memoryBytes
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: 0, operand: ins.Args[0], width: int64(width), read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: int64(form.shape.destinationBytes),
			read: form.mask >= 0 && !form.properties.zeroing, write: true},
	}}
	if form.mask >= 0 {
		effect.operands = append(effect.operands, x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect, true, nil
}

func validateX86PackedPrecisionFile(file *File, opt Options) error {
	if file == nil || file.Arch != ArchAMD64 {
		return nil
	}
	var pending error
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			_, known, err := x86PackedPrecisionProperties(ins.Op, ins, opt.Goarch)
			if !known {
				continue
			}
			if err != nil && !errors.Is(err, ErrProbeNeedsContext) {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
			if err == nil && !x86ScalarFloatIntegerNativeTarget(opt.Goarch, opt.TargetTriple) {
				err = fmt.Errorf("%w: %s needs its matching native x86 MXCSR target", ErrProbeNeedsContext, ins.Op)
			}
			if pending == nil && err != nil {
				pending = fmt.Errorf("%s: %w", fn.Sym, err)
			}
		}
	}
	return pending
}
