package plan9asm

import (
	"fmt"
	"strings"
)

type x86QwordLookupForm struct {
	x86PackedBinaryForm
	spec amd64QwordBitLookupSpec
}

// The byte result uses _yvblendmpd; the K result uses _yvpshufbitqmb.
// Share those complete existing shapes without rewriting the original inputs.
func x86QwordLookupProperties(op Op, ins Instr, arch string) (x86QwordLookupForm, bool, error) {
	base, suffix, dotted := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64QwordBitLookupSpecs[Op(base)]
	form := x86QwordLookupForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return form, true, fmt.Errorf("qword lookup dispatch/source opcode mismatch")
	}
	local := ins
	local.Op = op
	var err error
	if spec.output == amd64QwordBitLookupBytes {
		form.x86PackedBinaryForm, err = x86PackedBinaryOperandGrammar(local, arch,
			x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true},
			ins.x86Encoded || ins.x86SourceRaw != nil)
	} else {
		var valid bool
		form.x86PackedBinaryForm, valid = x86PackedMaskCompareProperties(local, arch, 0, 8, dotted, suffix)
		if !valid || dotted || arch != "386" && arch != "amd64" {
			err = fmt.Errorf("%s %s operands/suffix outside Go mask-result lookup grammar", arch, op)
		}
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(local, arch)
	}
	if err == nil && form.memory >= 0 {
		source := ins.Args[form.memory]
		if source.Kind == OpMem {
			if !x86ConditionalMoveOffsetKnown(source.Mem) || source.Mem.IndexExt != "" ||
				source.Mem.Segment != "" && source.Mem.Segment != FS && source.Mem.Segment != GS {
				err = fmt.Errorf("qword lookup source has an unresolved or foreign address")
			} else {
				err = x86SymbolIndexedMemoryError(source.Mem, arch)
			}
		}
		if err == nil && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
			err = fmt.Errorf("%w: qword lookup needs its original default address mode", ErrProbeNeedsContext)
		}
	}
	return form, true, err
}

func x86TypedQwordLookupByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86QwordLookupProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, firstWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	outputWidth := width
	if form.spec.output == amd64QwordBitLookupMask {
		outputWidth = 8
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
		{index: form.second, operand: ins.Args[form.second], width: width, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: outputWidth,
			read: form.spec.output == amd64QwordBitLookupBytes && form.mask >= 0 && !form.zeroing, write: true},
	}}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect, true, nil
}
