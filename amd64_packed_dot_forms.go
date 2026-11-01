package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedDotForm struct {
	x86PackedBinaryForm
	spec amd64PackedDotProductSpec
}

// The four integer operations share Go's complete _yvblendmpd grammar.
// Raw VEX is a distinct register/full-memory X/Y shape, not a named Go row;
// BF16 never inherits this integer grammar or its numerical continuation.
func x86PackedDotProperties(op Op, ins Instr, arch string) (x86PackedDotForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedDotProductSpecs[Op(base)]
	if !known || spec.bfloat {
		return x86PackedDotForm{}, false, nil
	}
	result := x86PackedDotForm{spec: spec}
	if ins.Op != "" && !strings.EqualFold(string(op), string(ins.Op)) {
		return result, true, fmt.Errorf("integer dot-product dispatch/source opcode mismatch")
	}
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 4, zeroing: true}
	if ins.x86PackedDotEncoding == x86RawPackedDotVEX {
		grammar = x86PackedBinarySpec{encoding: x86PackedLogicalVEX}
	}
	local := ins
	local.Op = op
	var err error
	result.x86PackedBinaryForm, err = x86PackedBinaryOperandGrammar(local, arch, grammar, ins.x86Encoded)
	if err != nil || result.memory < 0 {
		return result, true, err
	}
	source := ins.Args[result.memory]
	if !x86PackedShiftMemoryValid(source, arch) || source.Kind == OpMem &&
		(!x86ConditionalMoveOffsetKnown(source.Mem) || source.Mem.IndexExt != "" ||
			source.Mem.Segment != "" && source.Mem.Segment != FS && source.Mem.Segment != GS) {
		return result, true, fmt.Errorf("%s has an unresolved or foreign memory source", op)
	}
	if source.Kind == OpSym {
		if address, parseErr := parseInt(strings.TrimSpace(source.Sym)); parseErr == nil &&
			address != int64(int32(address)) && !(arch == "386" && address == int64(uint32(address))) {
			err = fmt.Errorf("%s absolute source exceeds its disp32 extent", op)
		}
	} else if source.Kind == OpMem {
		err = x86SymbolIndexedMemoryError(source.Mem, arch)
	}
	if err == nil && (ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride) {
		err = fmt.Errorf("%w: %s needs its original default address mode", ErrProbeNeedsContext, op)
	}
	return result, true, err
}

func x86TypedPackedDotByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedDotProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, firstWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
		{index: form.second, operand: ins.Args[form.second], width: width, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: width, read: true, write: true},
	}}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect, true, nil
}

// All three inputs contribute the corresponding dword, including the old
// destination with zero masking. Neither a mask nor an implementation zero
// initializes an arithmetic input, including dead results in Void functions.
func (form x86PackedDotForm) inputsDefined(first, second, old uint64) bool {
	output := x86CallerVectorByteMask(int64(form.byteWidth))
	input := output
	if form.broadcast {
		input = 15
	}
	return first&input == input && second&output == output && old&output == output
}
