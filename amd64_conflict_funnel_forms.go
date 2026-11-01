package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedConflictForm struct {
	x86PackedBinaryForm
	spec amd64PackedConflictSpec
}

// Unary _yvexpandpd has the same width/mask/address axes as the binary
// grammar. The local extra operand exists only while validating that shape;
// consumers retain the original source indexes and instruction identity.
func x86PackedConflictProperties(op Op, ins Instr, arch string) (x86PackedConflictForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64PackedConflictSpecs[Op(base)]
	result := x86PackedConflictForm{spec: spec}
	if !known {
		return result, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) || len(ins.Args) != 2 && len(ins.Args) != 3 {
		return result, true, fmt.Errorf("%s %s has an unbound dispatch or unary operand count", arch, op)
	}
	local := ins
	local.Op = op
	destination := ins.Args[len(ins.Args)-1]
	local.Args = []Operand{ins.Args[0], destination, destination}
	if len(ins.Args) == 3 {
		local.Args = []Operand{ins.Args[0], destination, ins.Args[1], destination}
	}
	var err error
	result.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch,
		x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: spec.laneBits / 8, zeroing: true}, true)
	result.second, result.destination = -1, len(ins.Args)-1
	if result.mask >= 0 {
		result.mask = 1
	}
	return result, true, err
}

type x86FunnelShiftForm struct {
	x86PackedBinaryForm
	spec amd64FunnelShiftSpec
}

func x86FunnelShiftProperties(op Op, ins Instr, arch string) (x86FunnelShiftForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := amd64FunnelShiftSpecs[Op(base)]
	result := x86FunnelShiftForm{spec: spec}
	if !known {
		return result, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return result, true, fmt.Errorf("funnel-shift dispatch/source opcode mismatch")
	}
	local := ins
	local.Op = op
	offset := 0
	if !spec.variable {
		if len(ins.Args) != 4 && len(ins.Args) != 5 || !amd64UnsignedImmediate(ins.Args[0], 8) || arch == "386" {
			return result, true, fmt.Errorf("%s %s has an invalid imm8 or named frontend arity", arch, op)
		}
		offset = 1
		local.Args = ins.Args[1:]
	}
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, zeroing: true}
	if spec.laneBits != 16 {
		grammar.broadcastBytes = spec.laneBits / 8
	}
	var err error
	result.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, grammar, false)
	result.first += offset
	result.second += offset
	result.destination += offset
	if result.mask >= 0 {
		result.mask += offset
	}
	if result.memory >= 0 {
		result.memory += offset
	}
	return result, true, err
}

func x86ConflictFunnelOperandGrammar(ins Instr, arch string, spec x86PackedBinarySpec, unary bool) (x86PackedBinaryForm, error) {
	local, contextual := x86VectorValueMemoryInput(ins, arch)
	form, err := x86PackedBinaryOperandGrammar(local, arch, spec, unary)
	if err != nil {
		return form, err
	}
	if err := x86Mode32VectorRegisterContext(ins, arch); err != nil {
		return form, err
	}
	if form.memory >= 0 && !contextual && !x86PackedShiftMemoryValid(ins.Args[form.memory], arch) {
		return form, fmt.Errorf("%s %s has an unresolved or unbound memory operand", arch, ins.Op)
	}
	if form.memory >= 0 {
		source := ins.Args[form.memory]
		if source.Kind == OpMem {
			if !x86ConditionalMoveOffsetKnown(source.Mem) || source.Mem.IndexExt != "" ||
				source.Mem.Segment != "" && source.Mem.Segment != FS && source.Mem.Segment != GS {
				return form, fmt.Errorf("%s %s has an unresolved or foreign address", arch, ins.Op)
			}
			if err := x86SymbolIndexedMemoryError(source.Mem, arch); err != nil {
				return form, err
			}
		}
		if source.Kind == OpSym {
			if address, parseErr := parseInt(strings.TrimSpace(source.Sym)); parseErr == nil &&
				address != int64(int32(address)) && !(arch == "386" && address == int64(uint32(address))) {
				return form, fmt.Errorf("%s %s absolute source exceeds its disp32 extent", arch, ins.Op)
			}
		}
	}
	if contextual {
		return form, x86VectorValueMemoryContext(ins)
	}
	if ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride {
		return form, fmt.Errorf("%w: %s needs its original default address mode", ErrProbeNeedsContext, ins.Op)
	}
	return form, nil
}

func (c *amd64Ctx) validateConflictFunnelMemory(ins Instr, form x86PackedBinaryForm) error {
	if form.memory < 0 {
		return nil
	}
	source := ins.Args[form.memory]
	if source.Kind == OpMem && !x86OrdinaryNativeMemoryOperand(source, c.goarch) &&
		!x86CallerMemoryCertified(ins, form.memory) && !c.fixedLocalMemoryCertified(ins, form.memory) {
		return fmt.Errorf("%w: %s needs its original native storage binding", ErrProbeNeedsContext, ins.Op)
	}
	if source.Kind == OpFP {
		return c.validateX86PackedShiftFPSpan(source.FPOffset, form.memoryBytes)
	}
	return nil
}

// The typed operand description is shared by byte consumers, not a caller,
// native backing or raw-entry permission. Variable funnel destinations are
// numerical inputs even with EVEX.z; immediate results only merge old bytes.
func x86TypedConflictFunnelByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	var form x86PackedBinaryForm
	var old, known bool
	var err error
	if parsed, recognized, failure := x86PackedConflictProperties(op, ins, arch); recognized {
		form, known, err = parsed.x86PackedBinaryForm, true, failure
	} else if parsed, recognized, failure := x86FunnelShiftProperties(op, ins, arch); recognized {
		form, old, known, err = parsed.x86PackedBinaryForm, parsed.spec.variable, true, failure
	}
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	return x86TypedFixedVectorInputs(ins, form, old), true, nil
}

func x86TypedFixedVectorInputs(ins Instr, form x86PackedBinaryForm, old bool) x86TypedByteEffect {
	width, firstWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		firstWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: firstWidth, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: width,
			read: old || form.mask >= 0 && !form.zeroing, write: true},
	}}
	if form.second >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.second, operand: ins.Args[form.second], width: width, read: true})
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect
}
