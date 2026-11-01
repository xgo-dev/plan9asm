package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedAbsSignSpec struct {
	x86PackedBinarySpec
	laneBits int
	sign     bool
}

// Go's legacy yxm_q4 rows are XMM-only, despite Intel's separate NP MMX
// encodings. ABS is unary; SIGN reads its control and data independently.
// The common shape describes encodings, not memory or physical-entry rights.
var x86PackedAbsSignSpecs = map[Op]x86PackedAbsSignSpec{
	"PABSB":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 8},
	"PABSW":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 16},
	"PABSD":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 32},
	"PSIGNB": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 8, sign: true},
	"PSIGNW": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 16, sign: true},
	"PSIGND": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}, laneBits: 32, sign: true},

	"VPABSB":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, laneBits: 8},
	"VPABSW":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, zeroing: true}, laneBits: 16},
	"VPABSD":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEXOrEVEX, broadcastBytes: 4, zeroing: true}, laneBits: 32},
	"VPABSQ":  {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalEVEX, broadcastBytes: 8, zeroing: true}, laneBits: 64},
	"VPSIGNB": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEX}, laneBits: 8, sign: true},
	"VPSIGNW": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEX}, laneBits: 16, sign: true},
	"VPSIGND": {x86PackedBinarySpec: x86PackedBinarySpec{encoding: x86PackedLogicalVEX}, laneBits: 32, sign: true},
}

type x86PackedAbsSignForm struct {
	x86PackedBinaryForm
	spec x86PackedAbsSignSpec
}

func (form x86PackedAbsSignForm) evex(ins Instr) bool {
	if form.legacy {
		return false
	}
	if ins.x86PackedAbsEVEX || form.spec.encoding == x86PackedLogicalEVEX ||
		form.byteWidth == 64 || form.mask >= 0 || form.broadcast {
		return true
	}
	for _, arg := range ins.Args {
		if index, valid := amd64VectorRegisterIndex(arg.Reg, form.byteWidth); arg.Kind == OpReg && valid && index >= 16 {
			return true
		}
	}
	return false
}

func x86PackedAbsSignProperties(op Op, ins Instr, arch string) (x86PackedAbsSignForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(op)), ".")
	spec, known := x86PackedAbsSignSpecs[Op(base)]
	form := x86PackedAbsSignForm{spec: spec}
	if !known {
		return form, false, nil
	}
	if ins.Op != "" && !strings.EqualFold(string(ins.Op), string(op)) {
		return form, true, fmt.Errorf("ABS/sign dispatch/source opcode mismatch")
	}
	if ins.x86PackedAbsEVEX && spec.encoding != x86PackedLogicalVEXOrEVEX && spec.encoding != x86PackedLogicalEVEX {
		return form, true, fmt.Errorf("%s %s has no physical EVEX generation", arch, op)
	}
	local := ins
	local.Op = op
	unary := !spec.sign && spec.encoding != x86PackedLogicalLegacyFP
	if unary {
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return form, true, fmt.Errorf("%s %s requires source, optional K1-K7 and destination", arch, op)
		}
		destination := ins.Args[len(ins.Args)-1]
		local.Args = []Operand{ins.Args[0], destination, destination}
		if len(ins.Args) == 3 {
			local.Args = []Operand{ins.Args[0], destination, ins.Args[1], destination}
		}
	}
	var err error
	form.x86PackedBinaryForm, err = x86ConflictFunnelOperandGrammar(local, arch, spec.x86PackedBinarySpec, unary)
	if !spec.sign {
		form.second = -1
	}
	if unary {
		form.destination = len(ins.Args) - 1
		if form.mask >= 0 {
			form.mask = 1
		}
	}
	return form, true, err
}

func x86TypedPackedAbsSignByteEffect(op Op, ins Instr, arch string) (x86TypedByteEffect, bool, error) {
	form, known, err := x86PackedAbsSignProperties(op, ins, arch)
	if !known || err != nil {
		return x86TypedByteEffect{}, known, err
	}
	width, sourceWidth := int64(form.byteWidth), int64(form.byteWidth)
	if form.memory >= 0 {
		sourceWidth = int64(form.memoryBytes)
	}
	effect := x86TypedByteEffect{requiresResultProof: true, operands: []x86TypedByteOperand{
		{index: form.first, operand: ins.Args[form.first], width: sourceWidth, read: true},
		{index: form.destination, operand: ins.Args[form.destination], width: width,
			read: form.spec.sign && form.legacy || form.mask >= 0 && !form.zeroing, write: true},
	}}
	if form.spec.sign && !form.legacy {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.second, operand: ins.Args[form.second], width: width, read: true})
	}
	if form.mask >= 0 {
		effect.operands = append(effect.operands,
			x86TypedByteOperand{index: form.mask, operand: ins.Args[form.mask], width: 8, read: true})
	}
	return effect, true, nil
}
