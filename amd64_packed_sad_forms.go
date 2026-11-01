package plan9asm

import (
	"fmt"
	"strings"
)

type x86PackedSADForm struct {
	x86PackedBinaryForm
	spec      amd64PackedSADSpec
	immediate uint8
}

// The ordered r/m, vvvv (or old destination), mask and destination views
// are shared by lowering, caller availability and native read envelopes.
// This is a grammar, not an address, initialized-value or ABI permission.
func x86PackedSADProperties(ins Instr, goarch string) (x86PackedSADForm, bool, error) {
	base, _, _ := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := amd64PackedSADSpecs[Op(base)]
	if !known {
		return x86PackedSADForm{}, false, nil
	}
	result := x86PackedSADForm{spec: spec}
	fail := func() (x86PackedSADForm, bool, error) {
		return result, true, fmt.Errorf("%s %s operands outside Go packed SAD grammar: %q", goarch, ins.Op, ins.Raw)
	}
	if goarch != "amd64" && goarch != "386" {
		return fail()
	}
	if goarch == "386" && len(ins.Args) > 3 && !ins.x86Encoded {
		return fail()
	}
	local := ins
	local.Args = append([]Operand(nil), ins.Args...)
	shift := 0
	if spec.kind != amd64PackedSADBlockSum {
		if len(local.Args) == 0 || !amd64UnsignedImmediate(local.Args[0], 8) {
			return fail()
		}
		result.immediate = uint8(local.Args[0].Imm)
		local.Args = local.Args[1:]
		shift = 1
	}
	grammar := x86PackedBinarySpec{encoding: x86PackedLogicalLegacyFP}
	if spec.form == amd64PackedSADVEXXY {
		grammar.encoding = x86PackedLogicalVEX
	} else if spec.form == amd64PackedSADEVEXXYZ {
		grammar.encoding = x86PackedLogicalVEXOrEVEX
	}
	if spec.kind == amd64PackedSADDoubleBlock {
		grammar.encoding, grammar.zeroing = x86PackedLogicalEVEX, true
	}
	// Go's shared table accepts high vector spellings on 386, but does not
	// establish their physical bank. Validate the table first and return
	// Context below, rather than misclassifying accepted syntax as invalid.
	// Address register/disp32 checks retain the actual mode independently.
	for i, operand := range local.Args {
		if operand.Kind != OpMem {
			continue
		}
		if !x86MemoryRegistersValidForArch(operand.Mem, goarch) {
			return fail()
		}
		if goarch == "386" && operand.Mem.Off == int64(uint32(operand.Mem.Off)) {
			local.Args[i].Mem.Off = int64(int32(operand.Mem.Off))
		}
	}
	form, err := x86PackedBinaryProperties(local, "amd64", grammar)
	form.first += shift
	form.second += shift
	form.destination += shift
	if form.memory >= 0 {
		form.memory += shift
	}
	if form.mask >= 0 {
		form.mask += shift
	}
	result.x86PackedBinaryForm = form
	if err == nil && goarch == "386" {
		for _, operand := range ins.Args {
			index, valid := amd64VectorRegisterIndex(operand.Reg, amd64VectorByteWidth(operand.Reg))
			if operand.Kind == OpReg && valid && index >= 8 && (form.legacy || amd64VectorByteWidth(operand.Reg) == 64) {
				return fail()
			}
		}
	}
	if err == nil && spec.kind != amd64PackedSADDoubleBlock && form.mask >= 0 {
		return fail()
	}
	if err == nil {
		err = x86Mode32VectorRegisterContext(ins, goarch)
	}
	if err == nil && form.memory >= 0 && ins.x86AddressBits != 0 {
		err = fmt.Errorf("%w: %s lacks its original native address-size binding", ErrProbeNeedsContext, ins.Op)
	}
	return result, true, err
}

// Only block SAD compares corresponding bytes. Sliding and shuffled SAD do
// not become constant merely because both operands name the same register.
// Call this only after validating the complete instruction grammar.
func (form x86PackedSADForm) constantZero(ins Instr) bool {
	return form.spec.kind == amd64PackedSADBlockSum && form.memory < 0 &&
		ins.Args[form.first].Reg == ins.Args[form.second].Reg
}

// Required byte masks for one output word. PSADBW's other six bytes in
// each qword are independent known zero; MPS/DBPS compute all output words.
func (form x86PackedSADForm) wordInputs(outputByte int) (first, second uint64) {
	switch form.spec.kind {
	case amd64PackedSADBlockSum:
		if outputByte%8 != 0 {
			return 0, 0
		}
		return uint64(255) << uint(outputByte), uint64(255) << uint(outputByte)
	case amd64PackedSADMultiple:
		lane := outputByte / 16 * 16
		control := form.immediate
		if lane != 0 {
			control >>= 3
		}
		firstOffset := lane + int(control&3)*4
		secondOffset := lane + int(control>>2&1)*4 + outputByte%16/2
		return uint64(15) << uint(firstOffset), uint64(15) << uint(secondOffset)
	default:
		block := outputByte / 8 * 8
		word := outputByte % 8 / 2
		secondOffset := block + word/2*4
		for i := 0; i < 4; i++ {
			shuffled := block + word + i
			lane := shuffled / 16 * 16
			selector := form.immediate >> uint(2*(shuffled%16/4)) & 3
			first |= uint64(1) << uint(lane+int(selector)*4+shuffled%4)
		}
		return first, uint64(15) << uint(secondOffset)
	}
}
