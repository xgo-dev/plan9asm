package plan9asm

import (
	"fmt"
	"strings"
)

func (s arm64PaddingState) transferPaddingRawConstant(ins Instr) bool {
	if ins.Op != OpWORD || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm ||
		ins.Args[0].ImmRaw != "" || ins.Args[0].ImmIsFloat {
		return false
	}
	form, known := decodeARM64RawModifiedImmediate(uint32(ins.Args[0].Imm))
	if !known {
		return false
	}
	reg := Reg(fmt.Sprintf("V%d", form.destination))
	result := arm64PaddingBits{}
	if form.op == "VORR" || form.op == "VBIC" {
		old := s.read(reg)
		for lane := 0; lane < form.arrangement.lanes; lane++ {
			// A known 1 in ORR or 0 in BIC kills just that dependency bit.
			value := old.element(form.arrangement.elementBits, lane) &^ form.value
			result.setElement(form.arrangement.elementBits, lane, value)
		}
	}
	s.write(reg, result) // MOVI/MVNI overwrite; Q=0 clears the inactive high bank.
	return true
}

func (s arm64PaddingState) transferPadding(ins Instr, decl *arm64FPReadDeclaration) error {
	op := arm64ControlOp(ins)
	if form, handled, err := parseARM64ScalarMemoryForm(op, ins); handled {
		if err != nil {
			return err
		}
		if s.observes(form.memory) {
			return arm64PaddingContext("address observes unspecified bits")
		}
		// Preserve the real source encoder's address-before-scratch-before-data
		// ordering; this proof never rewrites MOVD into a narrower source op.
		if form.scratch {
			s.write("R27", arm64PaddingBits{})
		}
		if form.store {
			if s.read(form.data)[0]&arm64PaddingMask(form.bits) != 0 {
				return arm64PaddingContext("store observes unspecified bits")
			}
			return nil
		}
		value := uint64(0)
		if read, padding := arm64FPPaddingCandidate(ins, decl); padding {
			value = arm64PaddingMask(form.bits) &^ arm64PaddingMask(int(read.declared*8))
		}
		value = arm64PaddingExtend(value, form.bits, form.signed, 64)
		s.write(form.data, arm64PaddingBits{value, 0})
		return nil
	}
	if op == "VMOV" || op == "VDUP" {
		form, err := parseARM64VectorTransfer(op, ins)
		if err != nil {
			return err
		}
		value := arm64PaddingVectorTransfer(form, s.read(form.source), s.read(form.destination))
		s.write(form.destination, value)
		return nil
	}
	_, rightShift := arm64VectorShiftRightSpecs[op]
	if op == "VSHL" || rightShift {
		form, err := parseARM64VectorShift(op, ins)
		if err != nil {
			return err
		}
		value := arm64PaddingVectorShift(op, form, s.read(form.source), s.read(form.destination))
		s.write(form.destination, value)
		return nil
	}
	if bits, signed := arm64ScalarMemoryBits(op); bits != 0 && ins.Op == op && len(ins.Args) == 2 &&
		ins.Args[1].Kind == OpReg && isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		source := ins.Args[0]
		if source.Kind == OpReg && isARM64GeneralOrZeroReg(source.Reg) {
			value := arm64PaddingExtend(s.read(source.Reg)[0], bits, signed, 64)
			s.write(ins.Args[1].Reg, arm64PaddingBits{value, 0})
			return nil
		}
		if source.Kind == OpImm && source.ImmRaw == "" && !source.ImmIsFloat &&
			(op == "MOVD" || op == "MOVW" || source.Imm == 0) {
			s.write(ins.Args[1].Reg, arm64PaddingBits{})
			return nil
		}
	}
	if spec, extend := arm64ScalarExtendSpecs[op]; extend {
		if _, handled, err := parseARM64GPDataForm(op, ins); !handled || err != nil {
			return arm64PaddingContext("invalid scalar extend")
		}
		destinationBits := 64
		if spec.wordDestination {
			destinationBits = 32
		}
		value := arm64PaddingExtend(s.read(ins.Args[0].Reg)[0], spec.sourceBits, spec.signed, destinationBits)
		s.write(ins.Args[1].Reg, arm64PaddingBits{value, 0})
		return nil
	}
	if form, handled, err := parseARM64GPDataForm(op, ins); handled {
		if err != nil {
			return err
		}
		if form.scratch != nil {
			s.write("R27", arm64PaddingBits{})
		}
		word := strings.HasSuffix(string(op), "W")
		value := uint64(0)
		for _, input := range form.inputs {
			value |= s.operand(input, word)
		}
		bits := 64
		if word {
			bits = 32
		}
		if value != 0 {
			value = arm64PaddingMask(bits) // Conservative carries/variable shifts.
		}
		if len(form.inputs) == 2 && form.inputs[0].Kind == OpImm {
			constant := uint64(form.inputs[0].Imm) & arm64PaddingMask(bits)
			left := s.operand(form.inputs[1], word)
			switch op {
			case "AND", "ANDW", "ANDS", "ANDSW":
				value = left & constant
			case "BIC", "BICW", "BICS", "BICSW", "ORR", "ORRW":
				value = left &^ constant
			case "EOR", "EORW":
				value = left
			case "LSL", "LSLW", "LSR", "LSRW", "ASR", "ASRW":
				value = arm64PaddingShift(left, bits, form.inputs[0].Imm, op != "LSL" && op != "LSLW", op == "ASR" || op == "ASRW")
			}
		}
		switch op {
		case "ADDS", "ADDSW", "SUBS", "SUBSW", "ANDS", "ANDSW", "BICS", "BICSW", "NEGS", "NEGSW", "CMP", "CMPW", "CMN", "CMNW", "TST", "TSTW":
			if value != 0 {
				return arm64PaddingContext("flags observe unspecified bits")
			}
		}
		s.write(form.destination.Reg, arm64PaddingBits{value, 0})
		return nil
	}
	if op == "CMP" || op == "CMPW" || op == "CMN" || op == "CMNW" || op == "TST" || op == "TSTW" {
		word := strings.HasSuffix(string(op), "W")
		if ins.Op != op || len(ins.Args) != 2 || validateARM64CompareNegativeOperands(ins.Args[0], ins.Args[1], word) != nil {
			return arm64PaddingContext("unregistered comparison operands")
		}
		if s.operand(ins.Args[0], word) != 0 || s.operand(ins.Args[1], word) != 0 {
			return arm64PaddingContext("comparison observes unspecified bits")
		}
		return nil
	}
	// Only this explicit operand-complete remainder is admitted. Unrecognized
	// instructions cannot gain a hidden-state permission merely because their
	// parser happened to expose no padding-tainted explicit operand.
	switch op {
	case "NOP", "VMOVQ", "VADD", "VADDP", "VSUB", "VAND", "VORR", "VEOR", "VBIC",
		"VCMGT", "VCMGE", "VCMEQ", "VCMHI", "VCMHS", "VCMTST", "VUSHL", "VSSHL", "VUSHLL", "VSSHLL", "VUXTL", "VUXTL2",
		"CSET", "CSETW", "CSETM", "CSETMW", "FMOVS", "FMOVD", "VLD1", "VLD2", "VLD3", "VLD4", "VST1", "VST2", "VST3", "VST4":
	default:
		if (op != "MOVBW" && op != "MOVHW") || !ins.arm64Encoded {
			return arm64PaddingContext("unregistered whole-source effect %s", op)
		}
	}
	// For these registered instructions no padding-tainted operand, including
	// a possibly destructive destination, may be consumed. Do not mistake an
	// unfamiliar effect for a known overwrite and wash away a dependency.
	for _, arg := range ins.Args {
		if s.observes(arg) {
			return arm64PaddingContext("unregistered effect observes unspecified bits")
		}
	}
	return nil
}
