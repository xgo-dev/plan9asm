package plan9asm

import (
	"fmt"
	"strings"
)

type arm64GPDataForm struct {
	inputs      []Operand
	destination Operand
	implicit    []Reg
	scratch     *Operand
}

// The Go ADD, AND/ANDS, NEG, MVN, LSL, SXTB and BFI rows have a
// full GP result, even for a W result (which clears its upper half). Only
// the shorthand and insert rows read the old Rd. This grammar is shared by
// lowering, continuation values and both may-frame address proofs; an opcode
// name or a raw GP-write mask alone is never a known overwrite.
func parseARM64GPDataForm(op Op, ins Instr) (form arm64GPDataForm, handled bool, err error) {
	if move, handled, err := parseARM64NamedMoveWide(op, ins); handled && move.op != "MOVK" {
		if err != nil {
			return form, true, err
		}
		// MOVN/Z do not consume the old destination, unlike MOVK's existing
		// read-modify-write contract. W also overwrites the complete X alias.
		form.destination = ins.Args[1]
		return form, true, nil
	}
	if bitfield, handled, err := parseARM64NamedBitfield(op, ins); handled {
		if err != nil {
			return form, true, err
		}
		form.inputs, form.destination = ins.Args[1:2], ins.Args[3]
		if bitfield.op == "BFM" {
			form.inputs = []Operand{ins.Args[1], ins.Args[3]}
		}
		return form, true, nil
	}
	if immediate, handled, err := parseARM64GPImmediateForm(op, ins); handled {
		if err != nil {
			return form, true, err
		}
		form.inputs = []Operand{ins.Args[0], immediate.left}
		form.destination = immediate.destination
		if immediate.scratch {
			constant := Operand{Kind: OpImm, Imm: int64(immediate.value)}
			form.scratch = &constant
			if immediate.left.Reg == "R27" {
				form.inputs[1] = constant
			}
			if immediate.destination.Reg != "R27" {
				form.implicit = []Reg{"R27"}
			}
		}
		return form, true, nil
	}
	family := ""
	word := strings.HasSuffix(string(op), "W")
	switch op {
	case "ADD", "ADDS", "SUB", "SUBS", "ADDW", "ADDSW", "SUBW", "SUBSW":
		family = "add"
	case "AND", "ANDW", "EOR", "EORW", "ORR", "ORRW", "BIC", "BICW", "EON", "EONW", "ORN", "ORNW", "ANDS", "ANDSW", "BICS", "BICSW":
		family = "logical"
	case "LSL", "LSLW", "LSR", "LSRW", "ASR", "ASRW", "ROR", "RORW":
		family = "shift"
	case "NEG", "NEGW", "NEGS", "NEGSW":
		family = "negate"
	case "MVN", "MVNW":
		family = "invert"
	case "BFI", "BFIW", "BFXIL", "BFXILW", "SBFIZ", "SBFIZW", "SBFX", "SBFXW", "UBFIZ", "UBFIZW", "UBFX", "UBFXW":
		family = "bitfield"
	default:
		if divide, handled, err := parseARM64DivideRemainderForm(op, ins); handled {
			if err != nil {
				return form, true, err
			}
			form.inputs = []Operand{divide.divisor, divide.dividend}
			form.destination = divide.destination
			if divide.remainder && divide.destination.Reg != "R27" {
				form.implicit = []Reg{"R27"}
			}
			return form, true, nil
		} else if _, ok := arm64ScalarExtendSpecs[op]; ok {
			family = "extend"
		} else if inputs, destination, valid := arm64ScalarMultiplyInputs(op, ins); valid {
			return arm64GPDataForm{inputs: inputs, destination: destination}, true, nil
		} else {
			return form, false, nil
		}
	}
	invalid := func() (arm64GPDataForm, bool, error) {
		return form, true, fmt.Errorf("arm64 %s operands are outside its typed Go GP data rows: %q", op, ins.Raw)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) == 0 {
		return invalid()
	}
	form.destination = ins.Args[len(ins.Args)-1]
	destinationGP := arm64ScalarMultiplyRegister(form.destination)
	destinationSP := form.destination.Kind == OpReg && arm64StackReg(form.destination.Reg)
	if !destinationGP && !destinationSP {
		return invalid()
	}
	bits := int64(64)
	if word {
		bits = 32
	}
	switch family {
	case "add", "logical", "shift":
		if len(ins.Args) != 2 && len(ins.Args) != 3 {
			return invalid()
		}
		source, left := ins.Args[0], form.destination
		if len(ins.Args) == 3 {
			left = ins.Args[1]
		}
		leftGP := arm64ScalarMultiplyRegister(left)
		leftSP := left.Kind == OpReg && arm64StackReg(left.Reg)
		valid := false
		switch family {
		case "add":
			valid = (leftGP || leftSP) && arm64AddFlagsSourceValid(source, word)
			if (leftSP || destinationSP) && source.Kind == OpRegShift {
				valid = valid && source.ShiftOp == ShiftLeft && source.ShiftAmount <= 4
			}
		case "logical":
			valid = leftGP && arm64BitClearSourceValid(source, word)
			if destinationSP {
				flags := op == "ANDS" || op == "ANDSW" || op == "BICS" || op == "BICSW"
				valid = valid && !flags && source.Kind == OpImm && len(ins.Args) == 3
			}
		case "shift":
			valid = leftGP && destinationGP && (arm64ScalarMultiplyRegister(source) ||
				source.Kind == OpImm && source.ImmRaw == "" && !source.ImmIsFloat && source.Imm >= 0 && source.Imm < bits)
		}
		if !valid || source.Kind == OpImm && source.ImmIsFloat {
			return invalid()
		}
		form.inputs = []Operand{source, left}
	case "negate", "invert":
		if !destinationGP || len(ins.Args) != 2 && (family != "negate" || len(ins.Args) != 1) {
			return invalid()
		}
		source := ins.Args[0]
		valid := validateARM64NegateSource(source, word) == nil
		if family == "invert" {
			valid = source.Kind != OpImm && arm64BitClearSourceValid(source, word)
		}
		if !valid {
			return invalid()
		}
		form.inputs = []Operand{source}
	case "extend":
		if !destinationGP || len(ins.Args) != 2 || !arm64ScalarMultiplyRegister(ins.Args[0]) {
			return invalid()
		}
		form.inputs = ins.Args[:1]
	case "bitfield":
		if !destinationGP || len(ins.Args) != 4 || !arm64ScalarMultiplyRegister(ins.Args[1]) {
			return invalid()
		}
		lsb, width := ins.Args[0], ins.Args[2]
		if lsb.Kind != OpImm || width.Kind != OpImm || lsb.ImmRaw != "" || width.ImmRaw != "" ||
			lsb.ImmIsFloat || width.ImmIsFloat || lsb.Imm < 0 || lsb.Imm >= bits || width.Imm <= 0 || width.Imm > bits-lsb.Imm {
			return invalid()
		}
		form.inputs = ins.Args[1:2]
		if strings.HasPrefix(string(op), "BFI") || strings.HasPrefix(string(op), "BFXIL") {
			form.inputs = []Operand{ins.Args[1], form.destination}
		}
	}
	return form, true, nil
}

func arm64GPDataInputRegisters(form arm64GPDataForm) []Reg {
	registers := make([]Reg, 0, len(form.inputs))
	for _, input := range form.inputs {
		if input.Kind == OpReg || input.Kind == OpRegShift || input.Kind == OpRegExtend {
			registers = append(registers, input.Reg)
		}
	}
	return registers
}

func arm64GPDataOutputRegisters(form arm64GPDataForm) []Reg {
	var outputs []Reg
	if form.destination.Kind == OpReg {
		outputs = append(outputs, form.destination.Reg)
	}
	return append(outputs, form.implicit...)
}

func (state *arm64ControlState) transferGPData(ins Instr) bool {
	form, handled, err := parseARM64GPDataForm(arm64ControlOp(ins), ins)
	if !handled || err != nil {
		return false
	}
	if form.scratch != nil {
		state.regs["R27"] = arm64ControlExternal()
	}
	value := arm64ControlExternal()
	for _, reg := range arm64GPDataInputRegisters(form) {
		value = arm64ControlUnion(value, arm64ControlLabels(arm64ControlRead(state.regs, arm64ControlBase(reg))))
	}
	if arm64ControlCount(arm64ControlLabels(value)) != 0 {
		value = arm64ControlWithToken(value, "code-derived:")
	}
	for _, reg := range arm64GPDataOutputRegisters(form) {
		if form.scratch != nil && reg == "R27" && form.destination.Reg != "R27" {
			continue
		}
		state.write(Operand{Kind: OpReg, Reg: reg}, value, false)
	}
	return true
}
