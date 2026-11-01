package plan9asm

// Scalar GP MOV rows write the complete destination register, unlike MOVK.
// A narrow register source is an extension, not a pure code-address copy.
// Literal MOVW uses the W view (clearing its upper half); it never reads Rd.
// Memory/address forms retain their separate typed grammars.
type arm64GPRegisterMoveForm struct {
	op     Op
	source Operand
}

// This same form is consumed by the control and private-data interpreters.
// Recognizing a move describes its numerical syntax, not an entry register or
// source/frame authority.
func parseARM64GPRegisterMove(ins Instr) (arm64GPRegisterMoveForm, bool) {
	op := arm64ControlOp(ins)
	switch op {
	case "MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD":
	default:
		return arm64GPRegisterMoveForm{}, false
	}
	width := arm64RawPrivateScalarBytes(op)
	if width == 0 || width > 8 || op == "MOVBW" || op == "MOVHW" ||
		string(ins.Op) != string(op) || len(ins.Args) != 2 ||
		ins.Args[1].Kind != OpReg || !isARM64GeneralOrZeroReg(ins.Args[1].Reg) {
		return arm64GPRegisterMoveForm{}, false
	}
	source := ins.Args[0]
	if source.Kind == OpReg && isARM64GeneralOrZeroReg(source.Reg) {
		return arm64GPRegisterMoveForm{op: op, source: source}, true
	}
	if source.Kind == OpImm && source.ImmRaw == "" && !source.ImmIsFloat &&
		(op == "MOVD" || op == "MOVW" || source.Imm == 0) {
		// The seven zero aliases are rewritten to ZR by Go's progedit;
		// Other narrow spellings do not have a valid literal encoder.
		// MOVWU inherits MOVW's rows, but omovconst/omovlconst do not
		// implement its nonzero literals; accepted syntax is not a proof.
		return arm64GPRegisterMoveForm{op: op, source: source}, true
	}
	return arm64GPRegisterMoveForm{}, false
}

func (state *arm64ControlState) transferGPRegisterMove(ins Instr) bool {
	form, known := parseARM64GPRegisterMove(ins)
	if !known {
		return false
	}
	value := arm64ControlExternal()
	if form.source.Kind == OpReg {
		value = state.source(form.source, false)
		if form.op != "MOVD" {
			value = arm64ControlUnion(arm64ControlExternal(), arm64ControlLabels(value))
			if arm64ControlCount(arm64ControlLabels(value)) != 0 {
				value = arm64ControlWithToken(value, "code-derived:")
			}
		}
	}
	state.write(ins.Args[1], value, false)
	return true
}
