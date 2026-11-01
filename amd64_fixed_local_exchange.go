package plan9asm

func fixedLocalExchangeStep(ins *Instr, state *x86FixedLocalState, sig FuncSig,
	proof *x86FixedLocalProof, residue int) (bool, error) {
	form, width, known, err := x86SwapProperties(*ins, "amd64")
	if !known {
		return false, nil
	}
	if err != nil {
		return true, err
	}
	if form.nop {
		return true, nil // Go's accumulator 90 encoding preserves even unknown bytes.
	}
	for _, operand := range ins.Args {
		root, _ := x86CallerGP(operand.Reg)
		if operand.Kind != OpReg && operand.Kind != OpMem || operand.Kind == OpReg && root == SP {
			return true, goAMD64FrameContext("fixed local exchange requires registers or independently owned memory")
		}
	}
	first, err := fixedLocalReadValue(ins, 0, state, sig, proof, residue, width, true)
	if err != nil {
		return true, err
	}
	last, err := fixedLocalReadValue(ins, 1, state, sig, proof, residue, width, true)
	if err != nil {
		return true, err
	}
	comparison := state.comparison
	order := [2]int{0, 1}
	if ins.Args[1].Kind == OpMem {
		order = [2]int{1, 0}
	}
	// Snapshot reads precede both writes. Write memory first so a base/index
	// that is also exchanged still addresses its original location.
	values := [2]fixedLocalScalarValue{last, first}
	for _, index := range order {
		if err := fixedLocalWriteValue(ins, index, 1-index, values[index], state, sig, proof, residue, width); err != nil {
			return true, err
		}
	}
	if width == 8 && ins.Args[0].Kind == OpReg && ins.Args[1].Kind == OpReg {
		for index, operand := range ins.Args {
			if comparison.register == operand.Reg {
				comparison.register = ins.Args[1-index].Reg
				break
			}
		}
		state.comparison = comparison
	}
	return true, nil // XCHG preserves FLAGS; only their value correlation moves.
}
