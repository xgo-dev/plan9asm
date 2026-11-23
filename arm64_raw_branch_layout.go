package plan9asm

type arm64RawLayoutWidths struct {
	fn Func

	branchBoundChecked bool
	textBytesBound     int64
	branchLabels       map[string]bool
}

func (widths *arm64RawLayoutWidths) knownWidth(ins Instr) (int64, bool) {
	operands, bits := arm64ConditionalBranchShape(ins.Op)
	if bits == 0 || ins.arm64Encoded {
		return arm64RawKnownSourceWidth(widths.fn, ins)
	}
	if len(ins.Args) != operands {
		return 0, false
	}
	if operands >= 2 {
		reg := ins.Args[operands-2]
		if reg.Kind != OpReg || !isARM64GeneralOrZeroReg(reg.Reg) {
			return 0, false
		}
	}
	if operands == 3 {
		bit := ins.Args[0]
		if bit.Kind != OpImm || bit.ImmRaw != "" || bit.ImmIsFloat || bit.Imm < 0 || bit.Imm > 63 {
			return 0, false
		}
	}
	target := ins.Args[operands-1]
	if target.Kind != OpIdent {
		return 0, false
	}
	if !widths.branchBoundChecked {
		widths.branchBoundChecked = true
		widths.boundConditionalBranches()
	}
	// span7 relaxes at either signed endpoint with ten bytes of slack.
	maxDistance := (int64(1) << (bits + 1)) - 10
	if !widths.branchLabels[target.Ident] || widths.textBytesBound >= maxDistance {
		return 0, false
	}
	return 4, true
}

func (widths *arm64RawLayoutWidths) boundConditionalBranches() {
	// Bound the entire TEXT so that even a target followed through a chain
	// of jumps stays in range. Count every possible veneer and worst-case
	// alignment padding. Unregistered widths can also introduce literal
	// pools, so their presence prevents this layout proof.
	labels := make(map[string]bool)
	var total int64
	for _, ins := range widths.fn.Instrs {
		if ins.Op == OpLABEL && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			labels[ins.Args[0].Sym] = true
		}
		switch {
		case !ins.arm64Encoded && arm64IsConditionalBranch(ins.Op):
			total += 12
		default:
			alignment, handled, err := arm64PCAlignment(ins)
			if err != nil {
				return
			}
			if handled {
				total += alignment - 4
				break
			}
			width, known := arm64RawKnownSourceWidth(widths.fn, ins)
			if !known {
				return
			}
			total += width
		}
		if total >= 1<<20-10 {
			return // No conditional branch can use this whole-TEXT bound.
		}
	}
	widths.textBytesBound = total
	widths.branchLabels = labels
}
