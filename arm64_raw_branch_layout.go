package plan9asm

type arm64LayoutPCBounds struct{ first, last int64 }

type arm64RawLayoutWidths struct {
	fn Func

	branchBoundChecked bool
	textBytesBound     int64
	branchLabels       map[string]int
	pcBounds           []arm64LayoutPCBounds
}

func (widths *arm64RawLayoutWidths) knownWidth(at int) (int64, bool) {
	ins := widths.fn.Instrs[at]
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
	targetIndex, ok := widths.branchLabels[target.Ident]
	if !ok {
		return 0, false
	}
	if widths.textBytesBound < maxDistance {
		return 4, true // Even a target reached through a jump chain is in range.
	}
	switch arm64ControlOp(widths.fn.Instrs[targetIndex]) {
	case "B", "JMP":
		return 0, false // Go can collapse this jump to a different target.
	}
	from, to := widths.pcBounds[at], widths.pcBounds[targetIndex]
	first, last := to.first-from.last, to.last-from.first
	if first >= maxDistance || last <= -maxDistance {
		// Both the initial and the relaxed layout require two extra words.
		// These words contain no original source instruction boundaries.
		return 12, true
	}
	if first > -maxDistance && last < maxDistance {
		return 4, true
	}
	return 0, false
}

func (widths *arm64RawLayoutWidths) boundConditionalBranches() {
	// Lay out lower and upper PC bounds while each conditional may occupy
	// either one or three words. Unknown instruction widths may also put
	// literal pools elsewhere in the TEXT, so they prevent this proof.
	bounds := make([]arm64LayoutPCBounds, len(widths.fn.Instrs))
	pc := arm64LayoutPCBounds{}
	if !arm64DeclaredFramelessText(widths.fn) {
		// A generated prefix may place the body at any word offset modulo
		// 2048, the largest accepted PCALIGN. Multiples of 2048 cancel in
		// relative distances and do not affect padding sizes.
		pc.last = 2044
	}
	var total int64
	for at, ins := range widths.fn.Instrs {
		bounds[at] = pc
		switch {
		case !ins.arm64Encoded && arm64IsConditionalBranch(ins.Op):
			pc.first += 4
			pc.last += 12
			total += 12
		default:
			alignment, handled, err := arm64PCAlignment(ins)
			if err != nil {
				return
			}
			if handled {
				// Rounding up to alignment, optionally only within the
				// PCALIGNMAX limit, is monotone even at a padding boundary.
				pc.first = arm64RawAlignedOffset(pc.first, alignment, ins)
				pc.last = arm64RawAlignedOffset(pc.last, alignment, ins)
				total += alignment - 4
				break
			}
			width, known := arm64RawKnownSourceWidth(widths.fn, ins)
			if !known {
				return
			}
			pc.first += width
			pc.last += width
			total += width
		}
		if pc.last >= 1<<31-2048 {
			return // Go computes the alignment padding from an int32 PC.
		}
	}
	// The Go assembler targets the Prog after any consecutive labels.
	labels := make(map[string]int)
	next := len(widths.fn.Instrs)
	for at := next - 1; at >= 0; at-- {
		ins := widths.fn.Instrs[at]
		if ins.Op != OpLABEL {
			next = at
		} else if next < len(widths.fn.Instrs) && len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
			labels[ins.Args[0].Sym] = next
		}
	}
	widths.textBytesBound = total
	widths.branchLabels = labels
	widths.pcBounds = bounds
}

func arm64RawAlignedOffset(offset, alignment int64, ins Instr) int64 {
	padding := -offset & (alignment - 1)
	if ins.Op == "PCALIGN" || padding <= ins.Args[1].Imm {
		return offset + padding
	}
	return offset
}
