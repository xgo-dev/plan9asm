package plan9asm

import "fmt"

// Go selects ADD or SUB together with the immediate in x86.span6. The
// directions agree on the next SP, but the two encodings differ in FLAGS.
type x86StackAdjustment struct {
	amount    int64 // Bytes reserved on the descending stack.
	immediate int64
	add       bool
}

func parseX86StackAdjustment(ins Instr) (x86StackAdjustment, error) {
	args := ins.Args
	if len(args) < 1 || len(args) > 2 ||
		args[0].Kind != OpImm || args[0].ImmRaw != "" || args[0].ImmIsFloat ||
		args[0].Imm < -2147483647 || args[0].Imm > 2147483647 ||
		len(args) == 2 && (args[1].Kind != OpReg || args[1].Reg != SP) {
		return x86StackAdjustment{}, fmt.Errorf("ADJSP expects an immediate and optional SP: %q", ins.Raw)
	}
	amount := args[0].Imm
	if amount == 128 || amount < 0 && amount != -128 {
		return x86StackAdjustment{amount: amount, immediate: -amount, add: true}, nil
	}
	return x86StackAdjustment{amount: amount, immediate: amount}, nil
}

// On a bounded active stack neither a downward subtraction nor an upward
// addition wraps. The sign-reversed immediate at ±128 produces carry/borrow.
// SP stays nonzero, and a multiple of 16 cannot carry or borrow into bit 4.
// PF, SF and OF can depend on the original address.
func (form x86StackAdjustment) relativeFlags() uint8 {
	flags := uint8(x86ByteFlagCF | x86ByteFlagZF)
	if form.immediate%16 == 0 {
		flags |= x86ByteFlagAF
	}
	return flags
}

// x86RelativeStackDepths records the linear SP depth that cmd/asm uses when
// rebasing FP references. The caller checks the same depth on every CFG edge.
// The bounded region has no memory use or escape through the adjusted SP.
func x86RelativeStackDepths(fn Func, instructions []Instr, arch string) ([]int64, error) {
	fail := func(ins Instr) ([]int64, error) {
		return nil, fmt.Errorf("%w: ADJSP needs a bounded relative stack without physical access: %q", ErrProbeNeedsContext, ins.Raw)
	}
	if fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || fn.x86RawReplay != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || len(fn.X86RawText) != 0 ||
		fn.FrameSize < 0 || fn.FrameSize > 4096 {
		return fail(Instr{Raw: fn.Sym})
	}
	if err := x86ResultLocalSourceReplay(fn, arch, "relative ADJSP"); err != nil {
		return nil, err
	}
	depths := make([]int64, len(instructions)+1)
	limit := int64(x86ResultValueStackLimit(arch))
	for pc, ins := range instructions {
		depths[pc+1] = depths[pc]
		if !x86ResultNamedPredicateInstruction(ins) {
			return fail(ins)
		}
		if ins.Op == "ADJSP" {
			form, err := parseX86StackAdjustment(ins)
			if err != nil {
				return nil, err
			}
			depths[pc+1] += form.amount
			if form.amount == 0 || depths[pc+1] < 0 || depths[pc+1] > limit {
				return fail(ins)
			}
			continue
		}
		if _, stack, _ := x86StackWidthProperties(ins, arch); stack {
			return fail(ins) // The private PUSH/POP data path has a separate backing object.
		}
		switch ins.Op {
		case OpCALL, "DUFFCOPY", "DUFFZERO", "ENTER", "ENTERW", "ENTERL", "ENTERQ", "LEAVE", "LEAVEW", "LEAVEL", "LEAVEQ":
			return fail(ins)
		case OpRET:
			if depths[pc] != 0 {
				return fail(ins)
			}
		}
		for _, operand := range ins.Args {
			if operand.Reg == SP || operand.Mem.Base == SP || operand.Mem.Index == SP {
				return fail(ins)
			}
		}
	}
	return depths, nil
}

func (c *amd64Ctx) lowerRelativeStackAdjustment(form x86StackAdjustment) {
	// Only the address-independent flags may be read by the checked CFG.
	c.clearX86StatusFlags(x86StatusAll)
	if form.immediate < 0 {
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsCFSlot)
	}
}
