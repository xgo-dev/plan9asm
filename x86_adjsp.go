package plan9asm

import (
	"fmt"
	"strings"
)

// Go selects ADD or SUB together with the immediate in x86.span6. The
// directions agree on the next SP, but the two encodings differ in FLAGS.
type x86StackAdjustment struct {
	amount    int64 // Bytes reserved on the descending stack.
	immediate int64
	add       bool
	prefix    byte
}

func parseX86StackAdjustment(ins Instr, arch string) (x86StackAdjustment, error) {
	args := ins.Args
	if len(args) < 1 || len(args) > 2 ||
		args[0].Kind != OpImm || args[0].ImmRaw != "" || args[0].ImmIsFloat ||
		args[0].Imm < -2147483647 || args[0].Imm > 2147483647 {
		return x86StackAdjustment{}, fmt.Errorf("ADJSP expects an immediate and optional rewritten destination: %q", ins.Raw)
	}
	var prefix byte
	if len(args) == 2 {
		var ok bool
		prefix, ok = x86StackAdjustmentDestination(ins, arch)
		if !ok {
			return x86StackAdjustment{}, fmt.Errorf("ADJSP destination must encode as SP with zero displacement: %q", ins.Raw)
		}
	}
	amount := args[0].Imm
	if amount == 128 || amount < 0 && amount != -128 {
		return x86StackAdjustment{amount: amount, immediate: -amount, add: true, prefix: prefix}, nil
	}
	return x86StackAdjustment{amount: amount, immediate: amount, prefix: prefix}, nil
}

// span6 replaces the destination's type and register. asmandsz still checks
// its displacement, and prefixof still sees a segment in its original Index.
// The rewritten destination grants no register, memory or relocation role.
func x86StackAdjustmentDestination(ins Instr, arch string) (byte, bool) {
	operand := ins.Args[1]
	_, arguments := splitOpcode(ins.Raw)
	literals := splitTopLevelCSV(arguments)
	if len(literals) != 2 {
		return 0, operand.Kind == OpReg && operand.Reg == SP
	}
	literal := strings.TrimSpace(strings.TrimPrefix(literals[1], "*"))
	normalized := normalizeGoGRegister(ArchAMD64, literal)
	if arch == "386" && normalized != literal {
		return 0, false
	}
	if operand.Kind == OpReg {
		return 0, x86SymbolGoRegisterName(normalized)
	}
	if memory, matched, err := parseX86SourceRegisterMemory(normalized); matched {
		if err != nil {
			return 0, false
		}
		// The general parser may retain a segment expression as a symbol.
		// Reuse the original Reg/Index positions for the rewrite.
		operand = Operand{Kind: OpMem, Mem: memory}
	}
	memory := operand.Mem
	switch operand.Kind {
	case OpSym:
		memory = MemRef{Sym: operand.Sym}
	case OpMem:
		if literal == "" || strings.Contains(literal, ":") {
			return 0, false
		}
		if match := x86ResultAUTOLiteral.FindStringSubmatch(literal); memory.Base == SP && match != nil {
			if _, named := parseNamedStackConstantOffset(match[1]); named {
				return 0, false // Its final displacement depends on the Go frame.
			}
		}
	default:
		return 0, false
	}
	if memory.Sym != "" {
		name, offset, ok := parseSBRef(memory.Sym)
		if !ok || offset != 0 || strings.HasPrefix(name, "$") || !strings.HasSuffix(memory.Sym, "(SB)") {
			return 0, false
		}
	}
	if memory.Off != 0 || memory.OffRaw != "" || memory.IndexExt != "" {
		return 0, false
	}
	switch memory.Index {
	case CS:
		return 0x2e, true
	case DS:
		return 0x3e, true
	case ES:
		return 0x26, true
	case FS:
		return 0x64, true
	case GS:
		return 0x65, true
	}
	return 0, true
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

type x86RelativeStackPlan struct {
	depths      []int64
	adjustments map[int]x86StackAdjustment // Original source ordinals.
}

// x86RelativeStack records the linear SP depth that cmd/asm uses when
// rebasing FP references. The caller checks the same depth on every CFG edge.
// Named AUTO cells retain their existing source-checked logical storage. The
// bounded region cannot access memory through the adjusted physical SP.
func x86RelativeStack(fn Func, instructions []Instr, ordinals []int, arch string, autoExtent int) (*x86RelativeStackPlan, error) {
	fail := func(ins Instr) (*x86RelativeStackPlan, error) {
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
	plan := &x86RelativeStackPlan{
		depths:      make([]int64, len(instructions)+1),
		adjustments: make(map[int]x86StackAdjustment),
	}
	limit := int64(x86ResultValueStackLimit(arch))
	for pc, ins := range instructions {
		plan.depths[pc+1] = plan.depths[pc]
		if !x86ResultNamedPredicateInstruction(ins) {
			return fail(ins)
		}
		if ins.Op == "ADJSP" {
			form, err := parseX86StackAdjustment(ins, arch)
			if err != nil {
				return nil, err
			}
			plan.depths[pc+1] += form.amount
			if form.amount == 0 || plan.depths[pc+1] < 0 || plan.depths[pc+1] > limit {
				return fail(ins)
			}
			plan.adjustments[ordinals[pc]] = form
			continue
		}
		if _, stack, _ := x86StackWidthProperties(ins, arch); stack {
			return fail(ins) // The private PUSH/POP data path has a separate backing object.
		}
		switch ins.Op {
		case OpCALL, "DUFFCOPY", "DUFFZERO", "ENTER", "ENTERW", "ENTERL", "ENTERQ", "LEAVE", "LEAVEW", "LEAVEL", "LEAVEQ":
			return fail(ins)
		case OpRET:
			if plan.depths[pc] != 0 {
				return fail(ins)
			}
		}
		for _, operand := range ins.Args {
			if operand.Reg == SP || operand.Mem.Index == SP {
				return fail(ins)
			}
			if operand.Mem.Base == SP {
				if _, logical := x86ResultAUTOOffset(operand, 1, autoExtent); !logical {
					return fail(ins)
				}
			}
		}
	}
	return plan, nil
}

func (c *amd64Ctx) lowerRelativeStackAdjustment(form x86StackAdjustment) {
	// Only the address-independent flags may be read by the checked CFG.
	c.clearX86StatusFlags(x86StatusAll)
	if form.immediate < 0 {
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsCFSlot)
	}
}
