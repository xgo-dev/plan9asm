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
	adjustments map[int]x86RelativeStackStep // Original source ordinals.
	accesses    map[int]Instr                // Same source instructions with projected operands.
	emission    map[int]Instr                // Linear emission positions, including TEXT.
	transports  map[int]int64                // Physical PUSH/POP slots in the same local object.
	extent      int
	scratch     int // Maximum dynamic depth when the value stack owns these bytes.
}

type x86RelativeStackStep struct {
	x86StackAdjustment
	before int64
}

func (plan *x86RelativeStackPlan) projects(ordinal, index int, arg Operand) bool {
	if plan == nil {
		return false
	}
	projected, found := plan.accesses[ordinal]
	return found && projected.Args[index].Mem != arg.Mem
}

func x86PlanRelativeStack(fn Func, arch string) (*x86RelativeStackPlan, error) {
	for _, ins := range fn.Instrs {
		if ins.Op == "ADJSP" {
			return x86RelativeStack(fn, arch)
		}
	}
	return nil, nil
}

// x86RelativeStack records the linear SP depth that cmd/asm uses when
// rebasing FP references. The caller checks the same depth on every CFG edge.
// Bare SP operands reach the same private byte object as named AUTO cells
// when their full access lies within live local storage.
func x86RelativeStack(fn Func, arch string) (*x86RelativeStackPlan, error) {
	fail := func(ins Instr) (*x86RelativeStackPlan, error) {
		return nil, fmt.Errorf("%w: ADJSP needs a bounded private stack effect: %q", ErrProbeNeedsContext, ins.Raw)
	}
	if fn.x86DirectTailRoot != nil || fn.x86ContinuationFlow != nil || fn.x86RawReplay != nil ||
		fn.x86SourceStack != nil || fn.x86FixedLocal != nil || len(fn.X86RawText) != 0 ||
		fn.FrameSize < 0 || fn.FrameSize > 4096 || len(fn.Instrs) == 0 || len(fn.Instrs) > 8192 || fn.Instrs[0].Op != OpTEXT {
		return fail(Instr{Raw: fn.Sym})
	}
	if err := x86ResultLocalSourceReplay(fn, arch, "relative ADJSP"); err != nil {
		return nil, err
	}
	plan := &x86RelativeStackPlan{
		depths:      make([]int64, 1, len(fn.Instrs)),
		adjustments: make(map[int]x86RelativeStackStep),
	}
	limit := int64(x86ResultValueStackLimit(arch))
	var depth, maxDepth int64
	for ordinal, ins := range fn.Instrs {
		if ins.Op == OpTEXT || ins.Op == OpLABEL {
			continue
		}
		if !x86ResultNamedPredicateInstruction(ins) {
			return fail(ins)
		}
		if ins.Op == "ADJSP" {
			form, err := parseX86StackAdjustment(ins, arch)
			if err != nil {
				return nil, err
			}
			plan.adjustments[ordinal] = x86RelativeStackStep{form, depth}
			depth += form.amount
			if form.amount == 0 || depth < 0 || depth > limit {
				return fail(ins)
			}
			if depth > maxDepth {
				maxDepth = depth
			}
			plan.depths = append(plan.depths, depth)
			continue
		}
		codePC := len(plan.depths) // The emitter includes the original TEXT.
		addressDepth := depth
		spec, stack, err := x86StackWidthProperties(ins, arch)
		if stack {
			if err != nil {
				return nil, err
			}
			if len(ins.Args) != 0 && x86SegmentRegisterOperand(ins.Args[0]) {
				return fail(ins)
			}
			width := int64(spec.bits / 8)
			slot := depth
			switch spec.mode {
			case amd64StackPushValue, amd64StackPushFlags:
				depth += width
				slot = depth
			case amd64StackPopValue, amd64StackPopFlags:
				depth -= width
				// POP computes a memory destination after incrementing SP.
				addressDepth = depth
			}
			if depth < 0 || depth > limit {
				return fail(ins)
			}
			if depth > maxDepth {
				maxDepth = depth
			}
			if plan.transports == nil {
				plan.transports = make(map[int]int64)
			}
			plan.transports[codePC] = -fn.FrameSize - slot
		}
		plan.depths = append(plan.depths, depth)
		switch ins.Op {
		case OpCALL, "DUFFCOPY", "DUFFZERO", "ENTER", "ENTERW", "ENTERL", "ENTERQ", "LEAVE", "LEAVEW", "LEAVEL", "LEAVEQ":
			return fail(ins)
		case OpRET:
			if depth != 0 {
				return fail(ins)
			}
		}
		if x86InertNOP(ins, arch) {
			continue // A checked NOP operand neither reads nor exports SP.
		}
		var arguments []string
		var projected Instr
		for index, operand := range ins.Args {
			if root, valid := x86CallerGP(operand.Reg); valid && root == SP || operand.Mem.Index == SP {
				return fail(ins)
			}
			if stack && spec.mode == amd64StackPopValue && operand.Kind == OpFP {
				return fail(ins) // The original named FP operand would move by the POP width.
			}
			if operand.Kind != OpMem || operand.Mem.Base != SP {
				continue
			}
			if arguments == nil {
				_, original := splitOpcode(ins.Raw)
				arguments = splitTopLevelCSV(original)
			}
			if len(arguments) != len(ins.Args) {
				return fail(ins)
			}
			off := operand.Mem.Off
			live := fn.FrameSize + addressDepth
			width := x86RelativeStackAccessWidth(ins, index, arch)
			if stack {
				width = int64(spec.bits / 8)
			}
			if named := x86ResultAUTOLiteral.FindStringSubmatch(arguments[index]); named != nil {
				if offset, ok := parseNamedStackConstantOffset(named[1]); ok {
					if !stack || spec.mode != amd64StackPopValue {
						continue // The existing named-AUTO validator checks its full width.
					}
					// cmd/asm encodes the named displacement with the depth before
					// POP, so the actual destination advances by another width.
					if offset != off || off < -fn.FrameSize || off > -2*width {
						return fail(ins)
					}
					off += live + width
				}
			}
			if operand.Mem != (MemRef{Base: SP, Off: operand.Mem.Off}) || width == 0 || off < 0 || off > live-width {
				return fail(ins)
			}
			if projected.Args == nil {
				projected = ins
				projected.Args = append([]Operand(nil), ins.Args...)
			}
			projected.Args[index].Mem.Off = off - live
		}
		if projected.Args != nil {
			if plan.accesses == nil {
				plan.accesses, plan.emission = make(map[int]Instr), make(map[int]Instr)
			}
			plan.accesses[ordinal], plan.emission[codePC] = projected, projected
		}
	}
	if len(plan.transports) != 0 {
		plan.scratch = int(maxDepth)
	}
	if len(plan.accesses) != 0 || plan.scratch != 0 {
		plan.extent = int(fn.FrameSize + maxDepth)
	}
	return plan, nil
}

// Only ordinary accesses with a bounded byte span use the logical object.
// Address formation, bit strings and memory effects that require the original
// native instruction keep their separate contracts.
func x86RelativeStackAccessWidth(ins Instr, index int, arch string) int64 {
	if form, known, err := x86LegacyPackedMoveProperties(ins.Op, ins, arch); known {
		if err == nil && !form.aligned && form.memory == index {
			return 16
		}
		return 0
	}
	if form, known, err := amd64PackedVectorMoveProperties(ins, arch); known {
		if err == nil && !form.spec.aligned && !form.undefinedOpcode() && form.memory == index {
			return int64(form.byteWidth)
		}
		return 0
	}
	if form, known, err := x86ScalarCompareProperties(ins.Op, ins, arch); known && err == nil && form.memory == index {
		return int64(form.bits / 8)
	}
	if form, known, err := x86LockScalarRMWProperties(ins.Op, ins, arch); known && err == nil && !form.spec.bitString {
		return int64(form.spec.bits / 8)
	}
	if x86RawReturnScalarMoveBytes(ins.Op) != 0 {
		observation := ins
		observation.Args = append([]Operand(nil), ins.Args...)
		observation.Args[index] = Operand{Kind: OpFP}
		if width, _, known := X86FPAccessBytes(observation, index, arch); known {
			return width
		}
	}
	return 0
}

func (c *amd64Ctx) lowerRelativeStackAdjustment(form x86StackAdjustment) {
	// Only the address-independent flags may be read by the checked CFG.
	c.clearX86StatusFlags(x86StatusAll)
	if form.immediate < 0 {
		fmt.Fprintf(c.b, "  store i1 true, ptr %s\n", c.flagsCFSlot)
	}
}
