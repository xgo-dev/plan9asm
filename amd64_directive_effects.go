package plan9asm

import (
	"fmt"
	"math"
	"strings"
)

type x86DirectiveEffect uint8

const (
	x86DirectiveLayout x86DirectiveEffect = iota + 1
	x86DirectiveMetadata
	x86DirectiveDiscarded
)

type x86DirectiveForm struct {
	effect    x86DirectiveEffect
	alignment int64
}

// These source directives preserve numerical availability. Layout and Go
// metadata still require their independent physical contracts.
func x86DirectiveProperties(ins Instr) (x86DirectiveForm, bool, error) {
	var form x86DirectiveForm
	base, suffix, dotted := strings.Cut(string(ins.Op), ".")
	count := 2
	switch base {
	case "PCALIGN":
		form.effect, count = x86DirectiveLayout, 1
	case "PCALIGNMAX":
		form.effect = x86DirectiveLayout
	case "PCDATA", "FUNCDATA":
		form.effect = x86DirectiveMetadata
	case "END":
		form.effect = x86DirectiveDiscarded
	default:
		return form, false, nil
	}
	fail := func() (x86DirectiveForm, bool, error) {
		return form, true, fmt.Errorf("invalid x86 %s directive operands: %q", base, ins.Raw)
	}
	if form.effect == x86DirectiveDiscarded {
		// cmd/asm parses the ordinary x86 suffix and operand grammar before
		// obj.Flushplist discards AEND. The accepted operands have no effects.
		_, valid := parseAMD64BinaryFloatingSuffix(suffix)
		if !valid || dotted && suffix == "" || len(ins.Args) > 5 {
			return fail()
		}
		for _, arg := range ins.Args {
			if !x86EndOperand(arg) {
				return fail()
			}
		}
		return form, true, nil
	}
	if string(ins.Op) != base || len(ins.Args) != count {
		return fail()
	}
	constant := func(arg Operand) bool {
		return arg.Kind == OpImm && arg.ImmRaw == "" && !arg.ImmIsFloat
	}
	if !constant(ins.Args[0]) {
		return fail()
	}
	if form.effect == x86DirectiveLayout {
		// obj.AlignmentPaddingLength: both spellings retain the function's
		// required alignment, even when PCALIGNMAX emits no padding here.
		form.alignment = ins.Args[0].Imm
		if form.alignment < 8 || form.alignment > 2048 || form.alignment&(form.alignment-1) != 0 {
			return fail()
		}
		if count == 2 && (!constant(ins.Args[1]) || ins.Args[1].Imm < 0 || ins.Args[1].Imm >= form.alignment) {
			return fail()
		}
		return form, true, nil
	}
	if base == "PCDATA" {
		// The backend's ypcdata row is Yi32,Yi32 and linkpcln retains an
		// int32 value. Frontend constant syntax alone is insufficient.
		if ins.Args[0].Imm < 0 || ins.Args[0].Imm > math.MaxInt32 || !constant(ins.Args[1]) ||
			ins.Args[1].Imm < math.MinInt32 || ins.Args[1].Imm > math.MaxInt32 {
			return fail()
		}
		return form, true, nil
	}
	// cmd/asm.validSymbol alone is not the full contract: x86's yfuncdata
	// row requires memory and linkpcln requires its offset to be zero. An
	// accepted frontend offset otherwise panics during object production.
	arg := ins.Args[1]
	symbol := strings.TrimSpace(arg.Sym)
	if ins.Args[0].Imm < 0 || ins.Args[0].Imm > math.MaxInt32 ||
		arg.Kind != OpSym || !strings.HasSuffix(symbol, "(SB)") {
		return fail()
	}
	name, offset := splitSymPlusOff(strings.TrimSpace(strings.TrimSuffix(symbol, "(SB)")))
	if offset != 0 || !validPPIdentifier(strings.TrimSuffix(name, "<>")) {
		return fail()
	}
	return form, true, nil
}

func x86EndOperand(arg Operand) bool {
	switch arg.Kind {
	case OpImm:
		return arg.ImmRaw == ""
	case OpIdent:
		return x86SymbolGoRegisterName(arg.Ident)
	case OpReg:
		return x86SymbolGoRegisterName(string(arg.Reg))
	case OpSym:
		if _, _, ok := parseSBRef(arg.Sym); ok {
			return true
		}
		_, absolute := parseImmExpr(arg.Sym)
		return absolute
	case OpFP, OpFPAddr, OpMem, OpRegList:
		return true // Already parsed address and register-list roles.
	}
	return false
}

func normalizeX86DirectiveFile(file *File, goarch string) (*File, error) {
	result := file
	for index, fn := range file.Funcs {
		hasEnd := false
		for _, ins := range fn.Instrs {
			form, _, err := x86DirectiveProperties(ins)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", fn.Sym, err)
			}
			if form.effect == x86DirectiveDiscarded {
				if goarch == "386" && len(ins.Args) > 3 {
					return nil, fmt.Errorf("%s: 386 END accepts at most three source operands: %q", fn.Sym, ins.Raw)
				}
				hasEnd = true
			}
		}
		if !hasEnd {
			continue
		}
		instructions, err := discardX86End(fn)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", fn.Sym, err)
		}
		if result == file {
			copy := *file
			copy.Funcs = append([]Func(nil), file.Funcs...)
			result = &copy
		}
		result.Funcs[index].Instrs = instructions
	}
	return result, nil
}

func x86EndOpcode(op Op) bool {
	return op == "END" || strings.HasPrefix(string(op), "END.")
}

// AEND has a source PC, even though Go's object writer removes it. Preserve
// existing PC-relative destinations as labels before deleting the source slots.
func discardX86End(fn Func) ([]Instr, error) {
	names := newAssemblyBlockNames(fn)
	linear := make([]int, 0, len(fn.Instrs))
	labelPC := make(map[string]int)
	for index, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			if len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
				labelPC[ins.Args[0].Sym] = len(linear)
			}
			continue
		}
		linear = append(linear, index)
		// A generated label must not satisfy an unresolved original reference.
		for _, operand := range ins.Args {
			switch operand.Kind {
			case OpIdent:
				names.used[operand.Ident] = true
			case OpSym:
				name := strings.TrimSuffix(strings.TrimSpace(operand.Sym), "(SB)")
				names.used[strings.TrimSuffix(name, "<>")] = true
			}
		}
	}

	labels := make(map[int]string)
	rebound := make(map[int]Instr)
	for ordinal, index := range linear {
		ins := fn.Instrs[index]
		if !isX86DirectControlTransfer(ins.Op) && ins.Op != "XBEGIN" {
			continue
		}
		args := x86DirectTailBranchArgs(ins)
		if len(args) != 1 {
			continue
		}
		if offset, relative := x86PCBranchOffset(args[0]); relative {
			target, inside := x86PCBranchIndex(ordinal, len(linear), offset)
			if !inside {
				return nil, fmt.Errorf("x86 PC-relative branch leaves the source body: %q", ins.Raw)
			}
			destination := linear[target]
			if x86EndOpcode(fn.Instrs[destination].Op) {
				return nil, fmt.Errorf("%w: branch targets discarded END: %q", ErrProbeNeedsContext, ins.Raw)
			}
			label := labels[destination]
			if label == "" {
				label = names.fresh("__x86_source_pc")
				labels[destination] = label
			}
			ins.Args = append([]Operand(nil), ins.Args...)
			ins.Args[len(ins.Args)-1] = Operand{Kind: OpIdent, Ident: label}
			rebound[index] = ins
			continue
		}
		name := args[0].Ident
		if args[0].Kind == OpReg {
			name = string(args[0].Reg)
		}
		if target, exists := labelPC[name]; exists && target < len(linear) &&
			x86EndOpcode(fn.Instrs[linear[target]].Op) {
			return nil, fmt.Errorf("%w: branch targets discarded END: %q", ErrProbeNeedsContext, ins.Raw)
		}
	}

	instructions := make([]Instr, 0, len(fn.Instrs))
	for index, ins := range fn.Instrs {
		if x86EndOpcode(ins.Op) {
			continue
		}
		if label := labels[index]; label != "" {
			instructions = append(instructions, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}})
		}
		if branch, ok := rebound[index]; ok {
			ins = branch
		}
		instructions = append(instructions, ins)
	}
	return instructions, nil
}
