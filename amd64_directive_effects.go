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
)

type x86DirectiveForm struct {
	effect    x86DirectiveEffect
	alignment int64
}

// These are the existing metadata directives and the complete PCALIGN family,
// not a blanket pseudo-op exemption. They preserve numerical availability but
// still have native layout/GC effects. This grammar grants no caller, raw-PC,
// stack, metadata ownership or physical function-alignment permission.
func x86DirectiveProperties(ins Instr) (x86DirectiveForm, bool, error) {
	var form x86DirectiveForm
	base, _, _ := strings.Cut(string(ins.Op), ".")
	count := 2
	switch base {
	case "PCALIGN":
		form.effect, count = x86DirectiveLayout, 1
	case "PCALIGNMAX":
		form.effect = x86DirectiveLayout
	case "PCDATA", "FUNCDATA":
		form.effect = x86DirectiveMetadata
	default:
		return form, false, nil
	}
	fail := func() (x86DirectiveForm, bool, error) {
		return form, true, fmt.Errorf("invalid x86 %s directive operands: %q", base, ins.Raw)
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

func validateX86DirectiveFile(file *File) error {
	for _, fn := range file.Funcs {
		for _, ins := range fn.Instrs {
			if _, known, err := x86DirectiveProperties(ins); known && err != nil {
				return fmt.Errorf("%s: %w", fn.Sym, err)
			}
		}
	}
	return nil
}
