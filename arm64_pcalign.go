package plan9asm

import "fmt"

// Go's obj.AlignmentPaddingLength defines both spellings. Alignment changes
// native layout, but emits only NOPs, with no register, memory or flag effects.
// Recognizing this grammar does not prove native PC offsets or code identity.
func arm64PCAlignment(ins Instr) (alignment int64, handled bool, err error) {
	base := arm64ControlOp(ins)
	count := 1
	switch base {
	case "PCALIGN":
	case "PCALIGNMAX":
		count = 2
	default:
		return 0, false, nil
	}
	invalid := func() (int64, bool, error) {
		return 0, true, fmt.Errorf("invalid ARM64 %s directive operands: %q", base, ins.Raw)
	}
	if ins.Op != base || len(ins.Args) != count {
		return invalid()
	}
	for _, arg := range ins.Args {
		if arg.Kind != OpImm || arg.ImmRaw != "" || arg.ImmIsFloat {
			return invalid()
		}
	}
	alignment = ins.Args[0].Imm
	if alignment < 8 || alignment > 2048 || alignment&(alignment-1) != 0 {
		return invalid()
	}
	if count == 2 && (ins.Args[1].Imm < 0 || ins.Args[1].Imm >= alignment) {
		return invalid()
	}
	return alignment, true, nil
}

func arm64FunctionPCAlignment(fn Func) (int64, error) {
	var alignment int64
	for _, ins := range fn.Instrs {
		value, _, err := arm64PCAlignment(ins)
		if err != nil {
			return 0, err
		}
		if value > alignment {
			alignment = value
		}
	}
	return alignment, nil
}
