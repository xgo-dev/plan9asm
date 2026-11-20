package plan9asm

import (
	"fmt"
	"strings"
)

func arm64NamedPCOperand(ins Instr) (int, bool) {
	op := Op(strings.ToUpper(string(ins.Op)))
	if dot := strings.IndexByte(string(op), '.'); dot >= 0 {
		op = op[:dot]
	}
	index, count := 0, 1
	switch op {
	case "B", "JMP", "BL", "CALL", "BEQ", "BNE", "BLO", "BHI", "BLT", "BGE", "BLE", "BGT", "BHS", "BLS", "BMI", "BPL", "BVS", "BVC", "BCC", "BCS":
	case "CBZ", "CBNZ", "CBZW", "CBNZW":
		index, count = 1, 2
	case "TBZ", "TBNZ":
		index, count = 2, 3
	case "ADR", "ADRP":
		count = 2
	default:
		return 0, false
	}
	return index, len(ins.Args) == count && ins.Args[index].Kind == OpMem && ins.Args[index].Mem.Base == PC
}

// normalizeARM64NamedPCRelative resolves Go assembler n(PC) operands before
// block splitting or raw-pool removal changes source instruction ordinals.
// cmd/asm counts each Prog, including zero-width metadata, but not labels.
func normalizeARM64NamedPCRelative(fn Func) (Func, error) {
	linear := make([]int, 0, len(fn.Instrs))
	known := make(map[string]bool)
	for i, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			if len(ins.Args) == 1 && ins.Args[0].Kind == OpLabel {
				known[ins.Args[0].Sym] = true
			}
		} else {
			linear = append(linear, i)
		}
	}
	labels := make(map[int]string)
	replacements := make(map[int]Instr)
	for ordinal, index := range linear {
		ins := fn.Instrs[index]
		argument, relative := arm64NamedPCOperand(ins)
		if !relative {
			continue
		}
		operand := ins.Args[argument]
		if strings.Contains(string(ins.Op), ".") || operand.Mem.Index != "" {
			return Func{}, fmt.Errorf("ARM64 invalid named PC-relative operand: %q", ins.Raw)
		}
		off := operand.Mem.Off
		if off < -int64(ordinal) || off >= int64(len(linear)-ordinal) {
			return Func{}, fmt.Errorf("ARM64 named PC-relative target %d(PC) is outside TEXT: %q", off, ins.Raw)
		}
		target := linear[ordinal+int(off)]
		label, exists := labels[target]
		if !exists {
			label = fmt.Sprintf("__arm64_pc_target_%d", target)
			for known[label] {
				label += "_"
			}
			known[label] = true
			labels[target] = label
		}
		ins.Args = append([]Operand(nil), ins.Args...)
		ins.Args[argument] = Operand{Kind: OpIdent, Ident: label}
		replacements[index] = ins
	}
	if len(replacements) == 0 {
		return fn, nil
	}
	result := fn
	result.Instrs = make([]Instr, 0, len(fn.Instrs)+len(labels))
	for i, ins := range fn.Instrs {
		if label, exists := labels[i]; exists {
			result.Instrs = append(result.Instrs, Instr{Op: OpLABEL, Args: []Operand{{Kind: OpLabel, Sym: label}}, Raw: label + ":"})
		}
		if replacement, exists := replacements[i]; exists {
			ins = replacement
		}
		result.Instrs = append(result.Instrs, ins)
	}
	return result, nil
}
