package plan9asm

import (
	"fmt"
	"strings"
)

func arm64NamedPCOperand(ins Instr) (index int, address bool, relative bool) {
	op := Op(strings.ToUpper(string(ins.Op)))
	if dot := strings.IndexByte(string(op), '.'); dot >= 0 {
		op = op[:dot]
	}
	count := 1
	switch op {
	case "B", "JMP", "BL", "CALL":
	case "ADR", "ADRP":
		count, address = 2, true
	default:
		count, _ = arm64ConditionalBranchShape(op)
		if count == 0 {
			return 0, false, false
		}
		index = count - 1
	}
	return index, address, len(ins.Args) == count && ins.Args[index].Kind == OpMem && ins.Args[index].Mem.Base == PC
}

// Normalize named PC operands before block splitting or raw-pool removal.
// Numeric branch destinations count Go Progs, including zero-width metadata.
// Numeric ADR/ADRP sources never acquire a From.Target in cmd/asm, so Go's
// brdist emits a zero displacement. Explicit label operands are already bound.
func normalizeARM64NamedPCRelative(fn Func) (Func, error) {
	firstOrdinal := 0
	found := false
	for _, ins := range fn.Instrs {
		if ins.Op == OpLABEL {
			continue
		}
		if _, _, relative := arm64NamedPCOperand(ins); relative {
			found = true
			break
		}
		firstOrdinal++
	}
	if !found {
		return fn, nil
	}

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
	for ordinal := firstOrdinal; ordinal < len(linear); ordinal++ {
		index := linear[ordinal]
		ins := fn.Instrs[index]
		argument, address, relative := arm64NamedPCOperand(ins)
		if !relative {
			continue
		}
		memory := ins.Args[argument].Mem
		if strings.Contains(string(ins.Op), ".") || memory != (MemRef{Base: PC, Off: memory.Off}) {
			return Func{}, fmt.Errorf("ARM64 invalid named PC-relative operand: %q", ins.Raw)
		}
		target := index
		if !address {
			off := memory.Off
			if off < -int64(ordinal) || off >= int64(len(linear)-ordinal) {
				return Func{}, fmt.Errorf("ARM64 named PC-relative target %d(PC) is outside TEXT: %q", off, ins.Raw)
			}
			target = linear[ordinal+int(off)]
		}
		label := labels[target]
		if target > 0 {
			previous := fn.Instrs[target-1]
			if previous.Op == OpLABEL && len(previous.Args) == 1 && previous.Args[0].Kind == OpLabel {
				label = previous.Args[0].Sym
			}
		}
		if label == "" {
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
