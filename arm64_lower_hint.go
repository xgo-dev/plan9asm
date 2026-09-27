package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64Hint(op Op, ins Instr) (ok bool, terminated bool, err error) {
	pointerAuthHints := map[Op]uint8{
		"PACIASP":   25,
		"PACIBSP":   27,
		"AUTIASP":   29,
		"AUTIBSP":   31,
		"AUTIA1716": 12,
		"AUTIB1716": 14,
	}
	_, pointerAuthHint := pointerAuthHints[op]
	if op != "HINT" && op != "YIELD" && op != "WFE" && op != "WFI" && op != "SEV" && op != "SEVL" && op != "NOP" && op != "NOOP" && op != "BTI" && !pointerAuthHint {
		return false, false, nil
	}
	if pointerAuthHint {
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 %s takes no operands or suffix: %q", op, ins.Raw)
		}
		c.emitARM64Hint(pointerAuthHints[op])
		return true, false, nil
	}
	if op == "BTI" {
		if strings.ToUpper(string(ins.Op)) != "BTI" || len(ins.Args) != 1 || ins.Args[0].Kind != OpIdent {
			return true, false, fmt.Errorf("arm64 BTI expects C, J, or JC and no suffix: %q", ins.Raw)
		}
		immediate, valid := map[string]uint8{"C": 34, "J": 36, "JC": 38}[strings.ToUpper(ins.Args[0].Ident)]
		if !valid {
			return true, false, fmt.Errorf("arm64 BTI target type must be C, J, or JC: %q", ins.Raw)
		}
		c.emitARM64Hint(immediate)
		return true, false, nil
	}
	if op == "NOOP" {
		if strings.ToUpper(string(ins.Op)) != "NOOP" || len(ins.Args) != 0 {
			return true, false, fmt.Errorf("arm64 NOOP takes no operands or suffix: %q", ins.Raw)
		}
		c.emitARM64Hint(0)
		return true, false, nil
	}
	if op == "NOP" {
		if strings.ToUpper(string(ins.Op)) != "NOP" || len(ins.Args) > 1 {
			return true, false, fmt.Errorf("arm64 NOP accepts no operand or one C_LCON/R/ZR/V operand, with no suffix: %q", ins.Raw)
		}
		if len(ins.Args) == 1 {
			operand := ins.Args[0]
			valid := operand.Kind == OpImm && operand.ImmRaw == "" && arm64GoLCON(operand.Imm)
			if operand.Kind == OpReg {
				_, vector := arm64ParseVReg(operand.Reg)
				valid = isARM64GeneralOrZeroReg(operand.Reg) || vector
			}
			if !valid {
				return true, false, fmt.Errorf("arm64 NOP operand is outside Go's C_LCON/C_ZREG/C_VREG rows: %q", ins.Raw)
			}
		}
		// Go's NOP pseudo-instruction intentionally emits no machine code.
		return true, false, nil
	}
	rawOp := strings.ToUpper(string(ins.Op))
	if op == "HINT" {
		if rawOp != "HINT" || len(ins.Args) != 1 || ins.Args[0].Kind != OpImm || ins.Args[0].ImmRaw != "" {
			return true, false, fmt.Errorf("arm64 HINT takes one resolved integer constant and no suffix: %q", ins.Raw)
		}
		c.emitARM64Hint(uint8(ins.Args[0].Imm & 0x7f))
		return true, false, nil
	}
	if rawOp != string(op) || len(ins.Args) != 0 {
		return true, false, fmt.Errorf("arm64 %s takes no operands or suffix: %q", op, ins.Raw)
	}
	mnemonics := map[Op]string{
		"YIELD": "yield",
		"WFE":   "wfe",
		"WFI":   "wfi",
		"SEV":   "sev",
		"SEVL":  "sevl",
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, \"\"()\n", mnemonics[op])
	return true, false, nil
}

func decodeARM64RawHint(word uint32) (uint8, bool) {
	const immediateMask = uint32(0x7f << 5)
	if word&^immediateMask != 0xd503201f {
		return 0, false
	}
	return uint8(word >> 5 & 0x7f), true
}

func (c *arm64Ctx) emitARM64Hint(immediate uint8) {
	fmt.Fprintf(c.b, "  call void asm sideeffect \"hint #%d\", \"\"()\n", immediate&0x7f)
}

// arm64GoLCON reports whether conclass(v, 64) can satisfy Go's C_LCON
// operand row. Only C_VCON falls outside that row; all earlier constant
// classes are compatible with it.
func arm64GoLCON(value int64) bool {
	if value == 0 || arm64GoAddConstant(value) || arm64GoMoveConstant(value) ||
		arm64GoMoveConstant(^value) || arm64GoBitConstant(uint64(value)) ||
		(value >= 0 && value <= 0xffffff) {
		return true
	}
	return uint64(value) == uint64(uint32(value)) || value == int64(int32(value))
}

func arm64GoAddConstant(value int64) bool {
	if value < 0 {
		return false
	}
	if value&0xfff == 0 {
		value >>= 12
	}
	return value <= 0xfff
}

func arm64GoMoveConstant(value int64) bool {
	bits := uint64(value)
	for shift := uint(0); shift < 64; shift += 16 {
		if bits&^(uint64(0xffff)<<shift) == 0 {
			return true
		}
	}
	return false
}

func arm64GoBitConstant(value uint64) bool {
	if value == ^uint64(0) || value == 0 {
		return false
	}
	switch {
	case value != value>>32|value<<32:
	case value != value>>16|value<<48:
		value = uint64(int64(int32(value)))
	case value != value>>8|value<<56:
		value = uint64(int64(int16(value)))
	case value != value>>4|value<<60:
		value = uint64(int64(int8(value)))
	default:
		return true
	}
	return arm64SequenceOfOnes(value) || arm64SequenceOfOnes(^value)
}

func arm64SequenceOfOnes(value uint64) bool {
	next := value + (value & -value)
	return (next-1)&next == 0
}
