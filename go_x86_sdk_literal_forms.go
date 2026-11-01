package plan9asm

import "strings"

type x86SDKLiteralOperand struct {
	memory  MemRef
	symbol  string
	offset  int64
	width   int64
	address bool
}

// Go's obj6 progedit rewrites AMD64 MOVL/Q TYPE_ADDR to LEAL/Q;
// non-shared 386 named MOVL TYPE_ADDR is an absolute relocation, ignoring
// both source Reg and Index. Named 386 LEA/memory ignores Reg but uses Index.
// This grammar supplies no bounds, numerical bytes or address permission.
func x86SDKLiteralOperandProperties(ins Instr, index int, arch string) (x86SDKLiteralOperand, bool) {
	var form x86SDKLiteralOperand
	if index < 0 || index >= len(ins.Args) || arch != "386" && arch != "amd64" ||
		ins.x86Encoded || ins.x86SourceRaw != nil || ins.x86AddressBits != 0 || ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return form, false
	}
	ins = x86SourceMoveInstruction(ins, arch) // Local grammar dispatch, never original Op/Raw.
	operand := ins.Args[index]
	immediate := operand.Kind == OpSym && strings.HasPrefix(strings.TrimSpace(operand.Sym), "$")
	if immediate {
		parsed, err := parseOperandForArch(ArchAMD64, strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(operand.Sym), "$")))
		if err != nil {
			return form, false
		}
		operand = parsed
	}
	memory, valid := x86SBMemoryAddressRole(operand, arch)
	if !valid {
		return form, false
	}
	base, offset, valid := parseSBRef(memory.Sym)
	if !valid || !strings.HasSuffix(base, "<>") || memory.OffRaw != "" || memory.Segment != "" || memory.IndexExt != "" {
		return form, false
	}
	// The shared parser preserves the symbolic displacement separately from
	// an AST memory displacement. Reject overflow before composing them.
	combined := offset + memory.Off
	if memory.Off > 0 && combined < offset || memory.Off < 0 && combined > offset {
		return form, false
	}
	form.memory, form.symbol, form.offset = memory, base, combined
	form.address = immediate || ins.Op == "LEAL" || ins.Op == "LEAQ"
	if form.address {
		word, move, lea := x86ResultPointerWord(arch), Op("MOVQ"), Op("LEAQ")
		if arch == "386" {
			move, lea = "MOVL", "LEAL"
		}
		if index != 0 || len(ins.Args) != 2 || ins.Op != lea && !(immediate && ins.Op == move) ||
			ins.Args[1].Kind != OpReg {
			return form, false
		}
		_, _, valid := x86ResultGP(ins.Args[1].Reg, word, arch)
		if !valid || ins.Args[1].Reg == "R14" {
			return form, false // Native SP/BP/g storage remains a separate role.
		}
		if arch == "386" && immediate {
			form.memory.Index, form.memory.Scale = "", 0
		}
		return form, true
	}
	width, write, known := x86InstructionMemoryShape(ins, index, arch)
	form.width = width
	return form, known && !write && width > 0
}
