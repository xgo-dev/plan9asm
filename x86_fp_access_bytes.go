package plan9asm

import "strings"

// X86FPAccessBytes observes a registered instruction's full native FP access
// width. It is not a source, initialization, alignment, caller or translation
// certificate. Unknown forms return no width; no opcode-suffix inference is
// used. The actual original assembler and selected declaration remain the
// diagnostic consumer's independent obligations.
func X86FPAccessBytes(ins Instr, index int, arch string) (width int64, write, known bool) {
	if arch != "amd64" && arch != "386" || index < 0 || index >= len(ins.Args) || ins.Args[index].Kind != OpFP {
		return 0, false, false
	}
	// Actual Parse/CPP output uses canonical source opcodes. The observation
	// does not promote a constructed case-folded identity to original source.
	if name := string(ins.Op); name != strings.ToUpper(name) || name != strings.TrimSpace(name) {
		return 0, false, false
	}
	// Generic source-stack diagnostics normalize suffixes, but that fallback
	// cannot certify a constructed scalar opcode which bypassed this grammar.
	if op := Op(normalizeInstructionOpcode(ins.Op)); x86RawReturnScalarMoveBytes(op) != 0 && ins.Op != op {
		return 0, false, false
	}
	// These three Ym rows observe exactly m16. FINIT/FCLEX and FSTSW AX
	// have no FP memory access. This supplies only width/direction, never a
	// known control/status word or an independent caller/storage permission.
	if form, recognized, err := x86X87WordProperties(ins, arch); recognized {
		if err != nil || index != 0 || form.operand.Kind != OpFP {
			return 0, false, false
		}
		return 2, form.kind != x86X87LoadControl, true
	}
	// x87 memory widths come from the same complete Go value grammar used by
	// lowering and the private source observer. Operand-free/register forms
	// have no FP access; malformed integer stores cannot fall through to a
	// suffix-derived width. Recognition supplies no initialized value or role.
	if form, recognized, err := x86X87ValueProperties(ins, arch); recognized {
		if err != nil || form.memoryBytes() == 0 {
			return 0, false, false
		}
		return form.memoryBytes(), index == 1, true
	}
	// CMP/TEST have two read-only operands, with opposite immediate positions.
	// Reuse the complete lowering grammar; observing these widths supplies
	// neither initialized flags/results nor permission to access native memory.
	if form, recognized, err := x86ScalarCompareProperties(ins.Op, ins, arch); recognized {
		if err != nil || form.memory != index {
			return 0, false, false
		}
		return int64(form.bits / 8), false, true
	}
	// Broadcast memory reads have their scalar/block width, not the width of
	// the vector destination. Mask-data broadcasts have no memory form at all.
	if form, recognized, err := x86BroadcastProperties(ins.Op, ins, arch); recognized {
		if err != nil || index != 0 || form.kind == x86BroadcastMask {
			return 0, false, false
		}
		return int64(form.sourceBytes), false, true
	}
	if effect, recognized, err := x86TypedInstructionByteEffect(ins.Op, ins, arch); recognized {
		if err != nil {
			return 0, false, false
		}
		for _, operand := range effect.operands {
			if operand.index == index {
				return operand.width, operand.write, true
			}
		}
		return 0, false, false
	}
	// MOVL/MOVQ/MOVD and the VEX forms have complete Go GP/X memory rows in the
	// same typed transfer grammar as register copies. Keep the FP observer on
	// those rows instead of falling through to the GP-only scalar shortcut;
	// otherwise MOVL X0,value(FP) and its load direction are silently reported
	// as unknown despite being official formats. Go's MOVD alias shares MOVQ's
	// eight-byte memory effect on both architectures.
	if form, recognized, err := x86GPSIMDTransferProperties(ins, arch); recognized {
		if err != nil || form.memory < 0 || form.memory != index {
			return 0, false, false
		}
		return int64(form.bits / 8), form.memoryWrite, true
	}
	// The legacy MMX memory rows use these same opcode widths, but their bank
	// remains separate from X-register state and caller initialization proofs.
	if spec, known := x86GPSIMDTransferSpecs[ins.Op]; known && spec.legacy && len(ins.Args) == 2 {
		other := ins.Args[1-index]
		if isAMD64MOVDMRegister(other) && x86PackedShiftMemoryValid(ins.Args[index], arch) {
			return int64(spec.bits / 8), index == 1, true
		}
	}
	op := x86SourceMoveInstruction(ins, arch).Op
	if op == "MOVB" || op == "MOVW" || op == "MOVL" || op == "MOVQ" {
		if len(ins.Args) != 2 {
			return 0, false, false
		}
		width = x86RawReturnScalarMoveBytes(op)
		otherOperand := ins.Args[1-index]
		if index == 1 && otherOperand.Kind == OpImm && otherOperand.ImmRaw == "" && !otherOperand.ImmIsFloat &&
			(width != 8 || arch == "amd64" && otherOperand.Imm == int64(int32(otherOperand.Imm))) {
			return width, true, true
		}
		if otherOperand.Kind != OpReg {
			return 0, false, false
		}
		other := ins.Args[1-index].Reg
		valid := isX86YrlRegisterForArch(other, arch)
		if width == 1 {
			valid = isGoYmbRegisterForArch(other, arch)
		}
		if !valid || width == 8 && arch == "386" {
			return 0, false, false
		}
		return width, index == 1, true
	}
	// The source-stack consumer shares these ordered typed forms. Its own
	// numerical/pointer/mask authority is not exported by this observation.
	return x86InstructionMemoryShape(ins, index, arch)
}
