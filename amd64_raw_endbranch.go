package plan9asm

// ENDBR changes CET tracking, not GP/SIMD, FLAGS or storage. Numerical
// observers may preserve existing facts only for the exact named/raw form.
// The lowerer still emits the native opcode; this supplies no entry authority.
func x86EndBranchPreservesSourceState(ins Instr) bool {
	if ins.Op != "ENDBR64" && ins.Op != "ENDBR32" || len(ins.Args) != 0 ||
		ins.x86RawNearReturn != nil || ins.x86AddressBits != 0 ||
		ins.x86UnboundAddressOverride || ins.x86SegmentPrefix != 0 {
		return false
	}
	origin := ins.x86SourceRaw
	if origin == nil {
		return ins.Op == "ENDBR64" && !ins.x86Encoded
	}
	return ins.x86Encoded && origin.op == ins.Op && len(origin.args) == 0
}

// These instructions have different native effects. Only their preservation
// of numerical source facts is shared, never their lowering or CET semantics.
func x86PreservesNumericalSourceState(ins Instr) bool {
	return x86NOPPreservesSourceState(ins) || x86EndBranchPreservesSourceState(ins)
}

// ENDBR32/ENDBR64 have fixed, operand-free encodings (Intel SDM, volume 2).
// x86asm does not decode them yet. Preserve the actual instruction rather than
// replacing the CET state transition with a NOP. Go names only ENDBR64, so
// x86Encoded also keeps ENDBR32 confined to validated raw input.
func decodedX86EndBranchInstruction(code []byte) (Instr, int, bool) {
	if len(code) < 4 || code[0] != 0xf3 || code[1] != 0x0f || code[2] != 0x1e {
		return Instr{}, 0, false
	}
	var op Op
	switch code[3] {
	case 0xfa:
		op = "ENDBR64"
	case 0xfb:
		op = "ENDBR32"
	default:
		return Instr{}, 0, false
	}
	return Instr{Op: op, Raw: string(op), x86Encoded: true}, 4, true
}
