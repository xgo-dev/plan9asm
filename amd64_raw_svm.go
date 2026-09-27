package plan9asm

// decodedX86AMDSystemManagementInstruction covers AMD's fixed 0F 01 D8-DF
// system-management opcode family. golang.org/x/arch/x86asm does not decode
// these privileged instructions, so packages conventionally spell them as
// Plan 9 BYTE directives even though LLVM 22 can assemble their mnemonics.
func decodedX86AMDSystemManagementInstruction(code []byte) (Instr, int, bool) {
	if len(code) < 3 || code[0] != 0x0f || code[1] != 0x01 || code[2] < 0xd8 || code[2] > 0xdf {
		return Instr{}, 0, false
	}
	ops := [...]Op{
		"VMRUN",
		"VMMCALL",
		"VMLOAD",
		"VMSAVE",
		"STGI",
		"CLGI",
		"SKINIT",
		"INVLPGA",
	}
	op := ops[code[2]-0xd8]
	return Instr{Op: op, Raw: string(op)}, 3, true
}
