package plan9asm

import "strings"

// Incoming g is opaque, not an initialized number or caller data pointer.
// Only an exact native-width private PUSH/POP may save/restore its identity.
// All non-stack uses still consume the actual caller's byte/provenance proof.
func x86SourceGRegister(register Reg) bool {
	root, valid := amd64FullRegBase(register)
	return valid && root == "R14"
}

func x86SourceGOperand(instruction Instr) bool {
	for _, operand := range instruction.Args {
		if operand.Kind == OpReg && x86SourceGRegister(operand.Reg) ||
			operand.Kind == OpMem && (x86SourceGRegister(operand.Mem.Base) || x86SourceGRegister(operand.Mem.Index)) {
			return true
		}
	}
	return false
}

func x86CallerGDefinition(instruction Instr, state *x86SourceStackState) {
	op := Op(normalizeInstructionOpcode(instruction.Op))
	if _, stack := amd64StackWidthSpecs[op]; stack {
		return // Stack transfer already consumed its exact opaque/numeric cell.
	}
	if op == OpTEXT || op == OpLABEL || op == OpRET || op == OpJMP || isAMD64ConditionalBranch(op) ||
		strings.HasPrefix(string(op), "CMP") || strings.HasPrefix(string(op), "TEST") {
		return
	}
	if count := len(instruction.Args); count != 0 {
		destination := instruction.Args[count-1]
		if destination.Kind == OpReg && x86SourceGRegister(destination.Reg) {
			// Called only after the registered family's complete must-defined
			// and pointer effects succeeded. No instruction can define the
			// original g; every source return needs an exact saved token POP.
			state.gOriginal = false
		}
	}
}
