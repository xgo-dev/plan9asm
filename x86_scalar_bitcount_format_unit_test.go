package plan9asm

import "testing"

// Original zero-argument format fixtures have no initialized entry registers
// or bound native pointers. Retain every Go object, public Context boundary
// and emitter-only LLVM format; initialized counterparts own public execution.
func x86ScalarCountUnboundFormatObject(t *testing.T, source, name, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSource(t, source, name, arch, triple)
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			// This object-only emitter observes the original SP destination
			// through its virtual register slot, not a native stack contract.
			// All public APIs above must still reject the unchanged source.
			c.allowSPWrite = arch == "386" && len(instruction.Args) == 2 &&
				instruction.Args[1].Kind == OpReg && instruction.Args[1].Reg == SP
			defer func() { c.allowSPWrite = false }()
			return c.lowerScalarBitCount(instruction.Op, instruction)
		})
}
