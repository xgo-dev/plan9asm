package plan9asm

import "testing"

// Keep each original uninitialized format source and its actual Go object.
// Three public APIs must retain Context; the direct family emitter supplies
// only operand/backend objects, never numerical or native-entry permission.
func x86PackedFloatShuffleUnboundFormatObject(t *testing.T, source, arch, triple string, want int) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	count := 0
	for _, function := range file.Funcs {
		for _, instruction := range function.Instrs {
			if instruction.Op == OpTEXT || instruction.Op == OpRET {
				continue
			}
			if _, known, err := x86PackedFloatShuffleProperties(instruction.Op, instruction, arch); !known || err != nil {
				t.Fatal("original complete floating-shuffle format row disappeared", instruction.Raw, err)
			}
			count++
		}
	}
	if count != want {
		t.Fatal("complete original floating-shuffle format denominator changed", count, want)
	}
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			return c.lowerPackedFloatShuffle(instruction.Op, instruction)
		})
}
