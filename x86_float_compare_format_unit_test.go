package plan9asm

import "testing"

func x86FloatingCompareUnboundFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	for index, function := range file.Funcs {
		decoded, err := decodeX86RawDirectives(function, arch)
		if err != nil {
			t.Fatal("original format unit lost its complete physical decoder", err)
		}
		// Retain the decoder's original raw provenance. This emitter-only
		// object is not a public source, initialized input or native ABI grant.
		file.Funcs[index] = decoded
	}
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			return c.lowerFloatingCompare(ins.Op, ins)
		})
}
