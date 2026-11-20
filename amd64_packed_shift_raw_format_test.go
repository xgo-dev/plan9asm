package plan9asm

import (
	"errors"
	"testing"
)

// Preserve original bytes, return and literal DATA. These isolated operand
// objects do not supply native entry inputs, caller memory or a return proof.
func x86PackedShiftRawFormatObject(t *testing.T, file *File, options Options) string {
	t.Helper()
	if ir, err := Translate(file, options); ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("original raw shift acquired unbound native entry/mask/return inputs", err)
	}
	normalized, err := normalizeX86RawFile(file, options.Goarch)
	if err != nil {
		t.Fatal("original raw shift formats could not be decoded", err)
	}
	return x86InstructionFormatObjectUnit(t, normalized, options.Sigs, options.Goarch, options.TargetTriple, 0,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			return c.lowerX86PackedShift(ins.Op, ins)
		})
}
