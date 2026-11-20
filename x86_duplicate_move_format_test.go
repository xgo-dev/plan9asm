package plan9asm

import (
	"errors"
	"testing"
)

// Original Go objects and public Context checks belong to the caller. This
// private object unit proves formats only, never numerical or physical entry.
func x86DuplicateMoveFormatObjectUnit(t *testing.T, file *File, signatures map[string]FuncSig, arch, triple string) string {
	t.Helper()
	return x86InstructionFormatObjectUnit(t, file, signatures, arch, triple, 0,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			form, known, err := x86DuplicateMoveProperties(ins.Op, ins, arch)
			if errors.Is(err, ErrProbeNeedsContext) && arch == "386" && x86Mode32VectorRegisterContext(ins, arch) != nil {
				// Go's accepted high X/Y names have no bound mode32 physical
				// identity. Its preserved object witnesses the actual encoding;
				// a private vector-format carrier cannot grant that public role.
				form, known, err = x86DuplicateMoveProperties(ins.Op, ins, "amd64")
			}
			if !known || err != nil {
				return known, false, err
			}
			return true, false, c.emitDuplicateMove(ins, form)
		})
}
