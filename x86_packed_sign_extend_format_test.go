package plan9asm

import (
	"errors"
	"testing"
)

// Keep every original named row as an actual Go object and three public
// Context observations before emitting any private format objects. Go386
// accepts high X/Y spellings that have no ordinary physical register role;
// they stay in the original source, not low-bank aliases in these objects.
func x86SignExtendOriginalFormatObject(t *testing.T, source, arch, triple string, wantPhysical, wantContext int) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	units := *file
	units.Funcs = nil
	physical, contextual := 0, 0
	for _, function := range file.Funcs {
		unit := function
		unit.Instrs = nil
		for _, instruction := range function.Instrs {
			if instruction.Op != OpTEXT && instruction.Op != OpRET {
				_, known, err := x86PackedSignExtendProperties(instruction, arch)
				if known && errors.Is(err, ErrProbeNeedsContext) && arch == "386" &&
					x86Mode32VectorRegisterContext(instruction, arch) != nil {
					contextual++
					continue
				}
				if !known || err != nil {
					t.Fatal("original signed widening row lost its exact physical grammar", instruction.Raw, err)
				}
				physical++
			}
			unit.Instrs = append(unit.Instrs, instruction)
		}
		units.Funcs = append(units.Funcs, unit)
	}
	if physical != wantPhysical || contextual != wantContext {
		t.Fatal("original signed widening format partition changed", physical, contextual, wantPhysical, wantContext)
	}
	t.Logf("all original Go rows/public Context retained; %d physical emitter rows and %d original Go-accepted high-bank Context rows; no initialized/native execution claim", physical, contextual)
	return x86InstructionFormatObjectUnit(t, &units, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			return c.lowerPackedExtendMove(instruction.Op, instruction)
		})
}
