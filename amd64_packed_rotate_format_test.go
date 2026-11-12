package plan9asm

import (
	"errors"
	"testing"
)

// Preserve the original Go object and three public Context outcomes before
// classifying physical emitter rows. A format object supplies no entry values.
func x86PackedRotateUnboundFormatObject(t *testing.T, source, arch, triple string, wantPhysical, wantContext int) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("original rotate formats lost their decoded source", err)
	}
	units := *normalized
	units.Funcs = nil
	physical, contextual := 0, 0
	for _, function := range normalized.Funcs {
		unit := function
		unit.Instrs = nil
		for _, instruction := range function.Instrs {
			if instruction.Op != OpTEXT && instruction.Op != OpRET {
				_, known, err := x86PackedRotateProperties(instruction.Op, instruction, arch)
				if known && errors.Is(err, ErrProbeNeedsContext) && arch == "386" &&
					x86Mode32VectorRegisterContext(instruction, arch) != nil {
					contextual++
					continue // Retained by the complete original Go/public Context controls.
				}
				if !known || err != nil {
					t.Fatal("original rotate row lost its complete typed grammar", instruction.Raw, err)
				}
				physical++
			}
			unit.Instrs = append(unit.Instrs, instruction)
		}
		units.Funcs = append(units.Funcs, unit)
	}
	if physical != wantPhysical || contextual != wantContext {
		t.Fatal("original rotate format classification changed", physical, contextual, wantPhysical, wantContext)
	}
	t.Logf("%d physical emitter formats; %d Go-accepted mode32 high-bank Context rows; no initialized/native claim", physical, contextual)
	return x86InstructionFormatObjectUnit(t, &units, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			return c.lowerPackedRotate(instruction.Op, instruction)
		})
}
