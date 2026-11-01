package plan9asm

import (
	"errors"
	"testing"
)

// An operand/emitter object is not an initialized public program. Preserve
// the entire actual Go object and all three public Context outcomes first.
// Go-accepted mode32 high banks remain physical Context, not low-bank aliases.
func x86InLanePermuteUnboundFormatObject(t *testing.T, source, arch, triple string, wantPhysical, wantContext int) string {
	t.Helper()
	return x86ElementPermuteUnboundFormatObject(t, source, arch, triple, wantPhysical, wantContext)
}

func x86ElementPermuteUnboundFormatObject(t *testing.T, source, arch, triple string, wantPhysical, wantContext int) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("complete original permute formats lost their decoded source", err)
	}
	units := *normalized
	units.Funcs = nil
	physical, contextual := 0, 0
	for _, function := range normalized.Funcs {
		unit := function
		unit.Instrs = nil
		for _, instruction := range function.Instrs {
			if instruction.Op != OpTEXT && instruction.Op != OpRET {
				_, known, err := x86ElementPermuteProperties(instruction.Op, instruction, arch)
				if !known {
					_, known, err = x86Shuffle128BitBlocksProperties(instruction.Op, instruction, arch)
				}
				if known && errors.Is(err, ErrProbeNeedsContext) && arch == "386" &&
					x86Mode32VectorRegisterContext(instruction, arch) != nil {
					contextual++
					continue // The original complete Go/Context controls above retain this row.
				}
				if !known || err != nil {
					t.Fatal("original permute row lost its complete typed grammar", instruction.Raw, err)
				}
				physical++
			}
			unit.Instrs = append(unit.Instrs, instruction)
		}
		units.Funcs = append(units.Funcs, unit)
	}
	if physical != wantPhysical || contextual != wantContext {
		t.Fatal("original permute format classification changed", physical, contextual, wantPhysical, wantContext)
	}
	t.Logf("complete original Go/public Context retained; %d physical emitter formats and %d Go-accepted mode32 high-bank Context rows; no initialized/native execution claim", physical, contextual)
	return x86InstructionFormatObjectUnit(t, &units, signatures, arch, triple, 0,
		func(c *amd64Ctx, instruction Instr) (bool, bool, error) {
			form, known, err := x86ElementPermuteProperties(instruction.Op, instruction, arch)
			if !known {
				return c.lowerShuffle128BitBlocks(instruction.Op, instruction)
			}
			if !known || err != nil {
				return known, false, err
			}
			return c.lowerElementPermute(form, instruction)
		})
}

func x86ElementPermuteCompileFormatObjects(t *testing.T, llc, triple, ir string) {
	t.Helper()
	for _, pipeline := range []struct{ ir, level string }{
		{ir, "-O0"}, {ir, "-O2"}, {x86DwordProductIROptimize(t, ir), "-O2"},
	} {
		x86PackedStringCompileObject(t, llc, triple, pipeline.ir, pipeline.level)
	}
}
