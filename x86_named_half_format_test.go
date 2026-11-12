package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Original formats retain actual Go objects and public Context independently
// of initialized public programs. A visible single-row function prevents a
// terminal architectural encoding from hiding any later backend format.
func x86NamedHalfOriginalFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	file, _ := x86UnboundVoidFormatSources(t, source, arch, triple)
	file, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("complete original half formats lost their physical decoding", err)
	}
	units := *file
	units.Funcs = nil
	signatures := make(map[string]FuncSig)
	rows, contextual := 0, 0
	for _, fn := range file.Funcs {
		last := len(fn.Instrs) - 1
		if last < 2 || fn.Instrs[0].Op != OpTEXT || fn.Instrs[last].Op != OpRET {
			t.Fatal("original half formats lost their TEXT/RET envelope")
		}
		for _, ins := range fn.Instrs[1:last] {
			_, known, err := x86NamedHalfProperties(ins.Op, ins, arch)
			if !known {
				t.Fatal("original half format acquired another instruction family", ins.Raw)
			}
			rows++
			if err != nil {
				if arch != "386" || !errors.Is(err, ErrProbeNeedsContext) ||
					x86Mode32VectorRegisterContext(ins, arch) == nil {
					t.Fatal("original half format lost a different grammar or source role", ins.Raw, err)
				}
				contextual++
				continue
			}
			name := fmt.Sprint("HalfFormat", rows)
			unit := fn
			unit.Sym = name
			unit.Instrs = []Instr{fn.Instrs[0], ins, fn.Instrs[last]}
			units.Funcs = append(units.Funcs, unit)
			signatures[name] = FuncSig{Name: name, Ret: Void}
		}
	}
	ir := x86SingleInstructionFormatObjectUnits(t, &units, signatures, arch, triple,
		func(c *amd64Ctx, ins Instr) (bool, bool, error) {
			return c.lowerPackedHalfConversion(ins.Op, ins)
		})
	if rows == 0 || strings.Count(ir, "define void @InstructionFormat") != rows-contextual {
		t.Fatal("an original half format lost its backend-visible unit", rows, contextual)
	}
	t.Logf("%d original half rows retain Go objects/public Context: %d physical mode32-bank Context, %d visible private format objects; no native execution claim",
		rows, contextual, rows-contextual)
	return ir
}
