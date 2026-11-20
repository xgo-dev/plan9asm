package plan9asm

import (
	"errors"
	"testing"
)

// Preserve every original source row, actual Go object and three-API Context
// result. A private direct-emitter object proves only the physically bound
// formats, not initialized source inputs or a native entry. Mode32 high banks
// remain represented by their unchanged Go object and explicit Context; they
// are never remapped to another register or claimed as initialized objects.
func x86PackedPrecisionOriginalFormatObject(t *testing.T, source, name, arch, triple string,
	raw bool, expectedRows, mode32ContextRows int) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSource(t, source, name, arch, triple)
	if raw {
		var err error
		file, err = normalizeX86RawFile(file, arch)
		if err != nil {
			t.Fatal("complete original packed precision bytes lost their decoder", err)
		}
	}
	local := *file
	local.Funcs = append([]Func(nil), file.Funcs...)
	local.Funcs[0].Instrs = nil
	rows, contextual := 0, 0
	for _, instruction := range file.Funcs[0].Instrs {
		if _, known, err := x86PackedPrecisionProperties(instruction.Op, instruction, arch); known {
			rows++
			if err != nil {
				if arch != "386" || !errors.Is(err, ErrProbeNeedsContext) ||
					x86Mode32VectorRegisterContext(instruction, arch) == nil {
					t.Fatal("original packed precision format became malformed or lost a different source role", instruction.Raw, err)
				}
				contextual++
				continue
			}
		}
		local.Funcs[0].Instrs = append(local.Funcs[0].Instrs, instruction)
	}
	wantContext := 0
	if arch == "386" {
		wantContext = mode32ContextRows
	}
	if rows != expectedRows || contextual != wantContext ||
		len(local.Funcs[0].Instrs)+contextual != len(file.Funcs[0].Instrs) {
		t.Fatal("complete original packed precision format partition changed", rows, expectedRows, contextual, wantContext)
	}
	t.Logf("all %d original rows retained in Go objects/public Context: %d physical-bank Context, %d private emitter-only objects; independent initialized public objects have their own owner",
		rows, contextual, rows-contextual)
	return x86ScalarFormatObjectUnit(t, &local, signatures, arch, triple, 0)
}
