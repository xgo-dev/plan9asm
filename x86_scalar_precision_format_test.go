package plan9asm

import (
	"errors"
	"testing"
)

// Preserve the entire original Go object and three-API Context result. Only
// physically bound rows enter this private, compile-only emitter carrier;
// mode32 high banks are not initialized or remapped into AMD64 registers.
// Public initialized objects have their own complete independent matrix.
func x86ScalarPrecisionOriginalFormatObject(t *testing.T, source, name, arch, triple string, raw bool) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSource(t, source, name, arch, triple)
	if raw {
		var err error
		file, err = normalizeX86RawFile(file, arch)
		if err != nil {
			t.Fatal("complete original scalar precision bytes lost their decoder", err)
		}
	}
	local := *file
	local.Funcs = append([]Func(nil), file.Funcs...)
	local.Funcs[0].Instrs = nil
	contextRows, retained := 0, 0
	for _, instruction := range file.Funcs[0].Instrs {
		if _, known, err := x86ScalarPrecisionProperties(instruction.Op, instruction, arch); known {
			if err != nil {
				if arch != "386" || !errors.Is(err, ErrProbeNeedsContext) ||
					x86Mode32VectorRegisterContext(instruction, arch) == nil {
					t.Fatal("original precision format became malformed or lost a different source role", instruction.Raw, err)
				}
				contextRows++
				continue
			}
			retained++
		}
		local.Funcs[0].Instrs = append(local.Funcs[0].Instrs, instruction)
	}
	expectedContext := 0
	if arch == "386" {
		expectedContext = 7
		if raw {
			expectedContext = 4
		}
	}
	if contextRows != expectedContext || retained == 0 {
		t.Fatal("original physical-bank Context partition changed", arch, raw, contextRows, expectedContext, retained)
	}
	t.Logf("complete original source/object preserved: %d rows remain physical-bank Context; %d direct-emitter rows are object-only", contextRows, retained)
	return x86ScalarFormatObjectUnit(t, &local, signatures, arch, triple, 0)
}
