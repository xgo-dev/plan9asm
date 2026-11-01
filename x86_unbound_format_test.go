package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// An original format-only function can lack numerical inputs, native addresses
// or a closed physical register state. Preserve its complete Go object and
// public Context result instead of treating a direct emitter as a public ABI.
func x86UnboundVoidFormatSource(t *testing.T, source, name, arch, triple string) (*File, map[string]FuncSig) {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	if len(file.Funcs) != 1 || strings.TrimPrefix(file.Funcs[0].Sym, "·") != name {
		t.Fatal("single original format source lost its function identity", name)
	}
	return file, signatures
}

func x86UnboundVoidFormatSources(t *testing.T, source, arch, triple string) (*File, map[string]FuncSig) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	var declarations strings.Builder
	signatures := make(map[string]FuncSig)
	for _, function := range file.Funcs {
		if function.FrameSize != 0 || function.ArgSize != 0 {
			t.Fatal("unbound Void format unit cannot impersonate a frame or typed input")
		}
		name := strings.TrimPrefix(function.Sym, "·")
		fmt.Fprintf(&declarations, "func %s()\n", name)
		signatures[name] = FuncSig{Name: name, Ret: Void}
	}
	if len(signatures) == 0 || len(signatures) != len(file.Funcs) {
		t.Fatal("incomplete or duplicate original Void format inventory")
	}
	x86LEAActualTargetGoObject(t, arch, triple, "#include \"textflag.h\"\n"+source)
	for _, api := range []string{"text", "module", "Go"} {
		ir, err := x86ScalarFPBitViewAPI(t, source, declarations.String(), arch, triple, api)
		if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("original format fixture invented its missing source inputs", api, err)
		}
	}
	return file, signatures
}

func x86UnboundVoidScalarFormatObject(t *testing.T, source, name, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSource(t, source, name, arch, triple)
	return x86ScalarFormatObjectUnit(t, file, signatures, arch, triple, 0)
}

func x86UnboundVoidRawScalarFormatObject(t *testing.T, source, arch, triple string) string {
	t.Helper()
	file, signatures := x86UnboundVoidFormatSources(t, source, arch, triple)
	normalized, err := normalizeX86RawFile(file, arch)
	if err != nil {
		t.Fatal("original format bytes could not be decoded", err)
	}
	return x86ScalarFormatObjectUnit(t, normalized, signatures, arch, triple, 0)
}

// Encoder probes may retain a terminal UD2 instead of an unproved native RET.
// That removes a return obligation, not the numerical/native input obligations
// of preceding instructions. Preserve every original format and its fault.
func x86UnboundVoidRawProbeObject(t *testing.T, file *File, arch, triple string) string {
	t.Helper()
	var source strings.Builder
	for _, function := range file.Funcs {
		text, valid := x86RawReplaySourceText(function)
		if !valid {
			t.Fatal("raw format probe lost its complete original source")
		}
		source.WriteString(text)
	}
	return x86UnboundVoidRawScalarFormatObject(t, source.String(), arch, triple)
}
