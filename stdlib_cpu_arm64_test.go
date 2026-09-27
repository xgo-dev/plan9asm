package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdlibInternalCPU_ARM64_Compile(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc not found")
	}

	goroot := testGOROOT(t)
	src, err := os.ReadFile(filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64.s"))
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatal("internal/cpu/cpu_arm64.s not present in this GOROOT")
		}
		t.Fatal(err)
	}

	file, err := Parse(ArchARM64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string {
		if strings.HasPrefix(sym, "·") {
			return "internal/cpu." + strings.TrimPrefix(sym, "·")
		}
		return strings.ReplaceAll(sym, "·", ".")
	}
	sigs := map[string]FuncSig{
		"internal/cpu.getisar0": {
			Name:  "internal/cpu.getisar0",
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
		},
		"internal/cpu.getisar1": {
			Name:  "internal/cpu.getisar1",
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
		},
		"internal/cpu.getpfr0": {
			Name:  "internal/cpu.getpfr0",
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
		},
		"internal/cpu.getMIDR": {
			Name:  "internal/cpu.getMIDR",
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
		},
	}
	ll, err := Translate(file, Options{
		TargetTriple: arm64LinuxGNUTriple,
		ResolveSym:   resolve,
		Sigs:         sigs,
		Goarch:       "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}

	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "cpu.ll", "cpu.o", ll)
}
