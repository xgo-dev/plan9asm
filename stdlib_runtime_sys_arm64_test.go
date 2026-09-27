//go:build go1.27
// +build go1.27

package plan9asm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdlibInternalRuntimeSys_ARM64_Compile(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc not found")
	}

	goroot := testGOROOT(t)
	src, err := os.ReadFile(filepath.Join(goroot, "src", "internal", "runtime", "sys", "dit_arm64.s"))
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatal("internal/runtime/sys/dit_arm64.s not present in this GOROOT")
		}
		t.Fatal(err)
	}

	file, err := Parse(ArchARM64, string(src))
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(sym string) string {
		if strings.HasPrefix(sym, "·") {
			return "internal/runtime/sys." + strings.TrimPrefix(sym, "·")
		}
		return strings.ReplaceAll(sym, "·", ".")
	}
	sigs := map[string]FuncSig{
		"internal/runtime/sys.EnableDIT": {
			Name: "internal/runtime/sys.EnableDIT",
			Ret:  I1,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 0, Type: I1, Index: 0}},
			},
		},
		"internal/runtime/sys.DITEnabled": {
			Name: "internal/runtime/sys.DITEnabled",
			Ret:  I1,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 0, Type: I1, Index: 0}},
			},
		},
		"internal/runtime/sys.DisableDIT": {
			Name: "internal/runtime/sys.DisableDIT",
			Ret:  Void,
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

	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "dit.ll", "dit.o", ll)
}

func TestTranslateGoModule_StdlibInternalRuntimeSys_ARM64_Compile(t *testing.T) {
	llc, _, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("llc not found")
	}

	goroot := testGOROOT(t)
	src, err := os.ReadFile(filepath.Join(goroot, "src", "internal", "runtime", "sys", "dit_arm64.s"))
	if err != nil {
		if os.IsNotExist(err) {
			t.Fatal("internal/runtime/sys/dit_arm64.s not present in this GOROOT")
		}
		t.Fatal(err)
	}
	pkg := mustGoPackage(t, "internal/runtime/sys", `package sys
func EnableDIT() bool
func DITEnabled() bool
func DisableDIT()
`)

	tr, err := TranslateGoModule(pkg, src, GoModuleOptions{
		FileName:     "dit_arm64.s",
		GOOS:         "linux",
		GOARCH:       "arm64",
		TargetTriple: arm64LinuxGNUTriple,
		ResolveSym:   testResolveSym("internal/runtime/sys"),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tr.Module.Dispose()

	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "dit-gomod.ll", "dit-gomod.o", tr.Module.String())
}
