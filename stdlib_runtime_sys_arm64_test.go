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
// Go 1.27 ARM64 has 128 bytes of padding followed by ten feature booleans.
// This supplies the real generated assembler constant; it does not modify
// the original assembly or substitute its DIT/barrier instructions.
const offsetARM64HasSB = 138
func EnableDIT() bool
func DITEnabled() bool
func DisableDIT()
`)

	for _, target := range []struct {
		goos, triple string
	}{
		{"linux", "aarch64-unknown-linux-gnu"},
		{"linux", "aarch64-unknown-linux-musl"},
		{"darwin", "aarch64-apple-darwin"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			// Assemble the same complete preprocessed source independently.
			// No DIT-changing instruction is executed by this object-only test.
			oracle, err := preprocessWithDefines("#define const_offsetARM64HasSB 138\n"+string(src), GoAssemblerDefines(target.goos, "arm64"))
			if err != nil {
				t.Fatal(err)
			}
			requireARM64GoAssemblerResult(t, oracle, true)
			tr, err := TranslateGoModule(pkg, src, GoModuleOptions{
				FileName: "dit_arm64.s", GOOS: target.goos, GOARCH: "arm64",
				TargetTriple: target.triple, ResolveSym: testResolveSym("internal/runtime/sys"),
			})
			if err != nil {
				t.Fatal(err)
			}
			defer tr.Module.Dispose()
			ir := tr.Module.String()
			if len(tr.Functions) != 3 {
				t.Fatalf("DIT production translation has %d functions, want all three", len(tr.Functions))
			}
			if target.goos == "darwin" {
				if strings.Contains(ir, "unreachable") {
					t.Fatal("Darwin barrier fallback is reachable and must retain its caller return")
				}
			} else if !strings.Contains(ir, "unreachable") {
				t.Fatal("non-Darwin dead barrier fallback must not fabricate a native branch or return")
			}
			compileLLVMToObject(t, llc, target.triple, "dit-gomod.ll", "dit-gomod.o", ir)
		})
	}
}
