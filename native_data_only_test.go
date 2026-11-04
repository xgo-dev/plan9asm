package plan9asm

import (
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func TestNativeDataOnlyTranslationUnits(t *testing.T) {
	const source = "#include \"textflag.h\"\nGLOBL ·entry(SB),RODATA|NOPTR,$8\nDATA ·entry(SB)/8,$target(SB)\n"
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(goos+"/"+arch, func(t *testing.T) {
				nativePhysicalOriginalObject(t, goos, arch, source)
				opts := NativeOptions{GOOS: goos, GOARCH: arch, PackagePath: "probe",
					Imports: map[string]string{"target": "component_target"}}
				assembly, data, err := TranslateNativeSource([]byte(source), opts)
				if err != nil || len(data) != 1 || data[0].Size != 8 || !strings.Contains(assembly, "component_target") {
					t.Fatal("complete data-only source lost its exact bound address", err, data, assembly)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateNativeModule(ctx, []byte(source), opts)
				if err != nil {
					t.Fatal("complete data-only module rejected", err)
				}
				defer mod.Dispose()
				entry, target := mod.NamedGlobal("probe.entry"), mod.NamedGlobal("component_target")
				if !mod.FirstFunction().IsNil() || entry.IsNil() || target.IsNil() || !entry.IsGlobalConstant() ||
					entry.Initializer().OperandsCount() != 1 || entry.Initializer().Operand(0) != target {
					t.Fatal("data address became a guessed function or lost relocation identity", mod.String())
				}
				if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
					t.Fatal(err)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM22 llc is required")
				}
				for _, level := range []string{"-O0", "-O2"} {
					x86PackedStringCompileObject(t, llc, mod.Target(), mod.String(), level)
				}
			})
		}
	}
	for _, row := range []struct{ name, source string }{
		{"empty", ""},
		{"no GLOBL", "DATA ·entry(SB)/8,$target(SB)\n"},
		{"unknown symbol", strings.Replace(source, "$target(SB)", "$unknown(SB)", 1)},
		{"symbol offset", strings.Replace(source, "$target(SB)", "$target+8(SB)", 1)},
		{"narrow relocation", strings.Replace(source, "/8,", "/4,", 1)},
		{"outside storage", strings.Replace(source, "DATA ·entry(SB)", "DATA ·entry+8(SB)", 1)},
		{"overlap", source + "DATA ·entry(SB)/8,$1\n"},
		{"foreign flag", strings.Replace(source, "RODATA|NOPTR", "RODATA|32", 1)},
		{"unowned code entry", source},
	} {
		t.Run(row.name, func(t *testing.T) {
			opts := NativeOptions{GOOS: "linux", GOARCH: "amd64", PackagePath: "probe",
				Imports: map[string]string{"target": "component_target"}}
			if row.name == "unowned code entry" {
				opts.CodeEntries = map[string]string{"target": "component_target"}
			}
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			mod, err := TranslateNativeModule(ctx, []byte(row.source), opts)
			if err == nil {
				mod.Dispose()
				t.Fatal("unbound or malformed data acquired a native module")
			}
			if !mod.IsNil() {
				t.Fatal("error returned a partial module")
			}
		})
	}
}
