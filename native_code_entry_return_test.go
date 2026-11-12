package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
)

func nativeReturnEntrySource(frame string) []byte {
	return []byte(fmt.Sprintf("#include \"textflag.h\"\nTEXT rawEntry(SB), NOSPLIT|NOFRAME, %s\nRET\n"+
		"GLOBL ·entry(SB), RODATA|NOPTR, $8\nDATA ·entry(SB)/8, $rawEntry(SB)\n", frame))
}

// The map binds an address token, never an inferred Go/C function prototype.
// The original Go assembler and both LLVM object levels see the same source.
func TestNativeCodeEntryReturnLeafObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			for _, frame := range []string{"$0", "$0-0"} {
				t.Run(goos+"/"+arch+"/"+frame, func(t *testing.T) {
					source := nativeReturnEntrySource(frame)
					directory := t.TempDir()
					file := filepath.Join(directory, "entry.s")
					if err := os.WriteFile(file, source, 0o600); err != nil {
						t.Fatal(err)
					}
					stage, cancel := runtimeOracleStageContext(t)
					output, err := goasmcmd.Run(stage, directory, append(os.Environ(),
						"GOROOT="+runtime.GOROOT(), "GOTOOLCHAIN=local", "GOENV=off", "GOWORK=off",
						"GOOS="+goos, "GOARCH="+arch), filepath.Join(runtime.GOROOT(), "bin/go"),
						"tool", "asm", "-p", "probe", "-I", filepath.Join(runtime.GOROOT(), "pkg/include"),
						"-o", filepath.Join(directory, "original.o"), file)
					cancel()
					if err != nil {
						t.Fatalf("actual Go assembler: %v\n%s", err, output)
					}
					t.Log("complete original Go assembly object accepted; no native execution claimed")
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					mod, err := TranslateNativeModule(ctx, source, NativeOptions{
						GOOS: goos, GOARCH: arch, PackagePath: "probe",
						CodeEntries: map[string]string{"rawEntry": "probe.native_return"},
					})
					if err != nil {
						t.Fatal("closed return-only address entry rejected", err)
					}
					defer mod.Dispose()
					entry := mod.NamedFunction("probe.native_return")
					global := mod.NamedGlobal("probe.entry")
					if entry.IsNil() || global.IsNil() {
						t.Fatal("missing original code or DATA identity")
					}
					initializer := global.Initializer()
					if initializer.IsNil() || initializer.OperandsCount() != 1 || initializer.Operand(0) != entry {
						t.Fatal("DATA did not retain its exact code-symbol relocation")
					}
					if !strings.Contains(mod.String(), "naked noinline") || strings.Contains(mod.String(), "module asm") {
						t.Fatal("entry lost its existing address-only carrier", mod.String())
					}
					if err := llvm.VerifyModule(mod, llvm.ReturnStatusAction); err != nil {
						t.Fatal(err)
					}
					for _, level := range []string{"-O0", "-O2"} {
						x86PackedStringCompileObject(t, llc, mod.Target(), mod.String(), level)
					}
				})
			}
		}
	}
}

func TestNativeCodeEntryReturnLeafRejectsUnprovedContracts(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		source := string(nativeReturnEntrySource("$0-0"))
		registerAccess, frameAccess := "MOVQ AX,DX", "MOVQ value+0(FP),AX"
		if arch == "arm64" {
			registerAccess, frameAccess = "MOVD R0,R1", "MOVD value+0(FP),R0"
		}
		for _, row := range []struct{ name, source string }{
			{"missing NOFRAME", strings.Replace(source, "|NOFRAME", "", 1)},
			{"missing NOSPLIT", strings.Replace(source, "NOSPLIT|", "", 1)},
			{"nonzero frame", strings.Replace(source, "$0-0", "$16-0", 1)},
			{"Go argument frame", strings.Replace(source, "$0-0", "$0-8", 1)},
			{"package Go symbol", strings.ReplaceAll(source, "rawEntry(SB)", "·rawEntry(SB)")},
			{"return changes stack", strings.Replace(source, "\nRET\n", "\nRET $8\n", 1)},
			{"register access", strings.Replace(source, "\nRET\n", "\n"+registerAccess+"\nRET\n", 1)},
			{"FP access", strings.Replace(source, "\nRET\n", "\n"+frameAccess+"\nRET\n", 1)},
			{"unowned sibling", source + "\nTEXT other(SB), NOSPLIT|NOFRAME, $0-0\nRET\n"},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				opts := NativeOptions{
					GOOS: "linux", GOARCH: arch, PackagePath: "probe",
					CodeEntries: map[string]string{"rawEntry": "probe.native_return"},
				}
				if row.name == "missing NOFRAME" || row.name == "register access" ||
					arch == "amd64" && row.name == "nonzero frame" {
					nativePhysicalOriginalObject(t, "linux", arch, row.source)
					ir := nativeAMD64PhysicalObjects(t, row.source, opts)
					if !strings.Contains(ir, "naked noinline") || !strings.Contains(ir, "probe.native_return") {
						t.Fatal("physical entry lost its exact address-only identity", ir)
					}
					return
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateNativeModule(ctx, []byte(row.source), opts)
				if err == nil {
					mod.Dispose()
					t.Fatal("unproved source inherited the closed address-entry role")
				}
				if !mod.IsNil() {
					t.Fatal("rejected source returned a partial module")
				}
			})
		}
	}
}
