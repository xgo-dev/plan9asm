package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	llvm "github.com/xgo-dev/llvm"
)

func nativeCodeEntryOptions(goos, arch string) NativeOptions {
	return NativeOptions{
		GOOS: goos, GOARCH: arch, PackagePath: "probe",
		Imports:     map[string]string{"imported": "strlen"},
		CodeEntries: map[string]string{"strlen": "probe.native_strlen"},
	}
}

func TestNativeCodeEntryTailStubFamily(t *testing.T) {
	rootOutput, err := exec.Command("go", "env", "GOROOT").CombinedOutput()
	if err != nil {
		t.Fatalf("actual Go GOROOT: %v\n%s", err, rootOutput)
	}
	goRoot := strings.TrimSpace(string(rootOutput))
	for _, goos := range []string{"linux", "darwin"} {
		for _, arch := range []string{"amd64", "arm64"} {
			ops := []string{"JMP"}
			if arch == "arm64" {
				ops = append(ops, "B")
			}
			for _, op := range ops {
				for _, frame := range []string{"$0", "$0-0"} {
					for _, deadRet := range []bool{false, true} {
						t.Run(fmt.Sprintf("%s/%s/%s/%s/ret-%v", goos, arch, op, frame, deadRet), func(t *testing.T) {
							source := fmt.Sprintf("#include \"textflag.h\"\nTEXT strlen(SB), NOSPLIT|NOFRAME, %s\n%s imported(SB)\n", frame, op)
							if deadRet {
								source += "RET\n"
							}
							dir := t.TempDir()
							file := filepath.Join(dir, "entry.s")
							if err := os.WriteFile(file, []byte(source), 0600); err != nil {
								t.Fatal(err)
							}
							goCmd := exec.Command("go", "tool", "asm", "-I", filepath.Join(goRoot, "pkg", "include"), "-o", filepath.Join(dir, "go.o"), file)
							goCmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS="+goos, "GOARCH="+arch)
							if out, err := goCmd.CombinedOutput(); err != nil {
								t.Fatalf("actual Go assembler: %v\n%s", err, out)
							}
							opts := nativeCodeEntryOptions(goos, arch)
							asm, _, err := TranslateNativeSource([]byte(source), opts)
							if err != nil {
								t.Fatal(err)
							}
							if !strings.Contains(asm, "probe.native_strlen") || !strings.Contains(asm, "strlen") {
								t.Fatal(asm)
							}
							ctx := llvm.NewContext()
							defer ctx.Dispose()
							mod, err := TranslateNativeModule(ctx, []byte(source), opts)
							if err != nil {
								t.Fatal(err)
							}
							defer mod.Dispose()
							entry := mod.NamedFunction("probe.native_strlen")
							if entry.IsNil() || entry.Linkage() != llvm.ExternalLinkage || mod.NamedGlobal("strlen").IsNil() {
								t.Fatalf("code token and foreign import identity collided:\n%s", mod.String())
							}
							assembly := nativeModuleAssembly(t, mod.String(), "default<O2>")
							asmFile := filepath.Join(dir, "llvm.s")
							if err := os.WriteFile(asmFile, []byte(assembly), 0600); err != nil {
								t.Fatal(err)
							}
							clang := findLLVM22Tool("clang")
							if clang == "" {
								t.Fatal("LLVM 22 clang is required")
							}
							if out, err := exec.Command(clang, "--target="+mod.Target(), "-c", asmFile, "-o", filepath.Join(dir, "llvm.o")).CombinedOutput(); err != nil {
								t.Fatalf("LLVM 22 object: %v\n%s\n%s", err, out, assembly)
							}
							nativeFile := filepath.Join(dir, "native.s")
							if err := os.WriteFile(nativeFile, []byte(asm), 0600); err != nil {
								t.Fatal(err)
							}
							if out, err := exec.Command(clang, "--target="+mod.Target(), "-c", nativeFile, "-o", filepath.Join(dir, "native.o")).CombinedOutput(); err != nil {
								t.Fatalf("LLVM 22 standalone native source object: %v\n%s\n%s", err, out, asm)
							}
							if goos == runtime.GOOS && arch == runtime.GOARCH {
								harness := filepath.Join(dir, "main.c")
								prefix := ""
								if goos == "darwin" {
									prefix = "_"
								}
								code := fmt.Sprintf("extern unsigned long token(const char *) __asm(\"%sprobe.native_strlen\");\nint main(void){return token(\"\")!=0 || token(\"native token\")!=12;}\n", prefix)
								if err := os.WriteFile(harness, []byte(code), 0600); err != nil {
									t.Fatal(err)
								}
								exe := filepath.Join(dir, "probe")
								ctx, cancel := runtimeOracleStageContext(t)
								command := runtimeOracleNativeCCommand(t, ctx, clang, "-O2", harness, filepath.Join(dir, "llvm.o"), "-o", exe)
								out, err := runtimeOracleCombinedOutput(ctx, command)
								cancel()
								if err != nil {
									t.Fatalf("native C link: %v\n%s", err, out)
								}
								if out, err := exec.Command(exe).CombinedOutput(); err != nil {
									t.Fatalf("native C call: %v\n%s", err, out)
								}
							}
						})
					}
				}
			}
		}
	}
}

func TestNativeCodeEntryRejectsUnprovedContracts(t *testing.T) {
	const source = "TEXT strlen(SB), NOSPLIT|NOFRAME, $0\nJMP imported(SB)\nRET\n"
	for _, arch := range []string{"amd64", "arm64"} {
		for _, tc := range []struct {
			name, src string
			entries   map[string]string
		}{
			{"absent", source, nil},
			{"wrong entry", source, map[string]string{"other": "probe.native_strlen"}},
			{"import collision", source, map[string]string{"strlen": "strlen"}},
			{"unsafe symbol", source, map[string]string{"strlen": "bad\n.globl injected"}},
			{"Go function", strings.ReplaceAll(source, "strlen(SB)", "·strlen(SB)"), map[string]string{"·strlen": "probe.native_strlen"}},
			{"no NOFRAME", strings.ReplaceAll(source, "|NOFRAME", ""), map[string]string{"strlen": "probe.native_strlen"}},
			{"nonzero frame", strings.ReplaceAll(source, "$0", "$16"), map[string]string{"strlen": "probe.native_strlen"}},
			{"Go argument frame", strings.ReplaceAll(source, "$0", "$0-8"), map[string]string{"strlen": "probe.native_strlen"}},
			{"call is not tail", strings.ReplaceAll(source, "JMP", "CALL"), map[string]string{"strlen": "probe.native_strlen"}},
			{"indirect tail", strings.ReplaceAll(source, "imported(SB)", "(R0)"), map[string]string{"strlen": "probe.native_strlen"}},
			{"unknown target", strings.ReplaceAll(source, "imported", "unknown"), map[string]string{"strlen": "probe.native_strlen"}},
			{"target addend", strings.ReplaceAll(source, "imported(SB)", "imported+8(SB)"), map[string]string{"strlen": "probe.native_strlen"}},
			{"import identity shadow", strings.ReplaceAll(source, "strlen(SB)", "imported(SB)"), map[string]string{"imported": "probe.native_strlen"}},
			{"data before tail", strings.ReplaceAll(source, "JMP", "MOVD R0, R1\nJMP"), map[string]string{"strlen": "probe.native_strlen"}},
			{"dead data is not leaf proof", source + "MOVD R0, R1\n", map[string]string{"strlen": "probe.native_strlen"}},
			{"unbound sibling", source + "TEXT other(SB), NOSPLIT|NOFRAME, $0\nJMP imported(SB)\n", map[string]string{"strlen": "probe.native_strlen"}},
			{"duplicate export", source + "TEXT other(SB), NOSPLIT|NOFRAME, $0\nJMP imported(SB)\n", map[string]string{"strlen": "probe.native_strlen", "other": "probe.native_strlen"}},
		} {
			t.Run(arch+"/"+tc.name, func(t *testing.T) {
				opts := nativeCodeEntryOptions("linux", arch)
				opts.CodeEntries = tc.entries
				if asm, _, err := TranslateNativeSource([]byte(tc.src), opts); err == nil || asm != "" {
					t.Fatalf("accepted unproved contract: %v\n%s", err, asm)
				}
				ctx := llvm.NewContext()
				defer ctx.Dispose()
				mod, err := TranslateNativeModule(ctx, []byte(tc.src), opts)
				if err == nil {
					mod.Dispose()
					t.Fatal("accepted unproved code address")
				}
				if !mod.IsNil() {
					t.Fatal("error returned a partial module")
				}
			})
		}
	}
}
