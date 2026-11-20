package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"golang.org/x/tools/go/packages"
)

const arm64ABI0TailCLIAssembly = `TEXT ·Slots(SB),516,$0-16
MOVD value+0(FP),R0
MOVD $out+8(FP),R8
B resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
ADD $7,R0,R11
MOVD R11,(R8)
RET
`

func arm64ABI0TailCLIFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":    "module example.com/abi0tail\n\ngo 1.20\n",
		"p.go":      "package p\nfunc Slots(value uint64) (out uint64)\n",
		"p_arm64.s": arm64ABI0TailCLIAssembly,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestCompileOneARM64ABI0TailWholeSourceGuards(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	for _, name := range []string{"no-load", "wrong-target", "overlay", "bodyful", "late-native-use", "late-DATA-use"} {
		t.Run(name, func(t *testing.T) {
			dir := arm64ABI0TailCLIFixture(t)
			t.Chdir(dir)
			pkgs, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("actual Go selection: packages=%d error=%v", len(pkgs), err)
			}
			config, err := resolveCompileConfig(true, "", false, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/arm64", nil)
			selection := config.x86CallerSelections[pkgs[0]]
			source := arm64ABI0TailCLIAssembly
			switch name {
			case "no-load":
				config.x86CallerSelections = nil
			case "wrong-target":
				selection.target = "linux/amd64"
			case "overlay":
				selection.env = append(selection.env, "GOFLAGS=-overlay=unbound.json")
			case "bodyful":
				if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte("package p\nfunc Slots(value uint64) (out uint64) { return value }\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "late-native-use":
				source += "TEXT observer<>(SB),516,$0\nADR resultbody<>(SB),R7\nRET\n"
			case "late-DATA-use":
				source += "DATA pointer<>(SB)/8,$resultbody<>(SB)\nGLOBL pointer<>(SB),$8\n"
			}
			input := filepath.Join(dir, "p_arm64.s")
			if err := os.WriteFile(input, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "unsafe.ll")
			err = compileOne(pkgs[0], plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: input, OutLL: output}, false, config)
			if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("unbound/changed source role obtained LLVM permission: %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatalf("rejected original source emitted LLVM: %v", err)
			}
		})
	}
}

func TestCompileOneARM64ABI0TailCompleteAndChunks(t *testing.T) {
	dir := arm64ABI0TailCLIFixture(t)
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	declaration := "package p\nfunc Slots(value uint64) (out uint64)\nfunc Other(value uint64) (out uint64)\n"
	root := arm64ABI0TailCLIAssembly[:strings.Index(arm64ABI0TailCLIAssembly, "TEXT resultbody")]
	source := arm64ABI0TailCLIAssembly + strings.Replace(root, "·Slots", "·Other", 1)
	for name, data := range map[string]string{"p.go": declaration, "p_arm64.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	requireARM64PrivateCLIOriginalObject(t, source)
	for _, target := range []struct{ os, triple string }{
		{"darwin", "aarch64-apple-darwin"}, {"linux", "aarch64-unknown-linux-gnu"},
		{"linux", "aarch64-unknown-linux-musl"}, {"freebsd", "aarch64-unknown-freebsd"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		pkgs, err := loadPkgs(target.os, "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
		if err != nil || len(pkgs) != 1 {
			t.Fatalf("actual complete Go selection: packages=%d error=%v", len(pkgs), err)
		}
		for _, keep := range []bool{false, true} {
			mode := "chunks"
			if keep {
				mode = "complete-object"
			}
			t.Run(target.triple+"/"+mode, func(t *testing.T) {
				config, err := resolveCompileConfig(true, "", keep, 2)
				if err != nil {
					t.Fatal(err)
				}
				config.Context = arm64PrivateCLIContext(t)
				config.MaxFunctions, config.MaxInstructions = 1, 1
				config.x86CallerSelections = captureX86CallerSelections(pkgs, target.os+"/arm64", nil)
				output := filepath.Join(t.TempDir(), "tails.ll")
				if err := compileOne(pkgs[0], plan9asm.ArchARM64, target.os, "arm64", target.triple,
					asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: filepath.Join(dir, "p_arm64.s"), OutLL: output}, false, config); err != nil {
					t.Fatal(err)
				}
				outputs, definitions := []string{output}, 2
				if !keep {
					outputs = append(outputs, strings.TrimSuffix(output, ".ll")+".part-0001.ll")
					definitions = 1
				}
				for _, filename := range outputs {
					data, err := os.ReadFile(filename)
					if err != nil || strings.Count(string(data), "define ") != definitions {
						t.Fatalf("bounded complete source lost a root: %v", err)
					}
					object := strings.TrimSuffix(filename, ".ll") + ".o"
					info, err := os.Stat(object)
					if keep {
						if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
							t.Fatalf("no complete LLVM22 object: %v", err)
						}
					} else if !os.IsNotExist(err) {
						t.Fatalf("compiled private chunk object was not released: %v", err)
					}
				}
			})
		}
	}
}

func TestCompileOneARM64ABI0TailSourcePostGuard(t *testing.T) {
	for _, change := range []string{"Go", "ASM", "selection"} {
		t.Run(change, func(t *testing.T) {
			dir := arm64ABI0TailCLIFixture(t)
			t.Chdir(dir)
			t.Setenv("GOWORK", "off")
			t.Setenv("GOENV", "off")
			t.Setenv("GOTOOLCHAIN", "local")
			t.Setenv("CGO_ENABLED", "0")
			t.Setenv("GOFLAGS", "")
			pkgs, err := loadPkgs("linux", "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("actual ordinary Go selection: %v", err)
			}
			config, err := resolveCompileConfig(true, "", true, 2)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			config.x86CallerSelections = captureX86CallerSelections(pkgs, "linux/arm64", nil)
			input := filepath.Join(dir, "p_arm64.s")
			expanded, err := readAsmSource(input, asmSourceRoot(pkgs[0], input))
			if err != nil {
				t.Fatal(err)
			}
			bound, err := loadARM64ABI0TailSource(pkgs[0], input, expanded, "linux/arm64", nil, config)
			if err != nil {
				t.Fatal(err)
			}
			if bound.actual == pkgs[0] || bound.actual.Types == pkgs[0].Types {
				t.Fatal("actual typed recheck was not independently retained")
			}
			if change == "selection" {
				pkgs[0].Imports = map[string]*packages.Package{"unbound": nil}
			} else {
				filename := input
				if change == "Go" {
					filename = filepath.Join(dir, "p.go")
				}
				if err := os.WriteFile(filename, []byte("// replaced actual input\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := bound.verify(config.Context, nil, nil); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("changed actual source/selection survived final consumer: %v", err)
			}
		})
	}
}

func TestCompileOneARM64ABI0TailActualDeclaration(t *testing.T) {
	dir := arm64ABI0TailCLIFixture(t)
	t.Chdir(dir)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOENV", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("CGO_ENABLED", "0")
	t.Setenv("GOFLAGS", "")
	t.Setenv("GOMAXPROCS", "2")
	requireARM64PrivateCLIOriginalObject(t, arm64ABI0TailCLIAssembly)
	for _, target := range []struct{ os, triple string }{
		{"darwin", "aarch64-apple-darwin"}, {"linux", "aarch64-unknown-linux-gnu"},
		{"linux", "aarch64-unknown-linux-musl"}, {"freebsd", "aarch64-unknown-freebsd"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			pkgs, err := loadPkgs(target.os, "arm64", []string{"."}, nil, "example.com/abi0tail", true, false)
			if err != nil || len(pkgs) != 1 {
				t.Fatalf("actual ordinary Go package selection: packages=%d error=%v", len(pkgs), err)
			}
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.Context = arm64PrivateCLIContext(t)
			config.x86CallerSelections = captureX86CallerSelections(pkgs, target.os+"/arm64", nil)
			output := filepath.Join(t.TempDir(), "tail.ll")
			err = compileOne(pkgs[0], plan9asm.ArchARM64, target.os, "arm64", target.triple,
				asmTask{PkgPath: pkgs[0].PkgPath, AsmFile: filepath.Join(dir, "p_arm64.s"), OutLL: output}, false, config)
			if err != nil {
				t.Fatalf("complete actual ABI0 declaration did not reach the LLVM object: %v", err)
			}
			ir, err := os.ReadFile(output)
			if err != nil || strings.Count(string(ir), "define ") != 1 || strings.Contains(string(ir), "resultbody") {
				t.Fatalf("source tail acquired a fictitious callable helper: %v", err)
			}
			object := strings.TrimSuffix(output, ".ll") + ".o"
			if info, err := os.Stat(object); err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 produced no %s object: %v", target.triple, err)
			}
		})
	}
}
