package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

const arm64PrivateTailCLISource = `TEXT ·Read<ABIInternal>(SB),516,$0-16
B readbody<>(SB)
TEXT ·Other<ABIInternal>(SB),516,$0-16
B readbody<>(SB)
TEXT readbody<>(SB),516,$0
CBZ R0,empty
MOVD (R0),R0
RET
empty:
MOVD $0,R0
RET
`

func TestCompileOneARM64PrivateTailSource(t *testing.T) {
	pkg, input := arm64PrivateCLIPackage(t,
		"package p\nfunc Read(*uint64) uint64\nfunc Other(*uint64) uint64\n", arm64PrivateTailCLISource)
	for _, target := range []struct{ os, triple string }{
		{"darwin", "aarch64-apple-darwin"}, {"linux", "aarch64-unknown-linux-gnu"},
		{"linux", "aarch64-unknown-linux-musl"}, {"freebsd", "aarch64-unknown-freebsd"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.triple, func(t *testing.T) {
			for _, keep := range []bool{false, true} {
				mode := "chunks"
				if keep {
					mode = "complete-object"
				}
				t.Run(mode, func(t *testing.T) {
					config, err := resolveCompileConfig(true, "", keep, 2)
					if err != nil {
						t.Fatal(err)
					}
					config.MaxFunctions, config.MaxInstructions = 1, 1
					config.Context = arm64PrivateCLIContext(t)
					output := filepath.Join(t.TempDir(), "tail.ll")
					if err := compileOne(pkg, plan9asm.ArchARM64, target.os, "arm64", target.triple,
						asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config); err != nil {
						t.Fatal(err)
					}
					files, definitions := []string{output}, 2
					if !keep {
						files = append(files, strings.TrimSuffix(output, ".ll")+".part-0001.ll")
						definitions = 1
					}
					for _, filename := range files {
						ir, err := os.ReadFile(filename)
						if err != nil || strings.Count(string(ir), "define ") != definitions || !strings.Contains(string(ir), "\nbb__5f_5farm64_5ftail_5f") {
							t.Fatalf("CLI %s lost the complete typed continuation: %v", mode, err)
						}
						object := strings.TrimSuffix(filename, ".ll") + ".o"
						info, err := os.Stat(object)
						if keep {
							if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
								t.Fatalf("LLVM22 did not compile the complete tail %s object: %v", target.triple, err)
							}
						} else if !os.IsNotExist(err) {
							t.Fatalf("compiled temporary chunk object was not removed: %v", err)
						}
					}
				})
			}
		})
	}
}

func TestCompileOneARM64PrivateTailCannotHideNativeUse(t *testing.T) {
	source := arm64PrivateTailCLISource + "DATA address<>(SB)/8,$readbody<>+4(SB)\nGLOBL address<>(SB),8,$8\n"
	pkg, input := arm64PrivateCLIPackage(t,
		"package p\nfunc Read(*uint64) uint64\nfunc Other(*uint64) uint64\n", source)
	config, err := resolveCompileConfig(true, "", false, 2)
	if err != nil {
		t.Fatal(err)
	}
	config.MaxFunctions, config.MaxInstructions = 1, 1
	config.Context = arm64PrivateCLIContext(t)
	output := filepath.Join(t.TempDir(), "unsafe.ll")
	err = compileOne(pkg, plan9asm.ArchARM64, "linux", "arm64", "aarch64-unknown-linux-gnu",
		asmTask{PkgPath: pkg.PkgPath, AsmFile: input, OutLL: output}, false, config)
	if !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatalf("a later native address use escaped the complete-file preflight: %v", err)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatalf("failed whole-source proof emitted an earlier chunk: %v", err)
	}
}
