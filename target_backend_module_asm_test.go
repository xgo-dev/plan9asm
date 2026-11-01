package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestTargetBackendModuleAssemblyUsesActualModule(t *testing.T) {
	for _, source := range []struct {
		arch           Arch
		goarch, native string
	}{
		{ArchAMD64, "amd64", "x86_64-unknown-linux-gnu"},
		{ArchAMD64, "386", "i386-unknown-linux-gnu"},
		{ArchARM, "arm", "armv7-unknown-linux-gnueabihf"},
		{ArchARM64, "arm64", "aarch64-unknown-linux-gnu"},
		{ArchWASM, "wasm", "wasm32-unknown-unknown"},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "i386-unknown-linux-gnu", "armv7-unknown-linux-gnueabihf", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", ""} {
			for _, assembly := range []string{"", ".byte 0"} {
				t.Run(source.goarch+"/"+triple+"/"+assembly, func(t *testing.T) {
					ctx := llvm.NewContext()
					defer ctx.Dispose()
					module := ctx.NewModule("actual")
					defer module.Dispose()
					module.SetTarget(triple)
					module.SetInlineAsm(assembly)
					detached := ctx.NewModule("detached")
					defer detached.Dispose()
					detached.SetInlineAsm("cpuid")
					err := validateTranslatedBackend(&File{Arch: source.arch}, Options{Goarch: source.goarch}, module)
					if assembly == "" || triple == source.native {
						if err != nil {
							t.Fatal("empty or matching module assembly rejected", err)
						}
					} else if !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("actual module assembly escaped its source backend", err)
					}
				})
			}
		}
	}
}

func TestTargetBackendWASMDataModuleAssemblyThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	row := targetBackendCase{arch: ArchWASM, goarch: "wasm", body: "RET\nDATA holder<>+0(SB)/8,$external(SB)\nGLOBL holder<>(SB),16,$8"}
	for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-unknown-wasi", "", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, triple, row)
				if strings.HasPrefix(triple, "wasm32-") {
					if err != nil || !strings.Contains(ir, "module asm") {
						t.Fatal("matching WASM DATA lost its actual assembly relocation", err)
					}
					x86ResultInitializationObject(t, llc, triple, ir, "wasm-data-relocation")
				} else if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("WASM DATA module assembly escaped to an unspecified or foreign backend", ir != "", err)
				}
			})
		}
	}
}
