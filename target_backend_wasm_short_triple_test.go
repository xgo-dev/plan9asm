package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestTargetBackendWASMShortTargetsThreeAPIsActualObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	row := targetBackendCase{arch: ArchWASM, goarch: "wasm",
		body: "RET\nDATA holder<>+0(SB)/8,$external(SB)\nGLOBL holder<>(SB),16,$8"}
	for _, target := range []struct {
		triple string
		native bool
	}{
		{"wasm32-wasi", true},
		{"wasm32--wasi", true},
		{"wasm32", true},
		{"wasm32-unknown-wasi", true},
		{"wasm32-notreal", true},
		{"unknown-unknown-wasm32", true},
		{"", false},
		{"x86_64-linux-gnu", false},
		{"aarch64-linux-gnu", false},
		{"wasm64-wasi", false},
		{"wasm32bad-wasi", false},
		{"xwasm32-wasi", false},
		{"wasm32x-wasi", false},
	} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(target.triple+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, target.triple, row)
				if !target.native {
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("unspecified, foreign or wrong-width target accepted real WASM module assembly", ir != "", err)
					}
					return
				}
				if err != nil || !strings.Contains(ir, "module asm") ||
					!strings.Contains(ir, "target triple = \""+target.triple+"\"") {
					t.Fatal("valid LLVM WASM target was rejected, rewritten or lost its real relocation", err)
				}
				x86ResultInitializationObject(t, llc, target.triple, ir, "wasm-short-target")
			})
		}
	}
}

func TestTargetBackendWASMShortTargetsKeepSourceModeBoundary(t *testing.T) {
	for _, goarch := range []string{"386", "amd64", "arm64"} {
		for _, api := range []string{"text", "module"} {
			t.Run(goarch+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, "wasm32-wasi",
					targetBackendCase{arch: ArchWASM, goarch: goarch, body: "RET"})
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("normalized target supplied a conflicting source Goarch", ir != "", err)
				}
			})
		}
	}
}

func TestTargetBackendWASMShortTargetsKeepBlockAddressBoundary(t *testing.T) {
	row := targetBackendCase{arch: ArchARM64, goarch: "arm64", result: true,
		body: "ADR target,R0\nMOVD R0,ret+0(FP)\nRET\ntarget:\nRET"}
	for _, triple := range []string{"wasm32-wasi", "wasm32--wasi", "wasm32"} {
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(triple+"/"+api, func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, triple, row)
				if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("short WASM target received blockaddress", ir != "", err)
				}
			})
		}
	}
}
