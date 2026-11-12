package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

// LLVM22 actually accepts this spelling as a wasm32 target. A source-based
// or raw-first-field WASM check must not let ARM64 code addresses escape.
func TestTargetBackendReorderedWASMRejectsBlockAddressThreeAPIs(t *testing.T) {
	row := targetBackendCase{arch: ArchARM64, goarch: "arm64", result: true,
		body: "ADR target,R0\nMOVD R0,ret+0(FP)\nRET\ntarget:\nRET"}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := targetBackendRequest(t, api, "unknown-unknown-wasm32", row)
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("LLVM's reordered WASM target received blockaddress", ir != "", err)
			}
		})
	}
}

func TestTargetBackendReorderedWASMPortableThreeAPIsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	const triple = "unknown-unknown-wasm32"
	row := targetBackendCase{arch: ArchAMD64, goarch: "amd64", result: true,
		body: "MOVQ $3,ret+0(FP)\nRET"}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := targetBackendRequest(t, api, triple, row)
			if err != nil || ir == "" || !strings.Contains(ir, "target triple = \""+triple+"\"") {
				t.Fatal("portable source was rejected or had its actual target rewritten", err)
			}
			x86ResultInitializationObject(t, llc, triple, ir, "reordered-wasm-portable")
		})
	}
}
