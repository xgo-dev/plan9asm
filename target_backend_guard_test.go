package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

type targetBackendCase struct {
	arch   Arch
	goarch string
	body   string
	result bool
	attrs  string
}

// Goarch describes the source's Go rules, not the backend architecture.
// Every entry point must preserve that distinction and the same output guard.
func targetBackendRequest(t *testing.T, api, triple string, row targetBackendCase) (string, error) {
	t.Helper()
	args, declaration := "0", "func backendContract()"
	sig := FuncSig{Name: "backendContract", Ret: Void, Attrs: row.attrs}
	if row.result {
		args, declaration = "8", "func backendContract() uint64"
		sig.Ret = I64
		sig.Frame.Results = []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}
	}
	source := "TEXT backendContract(SB),4,$0-" + args + "\n" + row.body + "\n"
	file, err := Parse(row.arch, source)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: row.goarch, TargetTriple: triple,
		Sigs: map[string]FuncSig{"backendContract": sig}, AnnotateSource: true}
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		mod, err := TranslateModuleInContext(ctx, file, options)
		if mod.IsNil() {
			return "", err
		}
		defer mod.Dispose()
		return mod.String(), err
	}
	pkg := mustGoPackage(t, "backendcontract", "package backendcontract\n"+declaration+"\n")
	bound, err := translateGoModuleInContext(ctx, pkg,
		[]byte(strings.Replace(source, "TEXT backendContract", "TEXT ·backendContract", 1)),
		GoModuleOptions{GOOS: "linux", GOARCH: row.goarch, TargetTriple: triple, AnnotateSource: true})
	if bound == nil {
		return "", err
	}
	defer bound.Module.Dispose()
	return bound.Module.String(), err
}

func TestTargetBackendPortableCrossArchitecture(t *testing.T) {
	for _, row := range []targetBackendCase{
		{arch: ArchARM64, goarch: "arm64", body: "MOVD $3, R0 // blockaddress( is only a source comment\nMOVD R0, ret+0(FP)\nRET", result: true},
		{arch: ArchAMD64, goarch: "amd64", body: "MOVQ $3, ret+0(FP)\nRET", result: true},
	} {
		for _, triple := range []string{"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown", "wasm32-unknown-wasi"} {
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%s/%s", row.goarch, triple, api), func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, triple, row)
					if err != nil || ir == "" {
						t.Fatalf("portable source was confused with backend architecture: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestTargetBackendRejectsWasmBlockAddresses(t *testing.T) {
	for _, op := range []string{"ADR", "ADRP"} {
		row := targetBackendCase{arch: ArchARM64, goarch: "arm64", result: true,
			body: op + " target, R0\nMOVD R0, ret+0(FP)\nRET\ntarget:\nRET"}
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(op+"/"+api+"/native-control", func(t *testing.T) {
				ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", row)
				if err != nil || !strings.Contains(ir, "blockaddress(") {
					t.Fatalf("native control did not retain its real local code address: %v", err)
				}
			})
			for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-unknown-wasi", "wasm64-unknown-unknown"} {
				t.Run(op+"/"+api+"/"+triple, func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, triple, row)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("WASM received a local code address: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}

func TestTargetBackendSVENeedsAArch64(t *testing.T) {
	// Cover native intrinsics, generic scalable operations and raw decoding.
	// A guard based only on opcode spelling or inferred attributes is incomplete.
	for _, body := range []string{
		"CNTB R0\nRET",
		"WORD $0x0420e3ea\nRET", // CNTB X10.
		"ZSUB Z1.S, Z2.S, Z3.S\nRET",
		"WORD $0x05203800\nRET", // DUP Z0.B, W0: generic scalable IR.
		"ZMATCH Z0.B, Z1.B, P0.Z, P2.B\nRET",
	} {
		for _, attrs := range []string{"", "nounwind"} {
			row := targetBackendCase{arch: ArchARM64, goarch: "arm64", body: body, attrs: attrs}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(fmt.Sprintf("%s/%s/%s/native-control", body, attrs, api), func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, "aarch64-unknown-linux-gnu", row)
					if err != nil || ir == "" {
						t.Fatalf("native SVE control rejected: output=%t err=%v", ir != "", err)
					}
				})
				for _, triple := range []string{"", "x86_64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", body, attrs, api, triple), func(t *testing.T) {
						ir, err := targetBackendRequest(t, api, triple, row)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatalf("SVE escaped to a non-AArch64 or unspecified backend: output=%t err=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}

func TestTargetBackendRejectsSourceGoarchMismatch(t *testing.T) {
	for _, row := range []targetBackendCase{
		{arch: ArchARM64, goarch: "wasm", body: "RET"},
		{arch: ArchARM64, goarch: "amd64", body: "RET"},
		{arch: ArchAMD64, goarch: "arm64", body: "RET"},
		{arch: ArchAMD64, goarch: "wasm", body: "RET"},
	} {
		for _, api := range []string{"text", "module"} {
			for _, triple := range []string{"aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
				t.Run(fmt.Sprintf("%s/%s/%s/%s", row.arch, row.goarch, triple, api), func(t *testing.T) {
					ir, err := targetBackendRequest(t, api, triple, row)
					if ir != "" || err == nil {
						t.Fatalf("source architecture accepted conflicting Goarch: output=%t err=%v", ir != "", err)
					}
				})
			}
		}
	}
}
