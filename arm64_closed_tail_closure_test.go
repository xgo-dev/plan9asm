package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ClosedTailClosure(t *testing.T, body, target, api string) (string, error) {
	t.Helper()
	const name = "test/closure.Capture"
	pkg := mustGoPackage(t, "test/closure", "package closure\nfunc Capture(*uint64) uint64\n")
	source := "TEXT ·Capture<ABIInternal>(SB),516,$0-16\nMOVD 8(R26),R2\nB body<>(SB)\nTEXT body<>(SB),516,$0\n" + body + "\nRET\n"
	requireARM64ClosureGoObject(t, source)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	resolve := func(symbol string) string {
		return "test/closure." + strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	entry := *file
	entry.Funcs = append([]Func(nil), file.Funcs[:1]...)
	entry.Funcs[0].Instrs = entry.Funcs[0].Instrs[:1]
	sigs, err := goSigsForAsmFile(pkg, &entry, resolve, "arm64", nil, nil, nil)
	if err != nil {
		return "", err
	}
	abi := arm64TestClosureABI(name, target)
	sig := sigs[name]
	sig.ARM64ClosureABI = &abi
	sigs[name] = sig
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	options := Options{Goarch: "arm64", TargetTriple: target, ResolveSym: resolve, Sigs: sigs}
	switch api {
	case "text":
		return Translate(file, options)
	case "module":
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			if err == nil {
				return module.String(), nil
			}
		}
		return "", err
	case "GoModule":
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve,
			ARM64ClosureABIs: map[string]ARM64ClosureABI{name: abi},
		})
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
			if err == nil {
				return result.Module.String(), nil
			}
		}
		return "", err
	default:
		t.Fatalf("unknown test API %q", api)
		return "", nil
	}
}

func TestARM64ClosedTailClosureReadOnlyCarrier(t *testing.T) {
	llc, _, _ := findLlcAndClang(t)
	for _, tc := range []struct{ name, body string }{
		{"scalar", "MOVD (R0),R0"},
		{"pair", "LDP (R0),(R0,R1)"},
		{"floating", "FMOVD (R0),F0\nFMOVD F0,R0"},
		{"structure", "VLD1 (R0),[V0.D2]\nVMOV V0.D[0],R0"},
		{"scalar-writeback", "MOVD.P 8(R0),R1\nMOVD R1,R0"},
		{"pair-writeback", "LDP.P 16(R0),(R1,R2)\nMOVD R1,R0"},
		{"structure-writeback", "VLD1.P (R0),[V0.D2]\nVMOV V0.D[0],R0"},
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(tc.name+"/"+api, func(t *testing.T) {
				ir, err := arm64ClosedTailClosure(t, tc.body, "aarch64-unknown-linux-gnu", api)
				if err != nil {
					t.Fatalf("closed source-only read cannot mutate or expose its immutable carrier: %v", err)
				}
				compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "closure-read.ll", "closure-read.o", ir)
			})
		}
	}
}

func TestARM64ClosedTailClosureCannotAliasCarrierWrites(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"scalar-store", "MOVD R2,(R0)\nMOVD $7,R0"},
		{"pair-store", "STP (R2,R2),(R0)\nMOVD $7,R0"},
		{"floating-store", "FMOVD R2,F0\nFMOVD F0,(R0)\nMOVD $7,R0"},
		{"structure-store", "VDUP R2,V0.D2\nVST1 [V0.D2],(R0)\nMOVD $7,R0"},
		{"hidden-read", "MOVD 8(R26),R0"},
		{"hidden-copy", "MOVD R26,R0"},
		{"hidden-index", "MOVD (R0)(R26),R0"},
		{"hidden-destination", "MOVD (R0),R26\nMOVD $7,R0"},
		{"address-materialization", "MOVD $8(R0),R0"},
		{"unregistered-memory-row", "LDAR (R0),R0"},
		{"undefined-data-base", "MOVD (R9),R0"},
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(tc.name+"/"+api, func(t *testing.T) {
				_, err := arm64ClosedTailClosure(t, tc.body, "aarch64-unknown-linux-gnu", api)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("ordinary pointer inputs acquired an unproved immutable-carrier alias promise: %v", err)
				}
			})
		}
	}
}
