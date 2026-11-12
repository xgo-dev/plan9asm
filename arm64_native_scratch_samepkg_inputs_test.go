package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// These are actual selected same-package sources and stock Go objects, not
// rewritten diagnostic strings or an SDK-role unit fixture. The new scratch
// observation must not admit undeclared incoming GP or NZCV state.
func TestARM64NativeScratchSamePackageInputsRemainContext(t *testing.T) {
	for _, test := range []struct {
		name, body string
		frame      string
		context    bool
	}{
		{"incoming-r6", "MOVD R6,R1", "0", true},
		{"incoming-closure-r26", "MOVD R26,R1", "0", true},
		{"incoming-nzcv", "B use\nCMP R1,R1\nuse:\nCSEL EQ,R1,R1,R1", "0", true},
		{"incoming-sp-data", "MOVD RSP,R1", "0", true},
		{"incoming-lr-data", "MOVD R30,R1", "0", true},
		{"incoming-bp-data", "MOVD R29,R1", "0", true},
		{"zero-frame-native-stack-load", "MOVD 8(RSP),R1", "0", true},
		{"uninitialized-local-stack-load", "MOVD 16(RSP),R1", "32", true},
		{"partial-local-stack-load", "MOVW R1,16(RSP)\nMOVD 16(RSP),R1", "32", true},
		{"one-path-local-stack-load", "CBZ R1,use\nMOVD R1,16(RSP)\nuse:\nMOVD 16(RSP),R1", "32", true},
		{"ordinary-fp-param-control", "ADD $3,R1", "0", false},
		{"initialized-local-control", "MOVD R1,16(RSP)\nMOVD 16(RSP),R1", "32", false},
		{"initialized-local-pair-control", "MOVD $7,R2\nSTP (R1,R2),16(RSP)\nLDP 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", false},
		{"initialized-local-word-pair-control", "MOVD $7,R2\nSTPW (R1,R2),16(RSP)\nLDPW 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", false},
		{"initialized-local-signed-pair-control", "MOVD $-7,R2\nSTPW (R1,R2),16(RSP)\nLDPSW 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", false},
		{"initialized-local-zero-pair-control", "STP (R1,ZR),16(RSP)\nLDP 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", false},
		{"uninitialized-local-pair", "LDP 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", true},
		{"partial-local-pair", "STPW (R1,R1),16(RSP)\nLDP 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", true},
		{"one-path-local-pair", "CBZ R1,use\nSTP (R1,R1),16(RSP)\nuse:\nLDP 16(RSP),(R3,R4)\nADD R4,R3\nMOVD R3,R1", "32", true},
		{"initialized-local-alias-control", "MOVD R1,16(RSP)\nfirst: next: MOVD 16(RSP),R1", "32", false},
		{"uninitialized-local-alias", "first: next: MOVD 16(RSP),R1", "32", true},
		{"partial-local-alias", "MOVW R1,16(RSP)\nfirst: next: MOVD 16(RSP),R1", "32", true},
		{"one-path-local-alias", "CBZ R1,first\nMOVD R1,16(RSP)\nfirst: next: MOVD 16(RSP),R1", "32", true},
		{"bitfield-unknown-source", "SXTB R6,R1", "0", true},
		{"bitfield-undefined-merge", "BFI $3,R1,$7,R4\nMOVD R4,R1", "0", true},
		{"bitfield-defined-merge", "MOVD $1,R4\nBFI $3,R1,$7,R4\nMOVD R4,R1", "0", false},
		{"bitfield-flags-retained", "CMP $1,R1\nSXTB R1,R4\nCSEL EQ,R1,R4,R1", "0", false},
		{"bitfield-no-incoming-flags", "SXTB R1,R4\nCSEL EQ,R1,R4,R1", "0", true},
	} {
		t.Run(test.name, func(t *testing.T) {
			assembly := strings.Replace(arm64ScratchSelectedSource, "ADD $3,R1", test.body, 1)
			assembly = strings.Replace(assembly, "TEXT ·Value(SB),4,$0-16", "TEXT ·Value(SB),4,$"+test.frame+"-16", 1)
			ctx, pkg, file, options, source := arm64ScratchActualBoundSourceWithAssembly(t,
				"linux", "aarch64-unknown-linux-gnu", assembly)
			layout, layoutErr := source.actualCalleeSignature(ctx, pkg.Path+".Value", "Value")
			if layoutErr != nil {
				t.Fatal(layoutErr)
			}
			for _, body := range source.native[pkg.Path+".Value"] {
				t.Logf("actual original body source=%q words=%08x relocations=%+v", body.source, body.code, body.relocs)
				if !test.context {
					_, physical := source.originalObjectSource(body.source)
					t.Logf("actual admission stages: ABI=%s generated=%v captured=%v R27=%v local-bytes=%v machine-inputs=%v",
						source.abis[pkg.Path+".Value"], source.originalObjectGenerated(body.source), physical,
						arm64ScratchNativeDoesNotAccess(body), arm64ScratchSourceLocalInputs(source.functions[pkg.Path+".Value"], layout),
						arm64ScratchSamePackageInputs(source.functions[pkg.Path+".Value"], layout, body))
				}
			}
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					var err error
					if api != "GoModule" {
						_, err = arm64ScratchSourceAPI(t, pkg, file, options, api)
					} else {
						context := llvm.NewContext()
						defer context.Dispose()
						translation, failure := translateGoModuleInContext(context, pkg, []byte(assembly), GoModuleOptions{
							GOARCH: options.Goarch, TargetTriple: options.TargetTriple, ResolveSym: options.ResolveSym,
							ManualSig: func(name string) (FuncSig, bool) {
								signature, present := options.Sigs[name]
								return signature, present
							},
						})
						if translation != nil && !translation.Module.IsNil() {
							translation.Module.Dispose()
						}
						err = failure
					}
					if test.context && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("actual same-package undeclared machine input acquired scratch-call admission through %s: %v", api, err)
					}
					if !test.context && err != nil {
						t.Fatalf("actual ordinary FP/initialized-local control through %s: %v", api, err)
					}
				})
			}
		})
	}
}
