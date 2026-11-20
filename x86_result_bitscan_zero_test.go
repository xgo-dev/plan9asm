package plan9asm

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86ScalarBitScanNativeHelperShapesAndTargetBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, typ, word, triple := "MOVQ", "uint64", 8, "x86_64-unknown-linux-gnu"
		if arch == "386" {
			move, typ, word, triple = "MOVL", "uint32", 4, "i386-unknown-linux-gnu"
		}
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				declaration := "func view(x,prior " + typ + ") " + typ + "\n"
				body := fmt.Sprintf("%s x+0(FP),AX\n%s prior+%d(FP),BX\n%s AX,BX\n%s BX,ret+RESULT(FP)", move, move, word, op, move)
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if err != nil {
							t.Fatal(err)
						}
						for _, required := range []string{"noinline noredzone", "asm sideeffect", strings.ToLower(op) + " ${3:", "=r,=r,0,r,r,~{memory}", "and i" + fmt.Sprint(word*8) + " %status, 2261"} {
							if !strings.Contains(ir, required) {
								t.Fatal("complete native prior/status bridge missing", required)
							}
						}
						if strings.Contains(ir, " = call i32 @llvm.cttz.") || strings.Contains(ir, " = call i64 @llvm.cttz.") || strings.Contains(ir, " = call i32 @llvm.ctlz.") || strings.Contains(ir, " = call i64 @llvm.ctlz.") {
							t.Fatal("scan still invents a software zero-input destination")
						}
						for _, target := range []string{"", "aarch64-unknown-linux-gnu", "wasm32-unknown-unknown"} {
							bad, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, target, api)
							if !errors.Is(err, ErrProbeNeedsContext) || bad != "" {
								t.Fatal("native scan guessed an absent/mismatched target", target, err)
							}
						}
					})
				}
			})
		}
	}
}

func TestX86ScalarBitScanNarrowRegisterAliasRetainsUnknownUpperBytes(t *testing.T) {
	for _, family := range []string{"BSF", "BSR"} {
		for _, row := range []struct {
			suffix, argument, result string
			pass                     bool
		}{
			{"W", "uint16", "uint16", true},
			{"W", "uint16", "uint32", false},
			{"W", "uint16", "uint64", false},
			{"L", "uint32", "uint32", true},
			{"L", "uint32", "uint64", false},
			{"Q", "uint64", "uint64", true},
		} {
			t.Run(family+row.suffix+"/"+row.result, func(t *testing.T) {
				declaration := fmt.Sprintf("func view(x %s) %s\n", row.argument, row.result)
				// This existing logical register-entry role defines only the
				// declared AX bytes. It supplies no physical Go caller/frame.
				source := "TEXT ·view<ABIInternal>(SB),4,$0-0\n" + family + row.suffix + " AX,AX\nRET\n"
				x86ResultGPSIMDAdmissionAPIs(t, "amd64", source, declaration, row.pass)
			})
		}
	}
}

func TestX86ScalarBitScanNamespaceAndMissingCompilerBridge(t *testing.T) {
	file, err := Parse(ArchAMD64, "TEXT ·scan(SB),4,$0-0\nBSFW AX,BX\nBSRL AX,BX\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	if got := x86BitScanNamespace(file, "amd64", resolve, map[string]FuncSig{"reserved": {Name: "__plan9asm_bitscan_0_amd64_bsfw"}}); got != "__plan9asm_bitscan_1_" {
		t.Fatal("compiler helper collided with a final LLVM name", got)
	}
	for _, target := range []string{"", "aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"} {
		for _, namespace := range []string{"", "__bound_"} {
			if target == "x86_64-unknown-linux-gnu" && namespace != "" {
				continue // Its complete emitted helper is tested through all APIs.
			}
			var output strings.Builder
			ctx := newX86Ctx(&output, Func{}, FuncSig{Ret: Void}, resolve, nil, "amd64", target, false)
			ctx.bitScanNS = namespace
			if accepted, _, err := ctx.lowerScalarBitScan("BSFW", x86ScalarLaneInstruction(t, "BSFW AX,BX")); !accepted || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("missing bridge/target was inferred from an unowned context", target, namespace, err)
			}
		}
	}
}

func TestX86ResultBitScanZeroPreservesOnlyPriorNumericalBytes(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue // The complete Go grammar has no mode32 qword row.
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				ins := x86ScalarLaneInstruction(t, op+" AX,BX")
				spec := x86ScalarBitScanSpecs[Op(op)]
				_, written, _ := x86ResultGP(BX, int64(spec.bits/8), arch)
				if spec.bits == 32 && arch == "amd64" {
					written = 0xff
				}
				for prior := 0; prior < 256; prior++ {
					state := x86ResultState{flags: x86ByteFlagsAll}
					state.gp[0], state.gp[3] = 0xff, uint8(prior)
					state.canonicalGP[3] = 0xff
					state.pointerGP[3], state.callerAddressGP[3] = true, true
					state.resultAddressGP[3] = x86ResultSlotAddress{start: 8, end: 16, valid: true}
					accepted, known := x86ResultBitScanStep(ins, &state, nil, arch)
					if !accepted || !known || state.gp[3] != uint8(prior) {
						t.Fatalf("zero input must retain exactly prior byte knowledge, not fabricate an output: prior=%02x state=%02x", prior, state.gp[3])
					}
					if state.canonicalGP[3] != 0xff&^written || state.pointerGP[3] || state.callerAddressGP[3] || state.resultAddressGP[3].valid || state.flags != x86ByteFlagZF {
						t.Fatal("a numerical scan retained pointer/canonical/address or nonportable status authority", state)
					}
					branch := x86ScalarLaneInstruction(t, "JNZ good")
					zero, nonzero := x86ResultBitScanEdge(state, branch, 0), x86ResultBitScanEdge(state, branch, 1)
					if zero.gp[3] != uint8(prior) || nonzero.gp[3] != uint8(prior)|written || state.gp[3] != uint8(prior) {
						t.Fatal("scan edge facts contaminated prior/zero/nonzero byte states")
					}
				}
			})
		}
	}
}

func TestX86ScalarBitScanInitializedPriorThreeAPIs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, typ, word := "MOVQ", "uint64", 8
		if arch == "386" {
			move, typ, word = "MOVL", "uint32", 4
		}
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				declaration := "func view(x,prior " + typ + ") " + typ + "\n"
				body := fmt.Sprintf("%s x+0(FP),AX\n%s prior+%d(FP),BX\n%s AX,BX\n%s BX,ret+RESULT(FP)", move, move, word, op, move)
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, true)
			})
		}
	}
}

func TestX86ScalarBitScanUnknownPriorStillNeedsZeroEdgeContext(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		move, typ := "MOVQ", "uint64"
		if arch == "386" {
			move, typ = "MOVL", "uint32"
		}
		for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
			if arch == "386" && strings.HasSuffix(op, "Q") {
				continue
			}
			t.Run(arch+"/"+op, func(t *testing.T) {
				declaration := "func view(x " + typ + ") " + typ + "\n"
				body := move + " x+0(FP),AX\n" + op + " AX,BX\n" + move + " BX,ret+RESULT(FP)"
				source := x86ResultGPSIMDAdmissionSource(t, arch, declaration, body)
				x86ResultGPSIMDAdmissionAPIs(t, arch, source, declaration, false)
			})
		}
	}
}

func TestX86ScalarBitScanOriginalGoHexWordOpsFunctionThreeAPIs(t *testing.T) {
	assembly, err := os.ReadFile(filepath.Join("testdata", "conformance", "amd64", "conformance_amd64.s"))
	if err != nil {
		t.Fatal(err)
	}
	goSource, err := os.ReadFile(filepath.Join("testdata", "conformance", "amd64", "conformance.go"))
	if err != nil {
		t.Fatal(err)
	}
	// This is the complete unchanged original function, not a claim that the
	// entire conformance file or its native/runtime axes have been executed.
	source, err := x86OriginalHexWordOpsSource(assembly)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "conformance.go", goSource, 0)
	if err != nil {
		t.Fatal(err)
	}
	declaration, matches := "", 0
	for _, node := range parsed.Decls {
		fn, ok := node.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "goHexWordOps" || fn.Body != nil {
			continue
		}
		declaration = string(goSource[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]) + "\n"
		matches++
	}
	if matches != 1 {
		t.Fatal("original typed declaration is missing or ambiguous", matches)
	}
	for _, api := range []string{"text", "module", "Go"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-unknown-linux-gnu", api)
			if err != nil || ir == "" {
				t.Fatal("unchanged original goHexWordOps was rejected", err)
			}
		})
	}
}

func x86OriginalHexWordOpsSource(assembly []byte) (string, error) {
	text := string(assembly)
	start := strings.Index(text, "TEXT ·goHexWordOps(SB)")
	if start < 0 {
		return "", fmt.Errorf("original conformance member disappeared")
	}
	end := strings.Index(text[start+1:], "\nTEXT ")
	if end < 0 {
		return "", fmt.Errorf("complete original function boundary disappeared")
	}
	source := text[start : start+1+end]
	// Check only a policy copy; return the complete original bytes unchanged
	// for every actual translation API, including CRLF checkouts.
	policySource := string(normalizeNativeOwnerPolicySource([]byte(source)))
	if !strings.Contains(policySource, "MOVQ $0, AX\n\tBSFW DX, AX") {
		return "", fmt.Errorf("original non-guarded initialized-destination counterexample changed")
	}
	return source, nil
}

func TestX86ScalarBitScanOriginalGoHexWordOpsSourceLineEndings(t *testing.T) {
	const original = "TEXT ·goHexWordOps(SB), NOSPLIT, $0-16\n\tMOVQ $0, AX\n\tBSFW DX, AX\n\tRET\nTEXT ·next(SB), NOSPLIT, $0\n\tRET\n"
	for _, newline := range []string{"\n", "\r\n"} {
		name := "LF"
		if newline == "\r\n" {
			name = "CRLF"
		}
		t.Run(name, func(t *testing.T) {
			assembly := strings.ReplaceAll(original, "\n", newline)
			source, err := x86OriginalHexWordOpsSource([]byte(assembly))
			boundary := strings.Index(assembly, "\nTEXT ·next(SB)")
			if err != nil || source != assembly[:boundary] {
				t.Fatal("Go-equivalent checkout changed original source selection or bytes", err)
			}
			changed := strings.Replace(assembly, "MOVQ $0, AX", "MOVQ $1, AX", 1)
			if _, err := x86OriginalHexWordOpsSource([]byte(changed)); err == nil {
				t.Fatal("changed original zero-input counterexample was accepted")
			}
		})
	}
}
