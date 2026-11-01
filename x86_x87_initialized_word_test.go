package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

// This test-only mode adapter uses the same actual Go declaration derivation
// and three existing translation APIs. It supplies no new source/word role.
func x86X87InitializedWordAPI(t *testing.T, source, declaration, arch, triple, api string, mode X87Mode) (string, error) {
	t.Helper()
	pkg := mustGoPackage(t, "wordinit", "package wordinit\n"+declaration)
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	context := llvm.NewContext()
	defer context.Dispose()
	if api == "Go" {
		translated, err := translateGoModuleInContext(context, pkg, []byte(source), GoModuleOptions{
			GOARCH: arch, TargetTriple: triple, ResolveSym: resolve, X87Mode: mode,
		})
		if translated != nil && !translated.Module.IsNil() {
			defer translated.Module.Dispose()
			return translated.Module.String(), err
		}
		return "", err
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs, X87Mode: mode}
	if api == "text" {
		return Translate(file, options)
	}
	if api != "module" {
		t.Fatal("unknown initialized-word API", api)
	}
	module, err := TranslateModuleInContext(context, file, options)
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func x86X87InitializedWordValue(t *testing.T, ir string, expected uint64) {
	t.Helper()
	for index, input := range []uint16{0, 0xffff, 0x5a5a} {
		name := fmt.Sprintf("WordProbe%d", index)
		probe := fmt.Sprintf("\ndefine i16 @%s() {\n %%r = call i16 @Value(i16 %d)\n ret i16 %%r\n}\n", name, input)
		// Exact logical LLVM values, not hardware FP80, rounding, trapping,
		// original Go execution or a native ABI conformance claim.
		x86ScalarFPNamedConstantResult(t, ir+probe, name, []uint64{expected})
	}
}

func TestX86X87InitializedWordsUseExistingNaturalStorageThreeAPIs(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		result := 8
		if target.arch == "386" {
			result = 4
		}
		for _, op := range []string{"FSTCW", "FSTSW"} {
			kinds := []string{"param", "result"}
			if op == "FSTSW" {
				kinds = append(kinds, "AX")
			}
			for _, kind := range kinds {
				body := "FINIT\n"
				switch kind {
				case "param":
					body += op + " input+0(FP)\nMOVW input+0(FP),AX\n"
					body += fmt.Sprintf("MOVW AX,ret+%d(FP)\n", result)
				case "result":
					body += fmt.Sprintf("%s ret+%d(FP)\n", op, result)
				case "AX":
					body += fmt.Sprintf("FSTSW AX\nMOVW AX,ret+%d(FP)\n", result)
				}
				declaration := "func Value(input uint16) uint16"
				_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body+"RET")
				for _, mode := range []X87Mode{X87Auto, X87Software} {
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(fmt.Sprintf("%s/%s/%s/mode%d/%s", target.triple, op, kind, mode, api), func(t *testing.T) {
							ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, mode)
							if err != nil || ir == "" {
								t.Fatal("explicit initialization lost the complete existing word-store role", err)
							}
							want := uint64(0)
							if op == "FSTCW" {
								want = 0x037f
								if !strings.Contains(ir, "i16 895") {
									t.Fatal("explicit default control-word producer missing from actual IR")
								}
							}
							if mode == X87Software || op == "FSTSW" {
								x86X87InitializedWordValue(t, ir, want)
							} else if !strings.Contains(ir, `asm sideeffect "fninit"`) ||
								!strings.Contains(ir, `asm sideeffect "fnstcw $0"`) {
								t.Fatal("hardware control-word path lost its real initialize/read operations")
							}
							// A hardware FNSTCW result is opaque to LLVM O2. The
							// original object/runtime owner, not constant folding,
							// independently checks that path's expected 0x037f.
						})
					}
				}
			}
		}
	}
}

func TestX86X87ClearOnlyDefinesItsArchitecturalStatusBits(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, prefix, mask, suffix string }{
			{"entry-cleared-bits", "FCLEX\n", "0x80ff", ""},
			{"initialized-full-word", "FINIT\nFCLEX\n", "0xffff", ""},
			{"compare-conditions", "FLD1\nFTST\nFCLEX\n", "0x4500", "FMOVDP F0,F0\n"},
		} {
			result := 8
			if target.arch == "386" {
				result = 4
			}
			body := row.prefix + "FSTSW AX\nANDW $" + row.mask + ",AX\n" +
				fmt.Sprintf("MOVW AX,ret+%d(FP)\n", result) + row.suffix + "RET"
			declaration := "func Value(input uint16) uint16"
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, declaration, body)
			for _, mode := range []X87Mode{X87Auto, X87Software} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, row.name, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, declaration, target.arch, target.triple, api, mode)
						if err != nil || ir == "" {
							t.Fatal("known cleared bits require an independent status-bit proof", err)
						}
						x86X87InitializedWordValue(t, ir, 0)
					})
				}
			}
		}
	}
}

func TestX86X87WordInitializationCannotBorrowUnknownOrForeignRoles(t *testing.T) {
	for _, target := range x86RawReturnTargets {
		for _, row := range []struct{ name, declaration, body string }{
			// Deliberately no extra GP/FP probe: these exact stores must not
			// publish the implementation alloca's initial status/control word.
			{"entry-control", "func Value() uint16", "FSTCW ret+0(FP)\nRET"},
			{"entry-status", "func Value() uint16", "FSTSW ret+0(FP)\nRET"},
			{"cleared-partial-status", "func Value() uint16", "FCLEX\nFSTSW ret+0(FP)\nRET"},
			{"compare-partial-status", "func Value() uint16", "FLD1\nFTST\nFSTSW ret+0(FP)\nFMOVDP F0,F0\nRET"},
			{"clear-does-not-define-conditions", "func Value() uint16", "FCLEX\nFSTSW AX\nANDW $0x4500,AX\nMOVW AX,ret+0(FP)\nRET"},
			{"control-load-is-not-environment-authority", "func Value(input uint16) uint16", "FLDCW input+0(FP)\nFSTCW ret+RESULT(FP)\nRET"},
			{"initialized-unknown-F0", "func Value(gate uint64) float64", "MOVL gate+4(FP),AX\nFINIT\nFMOVDP F0,ret+8(FP)\nRET"},
			{"initialized-unknown-F1", "func Value() uint16", "FINIT\nFLD1\nFADDD F1,F0\nFSTCW ret+0(FP)\nFMOVDP F0,F0\nRET"},
			{"partial-result", "func Value() uint32", "FINIT\nFSTCW ret+0(FP)\nRET"},
			{"parameter-padding", "func Value(input byte) uint16", "FINIT\nFSTCW input+0(FP)\nMOVW $0,ret+RESULT(FP)\nRET"},
			{"partial-parameter", "func Value(input uint32) uint16", "FINIT\nFSTCW input+0(FP)\nMOVW $0,ret+RESULT(FP)\nRET"},
			{"interior-parameter", "func Value(input uint32) uint16", "FINIT\nFSTCW input+1(FP)\nMOVW $0,ret+RESULT(FP)\nRET"},
			{"cross-parameter", "func Value(a,b byte) uint16", "FINIT\nFSTCW a+0(FP)\nMOVW $0,ret+RESULT(FP)\nRET"},
			{"pointer-parameter", "func Value(input *byte) uint16", "FINIT\nFSTCW input+0(FP)\nMOVW $0,ret+RESULT(FP)\nRET"},
		} {
			result := "8"
			if target.arch == "386" {
				result = "4"
			}
			body := strings.ReplaceAll(row.body, "RESULT", result)
			_, _, _, source := x86ResultInitializationFixture(t, target.arch, row.declaration, body)
			for _, mode := range []X87Mode{X87Auto, X87Software} {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(fmt.Sprintf("%s/%s/mode%d/%s", target.triple, row.name, mode, api), func(t *testing.T) {
						ir, err := x86X87InitializedWordAPI(t, source, row.declaration, target.arch, target.triple, api, mode)
						// A hardware FNSTCW reads an actual complete word, not the
						// private alloca's default. A typed FLDCW input likewise
						// writes known control bytes in either mode. Neither fact
						// supplies x87 values, Tag/TOP or an environment extent.
						if row.name == "entry-control" && mode != X87Software || row.name == "control-load-is-not-environment-authority" {
							if err != nil || ir == "" {
								t.Fatal("existing defined control-word path was rejected", err)
							}
							if mode != X87Software {
								x86X87HardwareWordRead(t, ir, 1)
							} else {
								x86X87SoftwareControlRoundTrip(t, ir)
							}
							return
						}
						if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
							t.Fatalf("unknown/foreign word state became NUM: output=%t error=%v", ir != "", err)
						}
					})
				}
			}
		}
	}
}
