package plan9asm

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64ABI0TailResultFixture(tuple bool, tail string) (string, string) {
	if tuple {
		return "func Slots(value uint64) (low uint64, high uint64)", fmt.Sprintf(`TEXT ·Slots(SB),516,$0-24
MOVD value+0(FP),R0
MOVD $low+8(FP),R8
MOVD $high+16(FP),R9
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
ADD $7,R0,R11
MOVD R11,(R8)
SUB $3,R0,R12
MOVD R12,(R9)
RET
`, tail)
	}
	return "func Slots(value uint64) (out uint64)", fmt.Sprintf(`TEXT ·Slots(SB),516,$0-16
MOVD value+0(FP),R0
MOVD $out+8(FP),R8
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
ADD $7,R0,R11
MOVD R11,(R8)
RET
`, tail)
}

func arm64ABI0TailResultSignature(t *testing.T, declaration string) (GoPackage, FuncSig) {
	t.Helper()
	source := []byte("package abi0result\n" + declaration + "\n")
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "pkg.go", source, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	info := &types.Info{Defs: make(map[*ast.Ident]types.Object), Uses: make(map[*ast.Ident]types.Object)}
	sizes := types.SizesFor("gc", "arm64")
	config := types.Config{Sizes: sizes}
	typed, err := config.Check("test/abi0result", fset, []*ast.File{syntax}, info)
	if err != nil {
		t.Fatal(err)
	}
	pkg := GoPackage{Path: typed.Path(), Types: typed, Syntax: []*ast.File{syntax},
		SourceSelection: &GoSourceSelection{Fset: fset, TypesInfo: info, Sizes: sizes,
			SelectedGoFiles: []string{"pkg.go"}, GoSources: map[string][]byte{"pkg.go": source}}}
	fn, ok := pkg.Types.Scope().Lookup("Slots").(*types.Func)
	if !ok {
		t.Fatal("missing actual typechecked first-party declaration")
	}
	sig, err := DeriveGoFuncABI0Signature("Slots", fn, "arm64", types.SizesFor("gc", "arm64"))
	if err != nil {
		t.Fatal(err)
	}
	return pkg, sig
}

func arm64ABI0TailResultTranslate(t *testing.T, source, declaration, target, api string, edit func(*FuncSig)) (string, error) {
	t.Helper()
	pkg, sig := arm64ABI0TailResultSignature(t, declaration)
	if edit != nil {
		edit(&sig)
	}
	file, err := Parse(ArchARM64, source)
	if err != nil {
		return "", err
	}
	original := fmt.Sprintf("%#v", file)
	resolve := func(symbol string) string {
		return strings.TrimPrefix(goStripABISuffix(symbol), "·")
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	options := Options{
		Goarch: "arm64", TargetTriple: target, ResolveSym: resolve,
		Sigs: map[string]FuncSig{"Slots": sig},
	}
	if api != "GoModule" {
		options.Sigs, err = BindGoARM64ABI0TailDeclarations(pkg, file, resolve, options.Sigs)
		if err != nil {
			return "", err
		}
	}
	var text string
	switch api {
	case "text":
		text, err = Translate(file, options)
	case "module":
		module, failure := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
			text = module.String()
		}
		err = failure
	case "GoModule":
		goOptions := GoModuleOptions{GOARCH: "arm64", TargetTriple: target, ResolveSym: resolve}
		if edit != nil {
			goOptions.ManualSig = func(name string) (FuncSig, bool) {
				return sig, name == "Slots"
			}
		}
		result, failure := translateGoModuleInContext(ctx, pkg, []byte(source), goOptions)
		if result != nil && !result.Module.IsNil() {
			defer result.Module.Dispose()
			text = result.Module.String()
		}
		err = failure
	default:
		t.Fatalf("unknown fixture API %q", api)
	}
	if fmt.Sprintf("%#v", file) != original {
		t.Fatal("ABI0 result-address rejection changed its original source")
	}
	return text, err
}

// The unmodified original source must first assemble with the selected SDK.
// These objects do not replace the separately initialized numerical oracles.
func TestARM64ABI0TailResultDeclaredContinuationObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, tuple := range []bool{false, true} {
		for _, tail := range []string{"B", "JMP", "RET"} {
			declaration, source := arm64ABI0TailResultFixture(tuple, tail)
			t.Run(fmt.Sprintf("tuple=%t/%s", tuple, tail), func(t *testing.T) {
				requireARM64GoABIInternalObject(t, source)
				for _, target := range []string{
					"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
					"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
				} {
					for _, api := range []string{"text", "module", "GoModule"} {
						t.Run(target+"/"+api, func(t *testing.T) {
							ir, err := arm64ABI0TailResultTranslate(t, source, declaration, target, api, nil)
							if err != nil {
								t.Fatalf("declared ABI0 result continuation needs its own capability: %v", err)
							}
							if strings.Contains(ir, "resultbody") {
								t.Fatal("source continuation acquired a fictitious callee ABI")
							}
							compileLLVMToObject(t, llc, target, "abi0-result.ll", "abi0-result.o", ir)
						})
					}
				}
			})
		}
	}
}

func TestARM64ABI0TailResultCapabilitiesCannotBeBorrowed(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	for name, change := range map[string]func(*FuncSig){
		"manual-frame-copy": func(s *FuncSig) {
			*s = FuncSig{Name: s.Name, Args: append([]LLVMType(nil), s.Args...), Ret: s.Ret,
				Frame: FrameLayout{Params: arm64CopyFPSlots(s.Frame.Params), Results: arm64CopyFPSlots(s.Frame.Results)}}
		},
		"JSON-layout-copy": func(s *FuncSig) {
			encoded, err := json.Marshal(s)
			if err != nil {
				t.Fatal(err)
			}
			var public FuncSig
			if err := json.Unmarshal(encoded, &public); err != nil {
				t.Fatal(err)
			}
			*s = public
		},
		"same-layout-other-declaration": func(s *FuncSig) {
			pkg := mustGoPackage(t, "test/abi0result", "package abi0result\nfunc Other(value uint64) (out uint64)\n")
			fn := pkg.Types.Scope().Lookup("Other").(*types.Func)
			var err error
			*s, err = DeriveGoFuncABI0Signature("Slots", fn, "arm64", types.SizesFor("gc", "arm64"))
			if err != nil {
				t.Fatal(err)
			}
		},
		"missing-result": func(s *FuncSig) { s.Frame.Results = nil },
		"wrong-result-offset": func(s *FuncSig) {
			s.Frame.Results = arm64CopyFPSlots(s.Frame.Results)
			s.Frame.Results[0].Offset++
		},
		"wrong-result-width": func(s *FuncSig) {
			s.Frame.Results = arm64CopyFPSlots(s.Frame.Results)
			s.Frame.Results[0].Type = I32
		},
		"wrong-result-identity": func(s *FuncSig) {
			s.Frame.Results = arm64CopyFPSlots(s.Frame.Results)
			s.Frame.Results[0].Index++
		},
		"wrong-argument":      func(s *FuncSig) { s.Args = []LLVMType{I32} },
		"fake-register-input": func(s *FuncSig) { s.ArgRegs = []Reg{"R0"} },
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				_, err := arm64ABI0TailResultTranslate(t, source, declaration, "aarch64-unknown-linux-gnu", api, change)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("manual/changed signature obtained ABI0 result capability: %v", err)
				}
			})
		}
	}
	_, sig := arm64ABI0TailResultSignature(t, declaration)
	if !reflect.DeepEqual(sig.Frame.Params, []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}) ||
		!reflect.DeepEqual(sig.Frame.Results, []FrameSlot{{Offset: 8, Type: I64, Index: 0, Name: "out", Field: -1}}) {
		t.Fatalf("actual typed first-party ABI0 layout changed: %+v", sig.Frame)
	}
}

func TestARM64ABI0TailResultEmptyArgumentsObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, tail := range []string{"B", "JMP", "RET"} {
		source := fmt.Sprintf(`TEXT ·Slots(SB),516,$0-8
MOVD $out+0(FP),R8
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
MOVD $99,R11
MOVD R11,(R8)
RET
`, tail)
		requireARM64GoABIInternalObject(t, source)
		for _, target := range []string{
			"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl",
			"aarch64-unknown-freebsd", "aarch64-pc-windows-msvc",
		} {
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(tail+"/"+target+"/"+api, func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, source, "func Slots() (out uint64)", target, api, nil)
					if err != nil {
						t.Fatalf("actual empty declaration lost its result capability: %v", err)
					}
					compileLLVMToObject(t, llc, target, "abi0-empty-result.ll", "abi0-empty-result.o", ir)
				})
			}
		}
	}
}

func TestARM64ABI0TailResultOriginalSourceCannotBeChanged(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	for name, mutated := range map[string]string{
		"result-slot-is-parameter": strings.Replace(source, "$out+8(FP)", "$value+0(FP)", 1),
		"changed-TEXT-args":        strings.Replace(source, "$0-16", "$0-24", 1),
		"nonzero-frame":            strings.Replace(source, "$0-16", "$16-16", 1),
		"unbound-native-layout":    source + "TEXT observer<>(SB),516,$0\nADR resultbody<>(SB),R7\nRET\n",
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				_, err := arm64ABI0TailResultTranslate(t, mutated, declaration, "aarch64-unknown-linux-gnu", api, nil)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("changed original source obtained result-slot permission: %v", err)
				}
			})
		}
	}
}

// Each path must produce every byte from actual initialized machine values.
func TestARM64ABI0TailResultAllPathsAndEmptyEntryAreMandatory(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(true, "B")
	for name, replacement := range map[string]string{
		"missing-tuple-result":     "ADD $7,R0,R11\nMOVD R11,(R8)\nRET",
		"partial-result":           "ADD $7,R0,R11\nMOVW R11,(R8)\nMOVD R11,(R9)\nRET",
		"conditional-write":        "CBZ R0,done\nMOVD R0,(R8)\nMOVD R0,(R9)\ndone:\nRET",
		"undefined-GP":             "MOVD R7,(R8)\nMOVD R0,(R9)\nRET",
		"undefined-FP-alias":       "FMOVD F0,R11\nMOVD R11,(R8)\nMOVD R0,(R9)\nRET",
		"mixed-result-pointer":     "CBZ R0,joined\nMOVD R9,R8\njoined:\nMOVD R0,(R8)\nMOVD R0,(R9)\nRET",
		"shifted-result-pointer":   "ADD $4,R8,R8\nMOVD R0,(R8)\nMOVD R0,(R9)\nRET",
		"partial-result-pointer":   "MOVW R8,R8\nMOVD R0,(R8)\nMOVD R0,(R9)\nRET",
		"result-pointer-as-value":  "MOVD R8,(R8)\nMOVD R0,(R9)\nRET",
		"result-pointer-escape":    "MOVD R8,escaped<>(SB)\nMOVD R0,(R8)\nMOVD R0,(R9)\nRET",
		"result-pointer-writeback": "MOVD.P R0,8(R8)\nMOVD R0,(R9)\nRET",
	} {
		at := strings.Index(source, "ADD $7,R0,R11")
		mutated := source[:at] + replacement + "\n"
		if name == "result-pointer-escape" {
			mutated += "GLOBL escaped<>(SB),$8\n"
		}
		requireARM64GoABIInternalObject(t, mutated)
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(name+"/"+api, func(t *testing.T) {
				_, err := arm64ABI0TailResultTranslate(t, mutated, declaration, "aarch64-unknown-linux-gnu", api, nil)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unwritten/escaped/undefined result continuation was admitted: %v", err)
				}
			})
		}
	}
	for _, api := range []string{"text", "module", "GoModule"} {
		t.Run("parameter-is-not-GP-entry/"+api, func(t *testing.T) {
			mutated := strings.Replace(source, "MOVD value+0(FP),R0\n", "", 1)
			requireARM64GoABIInternalObject(t, mutated)
			_, err := arm64ABI0TailResultTranslate(t, mutated, declaration, "aarch64-unknown-linux-gnu", api, nil)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ABI0 ordinary Args supplied an unproved GP entry value: %v", err)
			}
		})
	}
}

// This executes only the initialized first-party original Go program, not LLVM
// or a third-party kernel. It is independent of the proposed capability proof.
func TestCrossLinuxRuntimeMatrixARM64ABI0TailResultOriginalGoNumerics(t *testing.T) {
	_, _, _, runner := arm64FPPairRuntimeTools(t)
	for _, tail := range []string{"B", "JMP", "RET"} {
		for _, tuple := range []bool{false, true} {
			declaration, source := arm64ABI0TailResultFixture(tuple, tail)
			t.Run(fmt.Sprintf("tuple=%t/%s", tuple, tail), func(t *testing.T) {
				check := `out := [3]uint64{0xabc,0xbad,0xdef}
out[1] = Slots(value)
if out[1] != value+7 || out[0] != 0xabc || out[2] != 0xdef {
  panic("ABI0 single result/canary")
}
`
				if tuple {
					check = `out := [4]uint64{0xabc,0xbad,0xbad,0xdef}
out[1],out[2] = Slots(value)
if out[1] != value+7 || out[2] != value-3 || out[0] != 0xabc || out[3] != 0xdef {
  panic("ABI0 tuple result/canary")
}
`
				}
				main := "package main\n" + declaration + `
func main() {
  values := [...]uint64{0,1,3,99,1<<63,1<<63-1,^uint64(0)}
  original := values
  for _,value := range values {
` + check + `
  }
  if values != original { panic("ABI0 original inputs changed") }
}
`
				runARM64LocalRegisterGoOracle(t, source, main, len(runner) != 0)
			})
		}
		t.Run("zero-arguments/"+tail, func(t *testing.T) {
			source := fmt.Sprintf(`TEXT ·Slots(SB),516,$0-8
MOVD $out+0(FP),R8
%s resultbody<>(SB)
TEXT resultbody<>(SB),516,$0
MOVD $99,R11
MOVD R11,(R8)
RET
`, tail)
			runARM64LocalRegisterGoOracle(t, source, `package main
func Slots() (out uint64)
func main() {
  out := [3]uint64{0xabc,0xbad,0xdef}
  out[1] = Slots()
  if out != [3]uint64{0xabc,99,0xdef} { panic("ABI0 zero-argument result/canary") }
}
`, len(runner) != 0)
		})
	}
}
