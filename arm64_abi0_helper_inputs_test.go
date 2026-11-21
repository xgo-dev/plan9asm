package plan9asm

import (
	"errors"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64BareABI0HelperRegisterInputs(t *testing.T) {
	const declarations = "func Scale(value uint64) (result uint64)\n"
	const source = `TEXT ·Scale(SB),4,$0-16
 MOVD $7,R0
 MOVD $3,R5
 JMP scaled(SB)
TEXT scaled(SB),516,$0
 MOVD value+0(FP),R8
 MULTIPLY
 MOVD R8,result+8(FP)
 RET
`
	manual := func(name string) (FuncSig, bool) {
		return FuncSig{
			Name: name,
			Args: []LLVMType{I64},
			Ret:  I64,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Name: "value", Index: 0, Offset: 0, Type: I64, Field: -1}},
				Results: []FrameSlot{{Name: "result", Index: 0, Offset: 8, Type: I64, Field: -1}},
			},
		}, name == "scaled"
	}
	pkg := mustGoPackage(t, "bitview", "package bitview\n"+declarations)
	for _, row := range []struct {
		name, body, missing string
	}{
		{"hw-argument-overlap", "MUL R0,R8", "R0"},
		{"outside-hw-arguments", "MUL R5,R8", "R5"},
		{"reaching-write", "MOVD $11,R5\n MUL R5,R8", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			assembly := strings.Replace(source, "MULTIPLY", row.body, 1)
			goAssemblerOracleOutput(t, "arm64", assembly, "", true)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					err := arm64BareABI0HelperTestAPI(pkg, assembly, api, manual)
					if row.missing == "" {
						if err != nil {
							t.Fatal(err)
						}
						return
					}
					if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), row.missing+" read") {
						t.Fatalf("missing original %s input must require context, got %v", row.missing, err)
					}
				})
			}
		})
	}
}

func arm64BareABI0HelperTestAPI(pkg GoPackage, assembly, api string, manual func(string) (FuncSig, bool)) error {
	const triple = "aarch64-unknown-linux-gnu"
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "Go" {
		result, err := translateGoModuleInContext(ctx, pkg, []byte(assembly), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: triple, ResolveSym: resolve, ManualSig: manual,
		})
		if result != nil {
			result.Module.Dispose()
		}
		return err
	}
	file, err := Parse(ArchARM64, assembly)
	if err != nil {
		return err
	}
	sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", nil, nil, manual)
	if err != nil {
		return err
	}
	options := Options{Goarch: "arm64", TargetTriple: triple, ResolveSym: resolve, Sigs: sigs}
	if api == "text" {
		_, err := Translate(file, options)
		return err
	}
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		module.Dispose()
	}
	return err
}
