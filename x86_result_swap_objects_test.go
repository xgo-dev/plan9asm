package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86ResultSwapTranslateAPI(t *testing.T, api, source string, pkg GoPackage, arch, triple string) (string, error) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	sig, err := DeriveGoFuncABI0Signature("Value", pkg.Types.Scope().Lookup("Value").(*types.Func), arch, types.SizesFor("gc", arch))
	if err != nil {
		return "", err
	}
	options := Options{Goarch: arch, TargetTriple: triple, Sigs: map[string]FuncSig{"Value": sig},
		ResolveSym: func(symbol string) string { return strings.TrimPrefix(symbol, "·") }}
	if api == "text" {
		return Translate(file, options)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	if api == "module" {
		module, err := TranslateModuleInContext(ctx, file, options)
		if !module.IsNil() {
			defer module.Dispose()
		}
		if err != nil {
			return "", err
		}
		return module.String(), nil
	}
	if api != "Go" {
		t.Fatal("unknown translation API", api)
	}
	result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: arch, TargetTriple: triple, ResolveSym: options.ResolveSym})
	if result != nil && !result.Module.IsNil() {
		defer result.Module.Dispose()
	}
	if err != nil {
		return "", err
	}
	return result.Module.String(), nil
}

func TestX86ResultSwapThreeAPIFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc is required")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			word, move, typ := 8, "MOVQ", "uint64"
			if target.arch == "386" {
				word, move, typ = 4, "MOVL", "uint32"
			}
			body := fmt.Sprintf("%s x+0(FP),AX\n%s y+%d(FP),BX\n", move, move, word) +
				"XCHGB AH,AL\nXCHGB AL,AH\nXCHGB AX,BL\nXCHGW AX,BX\nXCHGW AX,AX\nXCHGL AX,BX\nXCHGL BX,BX\nXCHGL AX,AX\n"
			if target.arch == "amd64" {
				body += "MOVQ $42,R11\nMOVQ $43,R12\nXCHGB R11B,R12\nXCHGW R11,R12\nXCHGL R11,R12\nXCHGQ R11,R12\nXCHGQ AX,BX\nXCHGQ AX,AX\n"
			}
			body += fmt.Sprintf("%s AX,X0\nVPEXTRQ $0,X0,BX\n%s BX,ret0+%d(FP)\nRET", move, move, 2*word)
			pkg, file, sig, source := x86ResultInitializationFixture(t, target.arch, "func Value(x,y "+typ+") "+typ, body)
			goAssemblerOracleOutput(t, target.arch, source, "", true)
			for _, check := range []func(Func, FuncSig, string) error{CheckX86ABI0ResultInitialization, checkX86ScalarFPResultInitialization} {
				if err := check(file.Funcs[0], sig, target.arch); err != nil {
					t.Fatal("whole-source swap scalar result proof", err)
				}
			}
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ResultSwapTranslateAPI(t, api, source, pkg, target.arch, target.triple)
					if err != nil {
						t.Fatal(err)
					}
					x86ResultInitializationObject(t, llc, target.triple, ir, "register-swap-"+api)
				})
			}
		})
	}
}
