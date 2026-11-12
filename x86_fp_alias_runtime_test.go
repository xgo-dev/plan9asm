//go:build amd64 || (darwin && arm64)

package plan9asm

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestX86FPAliasInitializedLLVMCanary(t *testing.T) {
	llc, clang, triple, prefix := x86FloatAddSubRuntimeTools(t)
	fset := token.NewFileSet()
	syntax, err := parser.ParseFile(fset, "alias.go", "package alias\nfunc Value(x,y uint64) uint64\n", 0)
	if err != nil {
		t.Fatal(err)
	}
	sizes := types.SizesFor("gc", "amd64")
	typed, err := (&types.Config{Sizes: sizes}).Check("alias", fset, []*ast.File{syntax}, nil)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := DeriveGoFuncABI0Signature("Value", typed.Scope().Lookup("Value").(*types.Func), "amd64", sizes)
	if err != nil {
		t.Fatal(err)
	}
	source := "TEXT Value(SB),4,$0-24\nMOVQ x+8(FP),AX\nMOVQ AX,y+16(FP)\nRET\n"
	goAssemblerOracleOutput(t, "amd64", source, "", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	options := Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{"Value": sig}}
	ir, err := Translate(file, options)
	if err != nil {
		t.Fatal(err)
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	module, err := TranslateModuleInContext(ctx, file, options)
	if !module.IsNil() {
		defer module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	goModule, err := translateGoModuleInContext(ctx, GoPackage{Path: "alias", Types: typed, Syntax: []*ast.File{syntax}},
		[]byte(strings.Replace(source, "Value(SB)", "·Value(SB)", 1)), GoModuleOptions{GOARCH: "amd64", Sizes: sizes, TargetTriple: triple})
	if goModule != nil && !goModule.Module.IsNil() {
		defer goModule.Module.Dispose()
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(goModule.Functions) != 1 || goModule.Functions[0].TextSymbol != "·Value" {
		t.Fatalf("actual typed module symbol mapping missing: %#v", goModule.Functions)
	}
	for _, row := range []struct{ name, ir, symbol string }{
		{"text", ir, "Value"}, {"module", module.String(), "Value"}, {"go-module", goModule.Module.String(), goModule.Functions[0].ResolvedSymbol},
	} {
		t.Run(row.name, func(t *testing.T) {
			main := `#include <stdint.h>
#include <stdio.h>
extern uint64_t invoke(uint64_t,uint64_t) __asm__("SYMBOL");
int main(void) {
    static const uint64_t values[] = {0,1,UINT64_C(0x8000000000000000),UINT64_MAX};
    volatile struct { uint64_t before,x,y,after; } inputs;
    for (unsigned i=0;i<4;i++) for (unsigned j=0;j<4;j++) {
        inputs.before=UINT64_C(0x3141592653589793);
        inputs.x=values[i]; inputs.y=values[j];
        inputs.after=UINT64_C(0x2718281828459045);
        uint64_t result=invoke(inputs.x,inputs.y);
        if (result!=values[j] || inputs.x!=values[i] || inputs.y!=values[j] ||
            inputs.before!=UINT64_C(0x3141592653589793) || inputs.after!=UINT64_C(0x2718281828459045)) {
            fprintf(stderr,"alias/canary failed %u/%u\n",i,j); return 1;
        }
    }
    return 0;
}
`
			symbol := row.symbol
			if strings.Contains(triple, "apple") {
				symbol = "_" + symbol // Mach-O's actual external C symbol prefix.
			}
			main = strings.Replace(main, "SYMBOL", symbol, 1)
			compileAndRunRuntimeTestForTarget(t, llc, clang, "fp-alias-"+row.name, triple, row.ir, main, prefix)
		})
	}
}
