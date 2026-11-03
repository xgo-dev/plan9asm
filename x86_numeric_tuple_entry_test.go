package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Successful lowering may preserve an output-only failure, never turn that
// failure into a complete source/storage proof. The public query is stricter
// than this paired transfer, including for native and x87 inputs.
func x86PartialTupleCodegenControl(t *testing.T, source, declaration, arch, triple, ir string, err error) {
	t.Helper()
	if err != nil || ir == "" {
		t.Fatal("ordinary partial tuple lost code generation", err)
	}
	x86LEAActualTargetGoObject(t, arch, triple, "#include \"textflag.h\"\n"+source)
	x86RequireNumericNativeSourceContext(t, source, declaration, arch)
	pkg := mustGoPackage(t, "partialtuple", "package partialtuple\n"+declaration)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(goStripABISuffix(symbol), "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		fn.x86ResultFlowBudget = new(x86ResultFlowBudget)
		ctx := newX86Ctx(new(strings.Builder), fn, sigs[resolve(fn.Sym)], resolve, sigs, arch, triple, false)
		if err := ctx.scalarFPResultInitialized(); err != nil {
			t.Fatal("paired source inputs did not close before the output-only failure", err)
		}
		strict, visits := ctx.fpScalarCheckErr, fn.x86ResultFlowBudget.visits
		if _, exact := strict.(*x86IncompleteResultError); !exact || visits == 0 || ctx.abi0BoolResultByteStorage() {
			t.Fatal("partial code generation acquired complete-proof storage", strict, visits)
		}
		if err := ctx.scalarFPResultInitialized(); err != nil || ctx.fpScalarCheckErr != strict || fn.x86ResultFlowBudget.visits != visits {
			t.Fatal("a repeated consumer lost the strict cached output failure", err)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
		for _, level := range []string{"-O0", "-O2"} {
			x86PackedStringCompileObject(t, llc, triple, text, level)
		}
	}
}

func TestX86OrdinaryScalarTupleAllPublicRoutesRequireInputs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, initialized := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/initialized=%t", arch, initialized), func(t *testing.T) {
				body := "MOVL $-1,first+0(FP)\nMOVL AX,second+4(FP)\nRET"
				if initialized {
					body = "MOVL $7,AX\n" + body
				}
				declaration := "func Value() (first,second uint32)"
				_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				strict := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
				if initialized && strict != nil || !initialized && !errors.Is(strict, ErrProbeNeedsContext) {
					t.Fatal("the independent source audit changed input availability", strict)
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
						if !initialized {
							if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
								t.Fatal("a public lowering route supplied an undeclared GP input", err)
							}
							return
						}
						if err != nil || ir == "" {
							t.Fatal("the initialized original MOVL forms lost code generation", err)
						}
						x86ScalarFPTupleSpanConstantResult(t, ir, []uint64{0xffffffff, 7})
						for _, level := range []string{"-O0", "-O2"} {
							x86PackedStringCompileObject(t, llc, triple, ir, level)
						}
					})
				}
			})
		}
	}
}
