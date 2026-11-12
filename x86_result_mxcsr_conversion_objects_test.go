package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func x86MXCSRConversionCompleteObjectFixture(t *testing.T, arch string) (string, string, int) {
	t.Helper()
	var declarations, source strings.Builder
	count := 0
	if arch == "amd64" {
		// Retain the CI counterexample's complete eight original functions.
		goSource, asmSource, _ := x86SignedIntegerFloatFPFixture(t)
		declarations.WriteString(goSource)
		source.WriteString(asmSource)
		count = 8
	} else {
		declarations.WriteString("package oracle\n")
		for _, op := range []string{"CVTSL2SS", "CVTSL2SD", "VCVTSI2SSL", "VCVTSI2SDL", "VCVTSI2SSQ", "VCVTSI2SDQ"} {
			name := strings.ToLower(op)
			declaration := fmt.Sprintf("func %s(a,b,c,d,e,f,g,h byte,csr uint32)(value uint64,flags uint32)\n", name)
			declarations.WriteString(declaration)
			pkg := mustGoPackage(t, "oracle", "package oracle\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil || len(sig.Frame.Params) != 9 || len(sig.Frame.Results) != 2 {
				t.Fatal("complete actual mode32 conversion declaration changed", err)
			}
			value, flags := sig.Frame.Results[0].Offset, sig.Frame.Results[1].Offset
			args, destination := "a+0(FP),X0", "X0"
			if strings.HasPrefix(op, "V") {
				args, destination = "a+0(FP),X0,X1", "X1"
			}
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$8-%d\nSTMXCSR saved-4(SP)\nLDMXCSR csr+8(FP)\n%s %s\n", name, flags+4, op, args)
			if strings.Contains(op, "SS") {
				fmt.Fprintf(&source, "MOVL %s,AX\nMOVL AX,value+%d(FP)\nMOVL $0,value+%d(FP)\n", destination, value, value+4)
			} else {
				fmt.Fprintf(&source, "MOVQ %s,value+%d(FP)\n", destination, value)
			}
			fmt.Fprintf(&source, "STMXCSR flags+%d(FP)\nLDMXCSR saved-4(SP)\nRET\n", flags)
			count++
		}
	}
	for _, load := range []string{"LDMXCSR", "VLDMXCSR"} {
		for _, store := range []string{"STMXCSR", "VSTMXCSR"} {
			name := strings.ToLower(load + store)
			declaration := fmt.Sprintf("func %s(input uint32) uint32\n", name)
			declarations.WriteString(declaration)
			pkg := mustGoPackage(t, "oracle", "package oracle\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil {
				t.Fatal(err)
			}
			result := sig.Frame.Results[0].Offset
			fmt.Fprintf(&source, "TEXT ·%s(SB),4,$8-%d\n%s saved-4(SP)\n%s input+0(FP)\n%s ret+%d(FP)\n%s saved-4(SP)\nRET\n", name, result+4, store, load, store, result, load)
			count++
		}
	}
	return declarations.String(), source.String(), count
}

func TestX86MXCSRConversionCompleteFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete MXCSR/conversion objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			declarations, source, count := x86MXCSRConversionCompleteObjectFixture(t, target.arch)
			wantCount := 12
			if target.arch == "386" {
				wantCount = 10
			}
			if strings.Count(source, "TEXT ·") != count || count != wantCount {
				t.Fatal("complete mode-selected conversion/MXCSR source inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			pkg := mustGoPackage(t, "oracle", declarations)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewPackageAPI(t, source, pkg, target.arch, target.triple, api)
					if err != nil || strings.Count(ir, "define ") != count {
						t.Fatal("complete original conversion/AUTO source failed", err)
					}
					for _, optimized := range []bool{false, true} {
						input := ir
						if optimized {
							input = x86UndefinedTrapOptimizedIR(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimized, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}
