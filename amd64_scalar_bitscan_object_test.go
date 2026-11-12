package plan9asm

import (
	"fmt"
	"go/types"
	"strings"
	"testing"
)

// Complete source-mode cohorts, not cropped functions. Every supported name
// retains an independent six-status ADD producer, prior destination, full-word
// output, source/destination alias and portable ZF consumer. Q rows have no
// legal mode32 transport; their named grammar rejection is checked separately.
func x86BitScanOriginalObjectFixture(t *testing.T, arch string) (source, declarations string) {
	t.Helper()
	move, typ, word := "MOVQ", "uint64", int64(8)
	if arch == "386" {
		move, typ, word = "MOVL", "uint32", 4
	}
	for _, op := range []string{"BSFW", "BSFL", "BSFQ", "BSRW", "BSRL", "BSRQ"} {
		if arch == "386" && strings.HasSuffix(op, "Q") {
			continue
		}
		for _, role := range []string{"Prior", "Alias", "ZeroFlag"} {
			name := role + op
			declaration := fmt.Sprintf("func %s(x,prior %s,a,b uint32) %s\n", name, typ, typ)
			pkg := mustGoPackage(t, "scans", "package scans\n"+declaration)
			sig, err := DeriveGoFuncABI0Signature(name, pkg.Types.Scope().Lookup(name).(*types.Func), arch, types.SizesFor("gc", arch))
			if err != nil || len(sig.Frame.Params) != 4 || len(sig.Frame.Results) != 1 {
				t.Fatal("complete original typed scan layout unavailable", err)
			}
			if sig.Frame.Params[1].Offset != word || sig.Frame.Params[2].Offset != 2*word || sig.Frame.Params[3].Offset != 2*word+4 || sig.Frame.Results[0].Offset != 2*word+8 {
				t.Fatal("actual Go scan ABI0 field layout changed", sig.Frame)
			}
			destination := "BX"
			if role == "Alias" {
				destination = "AX"
			}
			result := sig.Frame.Results[0].Offset
			body := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s x+0(FP),AX\n%s prior+%d(FP),BX\nMOVL a+%d(FP),CX\nMOVL b+%d(FP),DX\nADDL DX,CX\n%s AX,%s\n", name, result+word, move, move, word, 2*word, 2*word+4, op, destination)
			if role == "ZeroFlag" {
				// Read only portable ZF, then combine its byte into an ordinary
				// numeric result. This grants neither bool nor other FLAGS roles.
				body += fmt.Sprintf("SETEQ DL\nMOVBLZX DL,CX\nSHL%s $%d,CX\nXOR%s CX,%s\n", strings.TrimPrefix(move, "MOV"), word*8-1, strings.TrimPrefix(move, "MOV"), destination)
			}
			body += fmt.Sprintf("%s %s,ret+%d(FP)\nRET\n", move, destination, result)
			source += body
			declarations += declaration
		}
	}
	return source, declarations
}

func TestX86ScalarBitScanCompleteOriginalGoAndLLVMFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete bit-scan objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86BitScanOriginalObjectFixture(t, target.arch)
			count := 18
			if target.arch == "386" {
				count = 12
			}
			if strings.Count(source, "TEXT ·") != count || strings.Count(source, "ADDL DX,CX") != count {
				t.Fatal("complete source/status producer inventory changed")
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete original scan cohort failed", err)
					}
					for _, optimizeIR := range []bool{false, true} {
						input := ir
						if optimizeIR {
							input = x86MulDivRoundOptimize(t, input)
						}
						for _, level := range []string{"-O0", "-O2"} {
							t.Run(fmt.Sprintf("IR_O2=%t/backend%s", optimizeIR, level), func(t *testing.T) {
								x86PackedStringCompileObject(t, llc, target.triple, input, level)
							})
						}
					}
				})
			}
		})
	}
}

func TestX86ScalarBitScanCompleteObjectFixtureNumericalRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source, declarations := x86BitScanOriginalObjectFixture(t, arch)
		// Pure/IR counterpart only. Actual Go and LLVM objects belong to the
		// separate required five-target root and are never inferred here.
		x86ResultGPSIMDAdmissionAPIs(t, arch, source, declarations, true)
	}
}
