package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func x86PartialResultFixture(t *testing.T, arch, typ, move string, boolFirst bool) (string, string, FuncSig, *File) {
	t.Helper()
	results := "n " + typ + ", ok bool"
	valueIndex, boolIndex := 0, 1
	if boolFirst {
		results, valueIndex, boolIndex = "ok bool, n "+typ, 1, 0
	}
	declaration := "func Value(fail uint32) (" + results + ")"
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
	value, boolean := sig.Frame.Results[valueIndex].Offset, sig.Frame.Results[boolIndex].Offset
	write := fmt.Sprintf("%s $42,n+%d(FP)", move, value)
	if strings.HasPrefix(typ, "float") {
		write = fmt.Sprintf("XORPS X0,X0\n%s X0,n+%d(FP)", move, value)
	}
	body := fmt.Sprintf(`MOVL fail+0(FP),AX
TESTL AX,AX
JNZ failure
MOVB $1,ok+%d(FP)
RET
failure:
%s
MOVB $0,ok+%d(FP)
RET`, boolean, write, boolean)
	_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
	return declaration, source, sig, file
}

func TestX86OrdinaryPartialResultsRetainStrictAudit(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range []struct{ typ, move string }{
			{"uint8", "MOVB"}, {"uint16", "MOVW"}, {"uint32", "MOVL"},
			{"float32", "MOVSS"}, {"float64", "MOVSD"}, {"uint64", "MOVQ"},
		} {
			if arch == "386" && row.typ == "uint64" {
				continue // A Q-width GP store is not an IA32 source format.
			}
			for _, boolFirst := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/bool-first=%t", arch, row.typ, boolFirst), func(t *testing.T) {
					declaration, source, sig, file := x86PartialResultFixture(t, arch, row.typ, row.move, boolFirst)
					goAssemblerOracleOutput(t, arch, source, "", true)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "result byte") {
						t.Fatal("the strict audit must retain the actual incomplete-result diagnostic", err)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if err != nil || ir == "" {
								t.Fatal("an independent output audit must not prevent valid ordinary code generation", err)
							}
							x86ResultInitializationObject(t, llc, triple, ir, "partial-result")
						})
					}
				})
			}
		}
	}
}

func TestX86OrdinaryPartialResultsKeepInputAndBoolChecks(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		declaration, source, sig, _ := x86PartialResultFixture(t, arch, "uint32", "MOVL", false)
		unwritten := fmt.Sprintf("MOVL n+%d(FP),AX", sig.Frame.Results[0].Offset)
		for _, row := range []struct{ name, source string }{
			{"undefined-input", strings.Replace(source, "MOVL fail+0(FP),AX", "MOVL BX,AX", 1)},
			{"noncanonical-success-bool", strings.Replace(source, "MOVB $1,ok+", "MOVB $2,ok+", 1)},
			{"noncanonical-later-return", strings.Replace(source, "MOVB $0,ok+", "MOVB $2,ok+", 1)},
			{"unknown-address-read", strings.Replace(source, "MOVL fail+0(FP),AX", "MOVL (SI),AX", 1)},
			{"unknown-address-store", strings.Replace(source, "TESTL AX,AX", "MOVL AX,(SI)\nTESTL AX,AX", 1)},
			{"unwritten-result-read", strings.Replace(source, "MOVL fail+0(FP),AX", unwritten, 1)},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, row.source, declaration, arch, triple, api)
						if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
							t.Fatal("output audit separation must not authorize input bytes, storage, or noncanonical bools", err)
						}
					})
				}
			})
		}
	}
}

func TestX86OrdinaryPartialResultCodegenKeepsCachedAudit(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		_, _, sig, file := x86PartialResultFixture(t, arch, "uint32", "MOVL", false)
		budget := new(x86ResultFlowBudget)
		fn := file.Funcs[0]
		fn.x86ResultFlowBudget = budget
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		ctx := amd64Ctx{sig: sig, fpSourceSig: sig, fpResults: sig.Frame.Results,
			fpScalarSource: fn, goarch: arch, targetTriple: triple}
		if err := ctx.validateMixedBoolResultRole(); err != nil {
			t.Fatal("the ordinary canonical bool contract must allow code generation", arch, err)
		}
		strict, visits := ctx.fpScalarCheckErr, budget.visits
		if strict == nil || !errors.Is(strict, ErrProbeNeedsContext) || visits == 0 {
			t.Fatal("code generation discarded the incomplete-result audit", arch, strict, visits)
		}
		if err := ctx.scalarFPResultInitialized(); err != nil || ctx.fpScalarCheckErr != strict || budget.visits != visits {
			t.Fatal("a repeated consumer changed the audit or reran the source analysis", arch, err)
		}
		if !ctx.fpMixedBoolBytes || ctx.abi0BoolResultByteStorage() {
			t.Fatal("an incomplete result acquired complete-proof storage permissions", arch)
		}
		for _, other := range []error{
			fmt.Errorf("different validation failure: %w", strict),
			errors.Join(strict, errors.New("independent source guard failed")),
		} {
			changed := ctx
			changed.fpScalarCheckErr = other
			if err := changed.scalarFPResultInitialized(); err != other {
				t.Fatal("a wrapped or joined validation error became output-only", arch, err)
			}
		}
	}
}
