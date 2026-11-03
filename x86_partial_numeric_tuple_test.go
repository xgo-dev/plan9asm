package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// This fixture copies a typed payload on success and writes only the numeric
// status on failure. Missing payload bytes remain a strict audit failure.
func x86NumericTuplePartialFixture(t *testing.T, arch, typ, move, register string, statusFirst bool) (string, string, FuncSig, *File) {
	t.Helper()
	results := "status int, n " + typ
	statusIndex, valueIndex := 0, 1
	if !statusFirst {
		results, statusIndex, valueIndex = "n "+typ+", status int", 1, 0
	}
	declaration := "func Value(fail uint32, x " + typ + ") (" + results + ")"
	_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
	word := "MOVQ"
	if arch == "386" {
		word = "MOVL"
	}
	body := fmt.Sprintf(`MOVL fail+%d(FP),AX
TESTL AX,AX
JNZ failure
%s x+%d(FP),%s
%s %s,n+%d(FP)
%s $0,status+%d(FP)
RET
failure:
%s $-1,status+%d(FP)
RET`, sig.Frame.Params[0].Offset, move, sig.Frame.Params[1].Offset, register,
		move, register, sig.Frame.Results[valueIndex].Offset,
		word, sig.Frame.Results[statusIndex].Offset, word, sig.Frame.Results[statusIndex].Offset)
	_, file, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
	return declaration, source, sig, file
}

func TestX86OrdinaryNumericTuplePartialResultsThreeAPIs(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, row := range []struct{ typ, move, register string }{
			{"uint32", "MOVL", "AX"}, {"float64", "MOVSD", "X0"},
		} {
			for _, statusFirst := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/%s/status-first=%t", arch, row.typ, statusFirst), func(t *testing.T) {
					declaration, source, sig, file := x86NumericTuplePartialFixture(t, arch, row.typ, row.move, row.register, statusFirst)
					goAssemblerOracleOutput(t, arch, source, "", true)
					strict := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch)
					if _, exact := strict.(*x86IncompleteResultError); !exact || !errors.Is(strict, ErrProbeNeedsContext) {
						t.Fatal("the original missing numerical output audit must remain exact", strict)
					}
					for _, api := range []string{"text", "module", "Go"} {
						t.Run(api, func(t *testing.T) {
							ir, err := x86ScalarFPBitViewAPI(t, source, declaration, arch, triple, api)
							if err != nil || ir == "" {
								t.Fatal("output definedness audit blocked ordinary typed tuple code generation", err)
							}
							for _, level := range []string{"-O0", "-O2"} {
								x86PackedStringCompileObject(t, llc, triple, ir, level)
							}
						})
					}
				})
			}
		}
	}
}

func TestX86OrdinaryNumericTuplePartialResultsKeepInputs(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		declaration, source, sig, _ := x86NumericTuplePartialFixture(t, arch, "uint32", "MOVL", "AX", true)
		initial := fmt.Sprintf("MOVL fail+%d(FP),AX", sig.Frame.Params[0].Offset)
		unwritten := fmt.Sprintf("MOVL n+%d(FP),AX", sig.Frame.Results[1].Offset)
		for _, row := range []struct{ name, source string }{
			{"undefined-input", strings.Replace(source, initial, "MOVL BX,AX", 1)},
			{"unknown-address-read", strings.Replace(source, initial, "MOVL (SI),AX", 1)},
			{"unknown-address-store", strings.Replace(source, "TESTL AX,AX", "MOVL AX,(SI)\nTESTL AX,AX", 1)},
			{"unwritten-result-read", strings.Replace(source, initial, unwritten, 1)},
			{"wrong-extent", strings.Replace(source, fmt.Sprintf("$0-%d", x86NumericTupleArgumentExtent(sig, arch)), fmt.Sprintf("$0-%d", x86NumericTupleArgumentExtent(sig, arch)+1), 1)},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				for _, api := range []string{"text", "module", "Go"} {
					ir, err := x86ScalarFPBitViewAPI(t, row.source, declaration, arch, triple, api)
					if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("missing numerical result authorized input/address/layout facts", api, err)
					}
				}
			})
		}
	}
}

// This local test-only extent mirrors the independently derived slots, not a
// new production role or source proof.
func x86NumericTupleArgumentExtent(sig FuncSig, arch string) int64 {
	var end int64
	for _, slot := range sig.Frame.Results {
		if next := slot.Offset + x86FrameScalarBytes(slot.Type, arch); next > end {
			end = next
		}
	}
	return end
}

func TestX86OrdinaryNumericTuplePartialResultsKeepCachedAudit(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		_, _, sig, file := x86NumericTuplePartialFixture(t, arch, "uint32", "MOVL", "AX", true)
		fn := file.Funcs[0]
		budget := new(x86ResultFlowBudget)
		fn.x86ResultFlowBudget = budget
		ctx := amd64Ctx{sig: sig, fpSourceSig: sig, fpResults: sig.Frame.Results, fpScalarSource: fn, goarch: arch}
		if err := ctx.scalarFPResultInitialized(); err != nil {
			t.Fatal("ordinary numerical tuple code generation rejected", arch, err)
		}
		strict, visits := ctx.fpScalarCheckErr, budget.visits
		if _, exact := strict.(*x86IncompleteResultError); !exact || visits == 0 || ctx.abi0BoolResultByteStorage() {
			t.Fatal("code generation lost its strict failure or acquired complete-proof storage", strict, visits)
		}
		if err := ctx.scalarFPResultInitialized(); err != nil || ctx.fpScalarCheckErr != strict || budget.visits != visits {
			t.Fatal("a repeated consumer discarded the strict cache or reran analysis", err)
		}
		for _, other := range []error{fmt.Errorf("wrapped: %w", strict), errors.Join(strict, errors.New("independent source failure"))} {
			changed := ctx
			changed.fpScalarCheckErr = other
			if err := changed.scalarFPResultInitialized(); err != other {
				t.Fatal("wrapped or joined validation error became output-only", err)
			}
		}
	}
}

func TestX86OrdinaryNumericTuplePartialResultsRoleBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, row := range []struct {
			name   string
			mutate func(*Func, *FuncSig)
		}{
			{"wrong-result-type", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Type = I8 }},
			{"wrong-result-index", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Index = 1 }},
			{"nested-result", func(_ *Func, sig *FuncSig) { sig.Frame.Results[0].Fields = []int{0} }},
			{"overlapping-results", func(_ *Func, sig *FuncSig) { sig.Frame.Results[1].Offset = sig.Frame.Results[0].Offset }},
			{"overlapping-parameters", func(_ *Func, sig *FuncSig) { sig.Frame.Params[1].Offset = sig.Frame.Params[0].Offset }},
			{"unrepresented-argument", func(_ *Func, sig *FuncSig) { sig.Args = append(sig.Args, I32) }},
			{"native-frame", func(fn *Func, _ *FuncSig) { fn.FrameSize = 4 }},
			{"register-entry", func(fn *Func, _ *FuncSig) { fn.Sym += "<ABIInternal>" }},
			{"custom-registers", func(_ *Func, sig *FuncSig) { sig.ArgRegs = []Reg{"AX"} }},
			{"borrowed-bool", func(_ *Func, sig *FuncSig) { sig.x86BorrowedBoolTail = true }},
			{"raw-text", func(fn *Func, _ *FuncSig) { fn.X86RawText = []byte{0xc3} }},
			{"source-stack", func(fn *Func, _ *FuncSig) { fn.x86SourceStack = &x86SourceStackProof{} }},
			{"fixed-local", func(fn *Func, _ *FuncSig) { fn.x86FixedLocal = &x86FixedLocalProof{} }},
			{"coalesced-flow", func(fn *Func, _ *FuncSig) { fn.x86ContinuationFlow = &x86ContinuationFlow{} }},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				_, _, sig, file := x86NumericTuplePartialFixture(t, arch, "uint32", "MOVL", "AX", true)
				fn := file.Funcs[0]
				row.mutate(&fn, &sig)
				ctx := amd64Ctx{sig: sig, fpSourceSig: sig, fpResults: sig.Frame.Results, fpScalarSource: fn, goarch: arch}
				if err := ctx.scalarFPResultInitialized(); !errors.Is(err, ErrProbeNeedsContext) || ctx.fpScalarCheckErr == nil {
					t.Fatal("partial tuple acquired an invalid layout or hidden entry role", err)
				}
			})
		}
	}
}

func TestX86OrdinaryNumericTupleKeepsOtherResultRoles(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, triple := "MOVQ", "x86_64-unknown-linux-gnu"
		if arch == "386" {
			word, triple = "MOVL", "i386-unknown-linux-gnu"
		}
		for _, custom := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/custom-registers=%t", arch, custom), func(t *testing.T) {
				declaration := "func Value(p *byte) (q *byte,n int)"
				move := word
				if custom {
					declaration, move = "func Value(p uint32) (q uint32,n uint32)", "MOVL"
				}
				_, _, sig, _ := x86ResultInitializationFixture(t, arch, declaration, "RET")
				body := fmt.Sprintf("%s p+%d(FP),AX\n%s AX,q+%d(FP)\n%s $7,n+%d(FP)\nRET",
					move, sig.Frame.Params[0].Offset, move, sig.Frame.Results[0].Offset,
					move, sig.Frame.Results[1].Offset)
				pkg, _, sig, source := x86ResultInitializationFixture(t, arch, declaration, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				var manual func(string) (FuncSig, bool)
				if custom {
					sig.ArgRegs = []Reg{AX}
					manual = func(string) (FuncSig, bool) { return sig, true }
				}
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewPackageAPIWithManual(t, source, pkg, arch, triple, api, manual)
						if err != nil || ir == "" {
							t.Fatal("numerical tuple audit changed an independent complete result role", err)
						}
					})
				}
			})
		}
	}
}
