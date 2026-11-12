package plan9asm

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/xgo-dev/llvm"
)

func x86ContinuationResultFixture(t *testing.T, arch string, vectors bool) (string, Options) {
	t.Helper()
	word, size, typ, triple := "Q", 8, "uint64", "x86_64-unknown-linux-gnu"
	if arch == "386" {
		word, size, typ, triple = "L", 4, "uint32", "i386-unknown-linux-gnu"
	}
	source := fmt.Sprintf(`TEXT ·Prepare(SB),$0-0
 LEA%s ·Advance(SB),AX
 MOV%s AX,dispatch<>(SB)
 RET
GLOBL dispatch<>(SB),16,$%d
TEXT ·Evaluate(SB),$0-%d
 MOV%s out+0(FP),DI
 MOV%s value+%d(FP),BX
 LEA%s dispatch<>(SB),SI
 TEST%s BX,BX
 JMP (SI)
TEXT ·Advance(SB),$0-0
 JEQ finished
 ADD%s $1,BX
finished:
 JMP ·Finish(SB)
TEXT ·Finish(SB),$0-0
 MOV%s BX,(DI)
 MOV%s BX,result+%d(FP)
 RET
`, word, word, size, size*3, word, word, size, word, word, word, word, word, size*2)
	if vectors {
		source = strings.Replace(source, " LEA"+word+" dispatch<>(SB),SI", " MOV"+word+" BX,X0\n MOV"+word+" X0,BX\n LEA"+word+" dispatch<>(SB),SI", 1)
	}
	pkg := mustGoPackage(t, "continuationproof", "package p\nfunc Prepare()\nfunc Evaluate(out *"+typ+", value "+typ+") "+typ+"\nfunc Advance()\nfunc Finish()\n")
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	resolve := func(symbol string) string { return strings.TrimPrefix(symbol, "·") }
	sigs, err := goSigsForAsmFile(pkg, file, resolve, arch, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return source, Options{Goarch: arch, TargetTriple: triple, ResolveSym: resolve, Sigs: sigs,
		X86TailGroups: []X86TailGroup{{Root: "·Evaluate", Helpers: []string{"·Advance", "·Finish"}}}}
}

func x86ContinuationResultAPI(t *testing.T, source string, options Options, api string) (string, error) {
	t.Helper()
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		return "", err
	}
	if api == "text" {
		return Translate(file, options)
	}
	var module llvm.Module
	if api == "module" {
		module, err = TranslateModule(file, options)
	} else {
		if api != "owned-module" {
			t.Fatal("unknown Options API", api)
		}
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		module, err = TranslateModuleInContext(ctx, file, options)
	}
	if !module.IsNil() {
		defer module.Dispose()
		return module.String(), err
	}
	return "", err
}

func TestX86ContinuationWholeCFGResultProof(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, vectors := range []bool{false, true} {
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(fmt.Sprintf("%s/vectors-%t/%s", arch, vectors, api), func(t *testing.T) {
					source, options := x86ContinuationResultFixture(t, arch, vectors)
					ir, err := x86ContinuationResultAPI(t, source, options, api)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.Contains(ir, "indirectbr") || !strings.Contains(ir, "blockaddress") || strings.Contains(ir, "define void @Advance") {
						t.Fatal("lost the actual coalesced root CFG")
					}
				})
			}
		}
	}
}

func TestX86ContinuationCodeAddressJoinsRetainOnlyActualRoot(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := "Q"
		if arch == "386" {
			word = "L"
		}
		for _, api := range []string{"text", "module", "owned-module"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				source, options := x86ContinuationResultFixture(t, arch, false)
				original := " TEST" + word + " BX,BX\n JMP (SI)"
				joined := " TEST" + word + " BX,BX\n JEQ chooseFinish\n LEA" + word +
					" ·Advance(SB),CX\n JMP chosen\nchooseFinish:\n LEA" + word + " ·Finish(SB),CX\nchosen:\n JMP CX"
				if !strings.Contains(source, original) {
					t.Fatal("join fixture lost its complete original root")
				}
				source = strings.Replace(source, original, joined, 1)
				if _, err := x86ContinuationResultAPI(t, source, options, api); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
	t.Run("distinct-roots-and-kinds-revoke", func(t *testing.T) {
		flow := new(x86ContinuationFlow)
		state := x86ResultState{continuation: &x86ContinuationResultState{flow: flow, tablesValid: true}}
		state.continuation.gp[0] = x86ContinuationAddress{kind: 2, symbol: "helper", root: "root"}
		for _, address := range []x86ContinuationAddress{
			{kind: 2, symbol: "helper", root: "another-root"},
			{kind: 1, symbol: "helper", root: "root"},
			{},
		} {
			other := state.clone()
			other.continuation.gp[0] = address
			for _, joined := range []x86ResultState{state.intersect(other), other.intersect(state)} {
				if joined.continuation.gp[0] != (x86ContinuationAddress{}) {
					t.Fatal("join borrowed a distinct root or non-code address")
				}
			}
		}
	})
}

func TestX86ContinuationWholeCFGResultRejectsIncomplete(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, size := "Q", 8
		if arch == "386" {
			word, size = "L", 4
		}
		for _, test := range []struct{ name, from, to string }{
			{"missing-result", fmt.Sprintf(" MOV%s BX,result+%d(FP)\n", word, size*2), ""},
			{"partial-result", fmt.Sprintf(" MOV%s BX,result+%d(FP)", word, size*2), fmt.Sprintf(" MOVB BX,result+%d(FP)", size*2)},
			{"unknown-result", fmt.Sprintf(" MOV%s BX,result+%d(FP)", word, size*2), fmt.Sprintf(" MOV%s CX,result+%d(FP)", word, size*2)},
			{"unknown-target", " JMP (SI)", " JMP CX"},
			{"unknown-table-write", " TEST" + word + " BX,BX", " MOV" + word + " $123,(SI)\n TEST" + word + " BX,BX"},
			{"opaque-as-number", " TEST" + word + " BX,BX", " ADD" + word + " SI,BX\n TEST" + word + " BX,BX"},
			{"possible-direct-exit", " JEQ finished", " JEQ missing\n JMP finished\nmissing:\n RET"},
		} {
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					source, options := x86ContinuationResultFixture(t, arch, false)
					if !strings.Contains(source, test.from) {
						t.Fatal("negative mutation does not match the complete source")
					}
					source = strings.Replace(source, test.from, test.to, 1)
					if _, err := x86ContinuationResultAPI(t, source, options, api); !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("incomplete continuation admitted: %v", err)
					}
				})
			}
		}
	}
}

func TestX86ContinuationPreparedIdentityCannotBeCopied(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*File, *Func, *amd64Ctx)
	}{
		{"copy-flow", func(_ *File, fn *Func, c *amd64Ctx) { copy := *fn.x86ContinuationFlow; fn.x86ContinuationFlow = &copy }},
		{"wrong-owner", func(_ *File, fn *Func, c *amd64Ctx) {
			copy := *fn.x86ContinuationFlow
			copy.graph = new(x86ContinuationGraph)
			fn.x86ContinuationFlow = &copy
		}},
		{"changed-instruction", func(_ *File, fn *Func, c *amd64Ctx) {
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			fn.Instrs[1].Raw += " "
		}},
		{"wrong-declaration", func(_ *File, fn *Func, c *amd64Ctx) { c.fpSourceSig.Args = []LLVMType{I64, I64} }},
		{"wrong-target", func(_ *File, fn *Func, c *amd64Ctx) { c.targetTriple = "x86_64-pc-windows-msvc" }},
		{"wrong-ordinal", func(_ *File, fn *Func, c *amd64Ctx) { fn.x86ContinuationFlow.ordinals[0]++ }},
		{"private-encoded-role", func(_ *File, fn *Func, c *amd64Ctx) { fn.x86ContinuationFlow.instructions[0].x86Encoded = true }},
		{"private-segment-role", func(_ *File, fn *Func, c *amd64Ctx) { fn.x86ContinuationFlow.instructions[0].x86SegmentPrefix = 0x64 }},
		{"wrong-edges", func(_ *File, fn *Func, c *amd64Ctx) {
			fn.x86ContinuationFlow.edges[0] = append(fn.x86ContinuationFlow.edges[0], 0)
		}},
		{"wrong-table", func(_ *File, fn *Func, c *amd64Ctx) {
			graph := fn.x86ContinuationFlow.graph
			table := graph.tables["dispatch<>"]
			table.bytes += 8
			graph.tables["dispatch<>"] = table
		}},
		{"changed-original", func(original *File, _ *Func, _ *amd64Ctx) { original.Funcs[0].Instrs[1].Raw += " " }},
	} {
		t.Run(test.name, func(t *testing.T) {
			source, options := x86ContinuationResultFixture(t, "amd64", false)
			original, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := coalesceX86Continuations(original, options)
			if err != nil {
				t.Fatal(err)
			}
			fn := prepared.Funcs[1]
			sig := options.Sigs["Evaluate"]
			c := newX86Ctx(new(strings.Builder), fn, sig, options.ResolveSym, options.Sigs, options.Goarch, options.TargetTriple, false)
			test.change(original, &fn, c)
			c.fpScalarSource = fn
			if err := c.checkLoweredScalarFPResultInitialization(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("copied or changed source role accepted: %v", err)
			}
		})
	}
	t.Run("permanent-revocation", func(t *testing.T) {
		source, options := x86ContinuationResultFixture(t, "amd64", false)
		original, err := Parse(ArchAMD64, source)
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := coalesceX86Continuations(original, options)
		if err != nil {
			t.Fatal(err)
		}
		before := original.Funcs[0].Instrs[1].Raw
		original.Funcs[0].Instrs[1].Raw += " "
		fn := prepared.Funcs[1]
		if fn.x86ContinuationFlow.bind(fn, options.Sigs["Evaluate"], "amd64") {
			t.Fatal("changed original accepted")
		}
		original.Funcs[0].Instrs[1].Raw = before
		if fn.x86ContinuationFlow.bind(fn, options.Sigs["Evaluate"], "amd64") {
			t.Fatal("restoring source revived a failed source role")
		}
	})
}

func TestX86ContinuationStateNeverInitializesOpaqueBits(t *testing.T) {
	source, options := x86ContinuationResultFixture(t, "amd64", false)
	original, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := coalesceX86Continuations(original, options)
	if err != nil {
		t.Fatal(err)
	}
	view := prepared.Funcs[1].x86ContinuationFlow
	state := x86ResultState{continuation: &x86ContinuationResultState{flow: view, tablesValid: true, written: make([]bool, view.graph.cells)}}
	ins := view.instructions[2] // Exact table address, after the two declared FP loads.
	if accepted, known := x86ContinuationResultStep(view.ordinals[2], ins, &state, nil, "amd64"); !known || !accepted {
		t.Fatal("table address role missing")
	}
	if state.gp != [16]uint8{} || state.pointerGP != [16]bool{} || state.callerAddressGP != [16]bool{} || state.flags != 0 {
		t.Fatal("opaque table address granted unrelated numerical/pointer/status facts")
	}
	copy := state.clone()
	copy.continuation.gp[6] = x86ContinuationAddress{}
	copy.continuation.written[0] = true
	if reflect.DeepEqual(copy.continuation, state.continuation) || state.continuation.gp[6].kind == 0 || state.continuation.written[0] {
		t.Fatal("clone aliases mutable opaque state")
	}
	joined := state.intersect(copy)
	if joined.continuation.gp[6].kind != 0 || joined.continuation.written[0] {
		t.Fatal("join invented opaque/table initialization facts")
	}
	for _, change := range []func(*x86ResultState){
		func(s *x86ResultState) { s.continuation = nil },
		func(s *x86ResultState) { s.continuation.flow = new(x86ContinuationFlow) },
		func(s *x86ResultState) { s.continuation.written = nil },
	} {
		other := state.clone()
		change(&other)
		joined := state.intersect(other)
		if !joined.continuation.invalid || joined.continuation.checkReturn() {
			t.Fatal("mismatched source-state join retained authority")
		}
		joined = other.intersect(state)
		if joined.continuation == nil || !joined.continuation.invalid || joined.continuation.checkReturn() {
			t.Fatal("reversed mismatched source-state join retained authority")
		}
	}
}

func TestX86ContinuationTableAndAliasBoundaries(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, size := "Q", 8
		if arch == "386" {
			word, size = "L", 4
		}
		for _, test := range []struct {
			name, from, to string
			accepted       bool
		}{
			{"readonly", ",16,$", ",RODATA|NOPTR,$", false},
			{"unknown-flags", ",16,$", ",UNKNOWN_FLAG,$", false},
			{"tls-storage", ",16,$", ",TLSBSS,$", false},
			{"dupok-storage", ",16,$", ",DUPOK|NOPTR,$", false},
			{"negative-SB-store", "AX,dispatch<>(SB)", fmt.Sprintf("AX,dispatch<>-%d(SB)", size), false},
			{"negative-SB-load", " JMP (SI)", fmt.Sprintf(" MOV%s dispatch<>-%d(SB),AX\n JMP AX", word, size), false},
			{"negative-reg-load", " JMP (SI)", fmt.Sprintf(" JMP -%d(SI)", size), false},
			{"outside-word", " JMP (SI)", fmt.Sprintf(" JMP %d(SI)", size), false},
			{"partial-code-load", " JMP (SI)", " MOVW (SI),AX\n JMP AX", false},
			{"native-alias-store", " JMP (SI)", " MOV" + word + " $0,(DI)\n JMP (SI)", false},
			{"code-escape", " JMP (SI)", " MOV" + word + " (SI),AX\n MOV" + word + " AX,leak(SB)\n JMP AX", false},
			{"table-escape", " JMP (SI)", fmt.Sprintf(" MOV%s SI,result+%d(FP)\n JMP (SI)", word, size*2), false},
			{"base-overwrite", " JMP (SI)", " MOV" + word + " $0,SI\n JMP (SI)", false},
			{"base-partial-overwrite", " JMP (SI)", " MOVB $0,SI\n JMP (SI)", false},
			{"table-copy", " LEA" + word + " dispatch<>(SB),SI", " LEA" + word + " dispatch<>(SB),AX\n MOV" + word + " AX,SI\n MOV" + word + " $0,AX", true},
			{"target-copy", " JMP (SI)", " MOV" + word + " (SI),AX\n MOV" + word + " AX,CX\n MOV" + word + " $0,AX\n JMP CX", true},
		} {
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(arch+"/"+test.name+"/"+api, func(t *testing.T) {
					source, options := x86ContinuationResultFixture(t, arch, false)
					if !strings.Contains(source, test.from) {
						t.Fatal("mutation absent")
					}
					source = strings.Replace(source, test.from, test.to, 1)
					_, err := x86ContinuationResultAPI(t, source, options, api)
					if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatalf("accepted=%t: %v", test.accepted, err)
					}
				})
			}
		}
	}
}

func TestX86ContinuationMemoryBranchReadsActualWord(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		source, options := x86ContinuationResultFixture(t, arch, false)
		for _, api := range []string{"text", "module", "owned-module"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ContinuationResultAPI(t, source, options, api)
				if err != nil {
					t.Fatal(err)
				}
				if arch == "386" && strings.Contains(ir, "load i64, ptr %t") {
					t.Fatal("mode32 indirect memory branch reads eight bytes from a four-byte table cell")
				}
			})
		}
	}
}

func TestX86ContinuationCannotSupplyWASMOrGoModuleContract(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm64-unknown-unknown", "aarch64-unknown-linux-gnu", ""} {
			source, options := x86ContinuationResultFixture(t, arch, false)
			options.TargetTriple = triple
			if ir, err := x86ContinuationResultAPI(t, source, options, "text"); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
				t.Fatalf("%s block-address contract escaped to %q: %v", arch, triple, err)
			}
		}
		source, options := x86ContinuationResultFixture(t, arch, false)
		options.TargetTriple = "i386-unknown-linux-gnu"
		if arch == "386" {
			options.TargetTriple = "x86_64-unknown-linux-gnu"
		}
		if _, err := x86ContinuationResultAPI(t, source, options, "text"); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("mismatched source/target pointer widths accepted", err)
		}
	}
	source, _ := x86ContinuationResultFixture(t, "amd64", false)
	pkg := mustGoPackage(t, "continuationproof", "package p\nfunc Prepare()\nfunc Evaluate(out *uint64,value uint64) uint64\nfunc Advance()\nfunc Finish()\n")
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "amd64", TargetTriple: "x86_64-unknown-linux-gnu"})
	if result != nil && !result.Module.IsNil() {
		result.Module.Dispose()
	}
	if err == nil {
		t.Fatal("an ordinary GoModule call reconstructed the explicit assembly-only group contract")
	}
}

func TestX86ContinuationFinalResolverCannotChangeContract(t *testing.T) {
	for _, change := range []string{"groups", "derived-plan"} {
		t.Run(change, func(t *testing.T) {
			source, options := x86ContinuationResultFixture(t, "amd64", false)
			original, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := coalesceX86Continuations(original, options)
			if err != nil {
				t.Fatal(err)
			}
			graph := prepared.x86ContinuationGraph
			calls := 0
			resolve := options.ResolveSym
			options.ResolveSym = func(symbol string) string {
				calls++
				if calls == len(graph.symbols) {
					if change == "groups" {
						options.X86TailGroups[0].Helpers[0] = "wrong"
					} else {
						graph.flows["·Evaluate"].edges[0] = []int{0}
					}
				}
				return resolve(symbol)
			}
			if err := graph.verify(prepared, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("final resolver changed a contract after its last check", err)
			}
		})
	}
}

func TestX86ContinuationInitializersAndSharedBudget(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word, size := "Q", 8
		if arch == "386" {
			word, size = "L", 4
		}
		for _, complete := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/complete=%t", arch, complete), func(t *testing.T) {
				source, options := x86ContinuationResultFixture(t, arch, false)
				source = strings.Replace(source, fmt.Sprintf("GLOBL dispatch<>(SB),16,$%d", size), fmt.Sprintf("GLOBL dispatch<>(SB),NOPTR,$%d", size*2), 1)
				if complete {
					source = strings.Replace(source, " RET\n", fmt.Sprintf(" LEA%s ·Finish(SB),CX\n MOV%s CX,dispatch<>+%d(SB)\n RET\n", word, word, size), 1)
				}
				_, err := x86ContinuationResultAPI(t, source, options, "text")
				if complete && err != nil || !complete && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("every actual initializer RET must write the complete table: %v", err)
				}
			})
		}
	}
	source, options := x86ContinuationResultFixture(t, "amd64", false)
	original, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := coalesceX86Continuations(original, options)
	if err != nil {
		t.Fatal(err)
	}
	budget := &x86ResultFlowBudget{}
	for index, fn := range prepared.Funcs {
		if index != 0 {
			budget.visits = 16383
		}
		fn.x86ResultFlowBudget = budget
		sig := options.Sigs[options.ResolveSym(fn.Sym)]
		c := newX86Ctx(new(strings.Builder), fn, sig, options.ResolveSym, options.Sigs, options.Goarch, options.TargetTriple, false)
		err := c.checkLoweredScalarFPResultInitialization()
		if index == 0 && (err != nil || budget.visits == 0) {
			t.Fatal("initializer did not consume the request's shared work budget", err)
		}
		if index != 0 && !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("second source flow acquired a fresh visit budget", err)
		}
		if index != 0 {
			break
		}
	}
}

func TestX86ContinuationCodeTableCannotBecomeNumericalStorage(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, read := range []string{
			"MOVB dispatch<>(SB),BX", "MOVW dispatch<>(SB),BX", "MOVL dispatch<>(SB),BX",
			"MOVSS dispatch<>(SB),X1\n MOVL X1,BX",
		} {
			for _, api := range []string{"text", "module", "owned-module"} {
				t.Run(arch+"/"+strings.Fields(read)[0]+"/"+api, func(t *testing.T) {
					source, options := x86ContinuationResultFixture(t, arch, false)
					word := "Q"
					if arch == "386" {
						word = "L"
					}
					source = strings.Replace(source, " TEST"+word+" BX,BX", " "+read+"\n TEST"+word+" BX,BX", 1)
					if output, err := x86ContinuationResultAPI(t, source, options, api); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
						t.Fatal("code-table bytes acquired numerical storage authority", err)
					}
				})
			}
		}
	}
}

func TestX86ContinuationUnknownABIRequiresObservedPointerWidth(t *testing.T) {
	for _, triple := range []string{"x86_64-unknown-linux-gnux32", "x86_64-unknown-unknown", "i386-unknown-linux-musl"} {
		t.Run(triple, func(t *testing.T) {
			arch := "amd64"
			if strings.HasPrefix(triple, "i386") {
				arch = "386"
			}
			source, options := x86ContinuationResultFixture(t, arch, false)
			options.TargetTriple = triple
			if output, err := x86ContinuationResultAPI(t, source, options, "text"); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unknown target ABI borrowed the native code/table word role", err)
			}
		})
	}
}

func TestX86ContinuationUnrelatedFunctionsDoNotBorrowCodeStorage(t *testing.T) {
	for _, operand := range []string{"dispatch<>(SB)", "·dispatch<>(SB)", "alias<>(SB)"} {
		t.Run(operand, func(t *testing.T) {
			source, options := x86ContinuationResultFixture(t, "amd64", false)
			source += "TEXT ·Unrelated(SB),$0-0\n MOVB " + operand + ",AX\n RET\n"
			options.Sigs["Unrelated"] = FuncSig{Ret: Void}
			resolve := options.ResolveSym
			options.ResolveSym = func(symbol string) string {
				if symbol == "·alias<>" {
					return resolve("·dispatch<>")
				}
				return resolve(symbol)
			}
			if output, err := x86ContinuationResultAPI(t, source, options, "text"); output != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("an unrelated unproved function borrowed numerical code-table storage", err)
			}
		})
	}
	source, options := x86ContinuationResultFixture(t, "amd64", false)
	source += "TEXT ·Unrelated(SB),$0-0\n MOVQ $7,AX\n RET\n"
	options.Sigs["Unrelated"] = FuncSig{Ret: Void}
	if _, err := x86ContinuationResultAPI(t, source, options, "text"); err != nil {
		t.Fatal("unrelated ordinary source lost its original consumer", err)
	}
}

func TestX86ContinuationConcurrentPublicRequestsDoNotMutateSource(t *testing.T) {
	source, options := x86ContinuationResultFixture(t, "amd64", true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	before := x86ContinuationSnapshot(file)
	var workers sync.WaitGroup
	failures := make(chan error, 24)
	for worker := 0; worker < 6; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 4; iteration++ {
				if iteration%2 == 0 {
					_, err := Translate(file, options)
					if err != nil {
						failures <- err
					}
				} else {
					ctx := llvm.NewContext()
					module, err := TranslateModuleInContext(ctx, file, options)
					if !module.IsNil() {
						module.Dispose()
					}
					ctx.Dispose()
					if err != nil {
						failures <- err
					}
				}
			}
		}()
	}
	workers.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if !reflect.DeepEqual(before, x86ContinuationSnapshot(file)) || file.x86ContinuationGraph != nil {
		t.Fatal("concurrent request-local coalescing changed the caller's original File")
	}
}
