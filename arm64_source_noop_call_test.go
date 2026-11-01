package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func arm64SourceNoopCallFixture(move, call, tail, callee string) string {
	return fmt.Sprintf("#include \"textflag.h\"\nTEXT ·Scratch(SB),0,$32904-16\n%s n+0(FP),R1\n%s\n%s\nRET\n%s",
		move, call, tail, callee)
}

func TestARM64SourceNoopCallScratchBoundary(t *testing.T) {
	const noop = "TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0\nRET\n"
	for _, tc := range []struct {
		name, call, tail, callee string
		accepted                 bool
	}{
		{"closed_ret", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", noop, true},
		{"bl_closed_ret", "BL ·Noop(SB)", "MOVD R1,ret+8(FP)", noop, true},
		{"numeric_flags", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "NOSPLIT|NOFRAME", "516", 1), true},
		{"missing_source", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", "", false},
		{"reads_scratch", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "MOVD R27,R0\nRET", 1), false},
		{"stores_scratch", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "MOVD R27,(R0)\nRET", 1), false},
		{"callee_scratch_result", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "MOVD R27,ret+0(FP)\nRET", 1), false},
		{"scratch_result", "CALL ·Noop(SB)", "MOVD R27,ret+8(FP)", noop, false},
		{"scratch_copy", "CALL ·Noop(SB)", "MOVD R27,R5\nMOVD R5,ret+8(FP)", noop, false},
		{"transitive_call", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "CALL ·Other(SB)\nRET", 1) + "TEXT ·Other(SB),NOSPLIT|NOFRAME,$0-0\nRET\n", false},
		{"label_body", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "return_here:\nRET", 1), false},
		{"raw_ret", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "WORD $0xd65f03c0", 1), false},
		{"operand_ret", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "RET", "RET (R30)", 1), false},
		{"missing_nosplit", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "NOSPLIT|NOFRAME", "NOFRAME", 1), false},
		{"missing_args_size", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "$0-0", "$0", 1), false},
		{"missing_noframe", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "NOSPLIT|NOFRAME", "NOSPLIT", 1), false},
		{"hidden_context", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", strings.Replace(noop, "NOSPLIT|NOFRAME", "NOSPLIT|NOFRAME|NEEDCTXT", 1), false},
		{"internal_selector_mismatch", "CALL ·Noop<ABIInternal>(SB)", "MOVD R1,ret+8(FP)", noop, false},
		{"abi0_selector_mismatch", "CALL ·Noop<ABI0>(SB)", "MOVD R1,ret+8(FP)", noop, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, move := range arm64MemoryScratchAuditMoves {
				source := arm64SourceNoopCallFixture(move, tc.call, tc.tail, tc.callee)
				pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch(n uint64) uint64\nfunc Noop()\nfunc Other()\n")
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				resolve := func(name string) string { return strings.TrimPrefix(goStripABISuffix(name), "·") }
				sizes := types.SizesFor("gc", "arm64")
				sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
				if err != nil {
					t.Fatal(err)
				}
				// Missing source must fail even with a plausible complete signature.
				if tc.callee == "" {
					sigs["Noop"] = FuncSig{Name: "Noop", Ret: Void}
				}
				options := Options{Goarch: "arm64", ResolveSym: resolve, Sigs: sigs}
				check := func(api string, err error) {
					if tc.accepted && err != nil || !tc.accepted && !errors.Is(err, ErrProbeNeedsContext) {
						t.Errorf("%s %s accepted=%t: %v", api, move, tc.accepted, err)
					}
				}
				_, err = Translate(file, options)
				check("Translate", err)
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, options)
				if err == nil {
					module.Dispose()
				}
				check("Module", err)
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", ResolveSym: resolve})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				check("GoModule", err)
			}
		})
	}
}

func TestARM64SourceNoopCallUniqueBinding(t *testing.T) {
	const noop = "TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0\nRET\n"
	for _, tc := range []struct {
		name   string
		suffix string
		alias  bool
	}{
		{"duplicate_source", noop, false},
		{"resolved_alias", strings.Replace(noop, "·Noop", "·Other", 1), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := arm64SourceNoopCallFixture("MOVD", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", noop+tc.suffix)
			pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch(n uint64) uint64\nfunc Noop()\nfunc Other()\n")
			ctx := llvm.NewContext()
			bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", ResolveSym: func(name string) string {
					name = strings.TrimPrefix(name, "·")
					if tc.alias && name == "Other" {
						return "Noop"
					}
					return name
				},
			})
			if err == nil {
				bound.Module.Dispose()
			}
			ctx.Dispose()
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ambiguous same-file source acquired a scratch proof: %v", err)
			}
		})
	}
	ctx := llvm.NewContext()
	defer ctx.Dispose()
	pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch(n uint64) uint64\nfunc Noop()\n")
	source := arm64SourceNoopCallFixture("MOVD", "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", noop)
	bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
		GOARCH: "arm64", KeepFunc: func(symbol, _ string) bool { return symbol != "·Noop" },
	})
	if err == nil {
		bound.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("an excluded/cross-file callee borrowed complete same-file source: %v", err)
	}
	t.Run("missing_actual_declaration", func(t *testing.T) {
		pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch(n uint64) uint64\n")
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64"})
		if err == nil {
			bound.Module.Dispose()
		}
		if err == nil || !strings.Contains(err.Error(), "missing Go declaration for asm symbol") {
			t.Fatalf("same-file RET alone supplied a missing actual Go declaration: %v", err)
		}
	})
}

func TestARM64SourceNoopCallRechecksNormalizedSource(t *testing.T) {
	file, err := Parse(ArchARM64, "TEXT ·Leaf(SB),NOSPLIT|NOFRAME,$0-0\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	sig := FuncSig{Name: "Leaf", Ret: Void}
	resolve := func(name string) string { return strings.TrimPrefix(name, "·") }
	proofs := captureARM64SourceNoopCalls(file, resolve, map[string]FuncSig{"Leaf": sig})
	proof, present := proofs["·Leaf"]
	if !present || !proof.matchesNormalized(file.Funcs[0], sig) {
		t.Fatal("complete arbitrary-named source leaf did not receive its exact witness")
	}
	for _, mutate := range []struct {
		name string
		fn   func(*Func)
	}{
		{"symbol", func(fn *Func) { fn.Sym = "·Other" }},
		{"frame", func(fn *Func) { fn.FrameSize = 8 }},
		{"args", func(fn *Func) { fn.ArgSize = 8 }},
		{"flags", func(fn *Func) { fn.Instrs[0].Raw = "TEXT ·Leaf(SB),NOSPLIT,$0-0" }},
		{"equivalent_but_changed_text", func(fn *Func) { fn.Instrs[0].Raw = "TEXT ·Leaf(SB),516,$0-0" }},
		{"changed_raw_ret", func(fn *Func) { fn.Instrs[1].Raw = "RET (R27)" }},
		{"changed_ret_operand", func(fn *Func) { fn.Instrs[1].Args = []Operand{{Kind: OpReg, Reg: "R27"}} }},
		{"physical_ret_identity", func(fn *Func) { fn.Instrs[1].arm64Encoded = true }},
		{"private_entry", func(fn *Func) { fn.arm64PrivateRegisterEntry = true }},
	} {
		t.Run(mutate.name, func(t *testing.T) {
			fn := file.Funcs[0]
			fn.Instrs = append([]Instr(nil), fn.Instrs...)
			mutate.fn(&fn)
			if proof.matchesNormalized(fn, sig) {
				t.Fatal("changed normalized source consumed the original leaf witness")
			}
		})
	}
	for _, changed := range []FuncSig{
		{Name: "Other", Ret: Void},
		{Name: "Leaf", Ret: I64},
		{Name: "Leaf", Ret: Void, Args: []LLVMType{I64}},
		{Name: "Leaf", Ret: Void, Frame: FrameLayout{Params: []FrameSlot{{Type: I64}}}},
		{Name: "Leaf", Ret: Void, ArgRegs: []Reg{"R27"}},
		{Name: "Leaf", Ret: Void, ARM64GoRegisterABI: &ARM64GoRegisterABI{}},
		{Name: "Leaf", Ret: Void, ARM64ClosureABI: &ARM64ClosureABI{}},
	} {
		if proof.matchesNormalized(file.Funcs[0], changed) {
			t.Errorf("changed callable/hidden ABI consumed the original zero-frame witness: %+v", changed)
		}
	}
	// This permission affects only validateSourceScratch. The independent typed
	// GP contract must still reject an otherwise opaque ABI0 call.
	flow := &arm64MachineAvailability{
		used: true, sourceScratch: true, entry: &ARM64GoRegisterABI{},
		blocks: []arm64MachineBlock{{name: "entry", effects: []arm64MachineEffect{
			{register: "R27", unavailable: true},
			{opaque: true, noScratchObserver: true, source: "closed leaf"},
		}}},
	}
	if err := flow.validateSourceScratch(); err != nil {
		t.Fatalf("the exact non-observer did not preserve missing scratch: %v", err)
	}
	if err := flow.validate(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("scratch witness bypassed the independent typed GP call boundary: %v", err)
	}
}

func TestARM64SourceNoopCallScalarFrameLLVM22Objects(t *testing.T) {
	const noop = "TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0\nRET\n"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc unavailable")
	}
	for _, move := range arm64MemoryScratchAuditMoves {
		source := arm64SourceNoopCallFixture(move, "CALL ·Noop(SB)", "MOVD R1,ret+8(FP)", noop)
		arm64PrivateCallGoObject(t, source)
		for _, target := range append(append([]string(nil), arm64TypedNativeTargets...), "aarch64-w64-windows-gnu") {
			for api, ir := range arm64ScalarMemoryIRs(t, source, "func Scratch(n uint64) uint64\nfunc Noop()\n", target) {
				compileLLVMToObject(t, llc, target, fmt.Sprintf("closed-%s-%d.ll", move, api), fmt.Sprintf("closed-%s-%d.o", move, api), ir)
			}
		}
	}
}

func TestARM64SourceNoopCallDoesNotAuthorizeNativeEffects(t *testing.T) {
	const noop = "TEXT ·Noop(SB),NOSPLIT|NOFRAME,$0-0\nRET\n"
	for _, tail := range []string{"SVC $0", "MOVD R27,(R0)", "MOVD R27,R0\nMOVD R0,ret+8(FP)"} {
		source := arm64SourceNoopCallFixture("MOVD", "CALL ·Noop(SB)", tail, noop)
		pkg := mustGoPackage(t, "test/scratch", "package scratch\nfunc Scratch(n uint64) uint64\nfunc Noop()\n")
		ctx := llvm.NewContext()
		bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64"})
		if err == nil {
			bound.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("closed call erased the later source effect %q: %v", tail, err)
		}
	}
}
