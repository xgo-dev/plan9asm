package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/llvm"
)

func TestARM64TypedCallCodeProvenanceComesFromTransport(t *testing.T) {
	for _, tc := range []struct {
		name, argument, escaped string
		known, proof, frame     bool
		wantContinuation        bool
	}{
		{name: "private_typed", known: true, proof: true, frame: true},
		{name: "actual_code_argument", known: true, proof: true, frame: true, argument: "label:argument"},
		{name: "already_escaped_code", known: true, proof: true, frame: true, escaped: "label:escaped"},
		{name: "unknown_target", proof: true, frame: true, wantContinuation: true},
		{name: "zero_default", known: true, frame: true, wantContinuation: true},
		{name: "no_source_frame", known: true, proof: true, wantContinuation: true},
		{name: "escaped_private_frame", known: true, proof: true, frame: true, escaped: "sp:16", wantContinuation: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sig := FuncSig{Name: "callee", Args: []LLVMType{Ptr}, Ret: I64,
				Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}},
			}
			state := &arm64ControlState{
				unexposedSP: tc.proof,
				regs: map[Reg]arm64ControlValue{
					SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R30": arm64ControlFromMap(map[string]bool{"label:continuation": true}),
					"R19": arm64ControlFromMap(map[string]bool{"label:source_witness": true}),
				},
				memory: map[string]arm64ControlValue{
					"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}), "sp:8": arm64ControlFromMap(map[string]bool{tc.argument: true}), "fp:0": arm64ControlExternal(),
				},
			}
			if tc.escaped != "" {
				state.escaped = arm64ControlFromMap(map[string]bool{tc.escaped: true})
			}
			ctx := &arm64Ctx{resolve: func(s string) string { return strings.TrimSuffix(s, "(SB)") },
				sigs: map[string]FuncSig{}, sourceGoFrame: arm64GoFrame{present: tc.frame}, unexposedCallFrame: tc.proof,
			}
			if tc.known {
				ctx.sigs["callee"] = sig
			}
			ctx.invalidateControlCallResults(state, Operand{Kind: OpSym, Sym: "callee(SB)"})
			for name, value := range map[string]arm64ControlValue{"result": state.regs["R0"], "fp": state.memory["fp:0"]} {
				if arm64ControlHas(value, "label:continuation") != tc.wantContinuation {
					t.Errorf("%s inherited an untransported automatic link: %v", name, value)
				}
				if !tc.wantContinuation && arm64ControlHas(value, "label:source_witness") {
					t.Errorf("%s inherited an untransported virtual GP: %v", name, value)
				}
				if tc.argument != "" && !arm64ControlHas(value, tc.argument) || tc.escaped != "" && strings.HasPrefix(tc.escaped, "label:") && !arm64ControlHas(value, tc.escaped) {
					t.Errorf("%s lost genuinely observable source code: %v", name, value)
				}
			}
			if !arm64ControlHas(state.regs["R19"], "label:source_witness") || !arm64ControlHas(state.regs["R19"], "") {
				t.Fatal("typed transport cannot prove caller-save GP preservation or erase its old code witness")
			}
			if !arm64ControlHas(state.memory["fp:0"], "") {
				t.Fatal("fresh private SP does not protect potentially aliased caller FP contents")
			}
		})
	}
}

func TestARM64TypedCallFPViewsRetainActualSourcePC(t *testing.T) {
	pkg := mustGoPackage(t, "test/pcviews", "package pcviews\nfunc PCArg(p *uint64)\nfunc X(uint64) uint64\n")
	resolve := func(sym string) string { return strings.TrimPrefix(sym, "·") }
	for _, input := range []string{
		"VMOV R30,V0.D[0]\nFMOVD F0,R5",
		"FMOVD R30,F0\nVMOV V0.D[0],R5",
	} {
		t.Run(input, func(t *testing.T) {
			source := fmt.Sprintf("TEXT ·PCArg(SB),4,$32-8\n%s\nMOVD R5,8(RSP)\nCALL ·X(SB)\nMOVD 16(RSP),R5\nADD $4,R5\nMOVD p+0(FP),R6\nMOVD R5,(R6)\nRET\n", input)
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", "arm64")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				if _, err := Translate(file, Options{Goarch: "arm64", Sigs: sigs, ResolveSym: resolve, TargetTriple: target}); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Translate washed away the actual caller-PC argument: %v", target, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, Options{Goarch: "arm64", Sigs: sigs, ResolveSym: resolve, TargetTriple: target})
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Module washed away the actual caller-PC argument: %v", target, err)
				}
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{GOARCH: "arm64", ResolveSym: resolve, TargetTriple: target})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s GoModule washed away the actual caller-PC argument: %v", target, err)
				}
			}
		})
	}
}

func TestARM64TypedCallInputsMatchEmittedTransports(t *testing.T) {
	state := &arm64ControlState{
		regs: map[Reg]arm64ControlValue{
			SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R0": arm64ControlFromMap(map[string]bool{"label:r0": true}), "R1": arm64ControlFromMap(map[string]bool{"label:r1": true}),
			"R2": arm64ControlFromMap(map[string]bool{"label:r2": true}), "R30": arm64ControlFromMap(map[string]bool{"label:link": true}),
			"F0": arm64ControlFromMap(map[string]bool{"label:f0": true}), "V0.D[0]": arm64ControlFromMap(map[string]bool{"label:v0": true}), "Z0.D": arm64ControlFromMap(map[string]bool{"label:z0": true}),
			"F1": arm64ControlFromMap(map[string]bool{"label:f1": true}),
		},
		memory: map[string]arm64ControlValue{
			"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true}), "sp:8": arm64ControlFromMap(map[string]bool{"label:slot0": true}), "sp:16": arm64ControlFromMap(map[string]bool{"label:slot1": true}),
		},
	}
	registerSig := FuncSig{Args: []LLVMType{"double", I64, "{ i64, double }", Ptr}, Ret: Void}
	internalSig := registerSig
	var err error
	internalSig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(internalSig)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		sig      FuncSig
		internal bool
		want     []string
	}{
		{"independent_gp_fp_banks", registerSig, false, []string{"label:f0", "label:r0", "label:r1", "label:f1", "label:r2"}},
		{"internal_recursive_banks", internalSig, true, []string{"label:f0", "label:r0", "label:r1", "label:f1", "label:r2"}},
		{"custom_link_is_real_input", FuncSig{Args: []LLVMType{I64}, ArgRegs: []Reg{"R30"}}, false, []string{"label:link"}},
		{"custom_sp_is_real_input", FuncSig{Args: []LLVMType{Ptr}, ArgRegs: []Reg{"RSP"}}, false, []string{"sp:0"}},
		{"zero_args_present_internal", FuncSig{Ret: Void, ARM64GoRegisterABI: &ARM64GoRegisterABI{}}, true, nil},
		{"classic_aggregate_fields", FuncSig{Args: []LLVMType{"{ ptr, i64 }"}, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: 0, Type: Ptr, Index: 0, Field: 0}, {Offset: 8, Type: I64, Index: 0, Field: 1},
		}}}, false, []string{"label:slot0", "label:slot1"}},
		{"unaligned_saved_link_overlap", FuncSig{Args: []LLVMType{I32}, Frame: FrameLayout{Params: []FrameSlot{
			{Offset: -7, Type: I32, Index: 0, Field: -1},
		}}}, false, []string{"label:caller"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inputs, known := arm64ControlCallInputs(state, tc.sig, tc.internal)
			if !known || len(inputs) != len(tc.want) {
				t.Fatalf("emitted typed transport not recognized: known=%t inputs=%v", known, inputs)
			}
			for index, token := range tc.want {
				if !arm64ControlHas(inputs[index], token) {
					t.Errorf("transport leaf %d lost %s: %v", index, token, inputs[index])
				}
			}
			if len(inputs) != 0 && isARM64ABIFloatingType(tc.sig.Args[0]) {
				for _, alias := range []string{"label:v0", "label:z0"} {
					if !arm64ControlHas(inputs[0], alias) {
						t.Errorf("physical FP/V/Z input alias lost %s: %v", alias, inputs[0])
					}
				}
			}
		})
	}
	// A covering scalar write is not permission to forget another physical
	// view's code witness: this proof does not model every partial SIMD write.
	state.write(Operand{Kind: OpReg, Reg: "F0"}, arm64ControlExternal(), false)
	if value := arm64ControlRead(state.regs, "F0"); !arm64ControlHas(value, "label:v0") || !arm64ControlHas(value, "label:z0") {
		t.Fatalf("covering write silently discarded aliases: %v", value)
	}
	for _, tc := range []struct {
		name     string
		sig      FuncSig
		internal bool
	}{
		{"hidden_carrier", FuncSig{ARM64ClosureABI: &ARM64ClosureABI{}}, false},
		{"missing_internal_contract", FuncSig{Ret: Void}, true},
		{"partial_custom_registers", FuncSig{Args: []LLVMType{Ptr, I64}, ArgRegs: []Reg{"R0"}}, false},
		{"invalid_custom_register", FuncSig{Args: []LLVMType{Ptr}, ArgRegs: []Reg{"R40"}}, false},
		{"custom_aggregate", FuncSig{Args: []LLVMType{"{ ptr, i64 }"}, ArgRegs: []Reg{"R0"}}, false},
		{"nested_generic_aggregate", FuncSig{Args: []LLVMType{"{ ptr, { i64, double } }"}}, false},
		{"unknown_scalar", FuncSig{Args: []LLVMType{"unrecognized"}}, false},
		{"gp_bank_overflow", FuncSig{Args: makeRepeatedARM64CallTypes(I64, 17)}, false},
		{"fp_bank_overflow", FuncSig{Args: makeRepeatedARM64CallTypes("double", 17)}, false},
		{"frame_offset_overflow", FuncSig{Args: []LLVMType{Ptr}, Frame: FrameLayout{Params: []FrameSlot{{Offset: 1<<63 - 1, Type: Ptr, Index: 0, Field: -1}}}}, false},
		{"missing_frame_parameter", FuncSig{Args: []LLVMType{Ptr, I64}, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}}}}, false},
		{"unknown_frame_width", FuncSig{Args: []LLVMType{Ptr}, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "unrecognized", Index: 0, Field: -1}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, known := arm64ControlCallInputs(state, tc.sig, tc.internal); known {
				t.Fatal("unproved typed input transport accepted")
			}
		})
	}
	for _, mutate := range []func(*ARM64GoRegisterABI){
		func(abi *ARM64GoRegisterABI) { abi.Params = abi.Params[:len(abi.Params)-1] },
		func(abi *ARM64GoRegisterABI) { abi.Params[0].Register = "R0" },
	} {
		sig := registerSig
		sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
		if err != nil {
			t.Fatal(err)
		}
		mutate(sig.ARM64GoRegisterABI)
		if _, known := arm64ControlCallInputs(state, sig, true); known {
			t.Fatal("incomplete/wrong-bank ABIInternal input contract accepted")
		}
	}
}

func makeRepeatedARM64CallTypes(typ LLVMType, count int) []LLVMType {
	values := make([]LLVMType, count)
	for index := range values {
		values[index] = typ
	}
	return values
}

func TestARM64TypedCallFloatingResultsRetainSourcePC(t *testing.T) {
	pkg := mustGoPackage(t, "test/fpresult", "package fpresult\nfunc PCArg(p *uint64)\n//go:linkname X runtime.X\nfunc X(uint64) float64\n")
	resolve := func(sym string) string {
		return strings.ReplaceAll(strings.TrimPrefix(goStripABISuffix(sym), "·"), "·", ".")
	}
	for _, tc := range []struct {
		name, setup, call, result string
		manual                    bool
	}{
		{"classic_register_result", "MOVD R30,R5\nMOVD R5,8(RSP)", "CALL runtime·X(SB)", "FMOVD F0,R5", true},
		{"internal_fp_result", "MOVD R30,R0", "CALL runtime·X<ABIInternal>(SB)", "FMOVD F0,R5", false},
		{"classic_stack_result", "MOVD R30,R5\nMOVD R5,8(RSP)", "CALL runtime·X(SB)", "FMOVD 16(RSP),F0\nFMOVD F0,R5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Clear the old GP witness before reading the floating result.
			// Otherwise the generic transform's conservative destination read
			// could hide an omitted F0 result definition in this negative.
			source := fmt.Sprintf("TEXT ·PCArg(SB),4,$32-8\n%s\n%s\nMOVD $0,R5\n%s\nADD $4,R5\nMOVD p+0(FP),R6\nMOVD R5,(R6)\nRET\n", tc.setup, tc.call, tc.result)
			requireARM64TypedCallGoSelectorObject(t, source)
			manual := func(name string) (FuncSig, bool) {
				return FuncSig{Name: "X", Args: []LLVMType{I64}, ArgRegs: []Reg{"R5"}, Ret: "double"}, name == "runtime.X" && tc.manual
			}
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			sizes := types.SizesFor("gc", "arm64")
			sigs, err := goSigsForAsmFile(pkg, file, resolve, "arm64", sizes, sizes, manual)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range arm64TypedNativeTargets {
				opt := Options{Goarch: "arm64", Sigs: sigs, ResolveSym: resolve, TargetTriple: target}
				if _, err := Translate(file, opt); !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Translate lost source PC through float result: %v", target, err)
				}
				ctx := llvm.NewContext()
				module, err := TranslateModuleInContext(ctx, file, opt)
				if err == nil {
					module.Dispose()
				}
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s Module lost source PC through float result: %v", target, err)
				}
				bound, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
					GOARCH: "arm64", ResolveSym: resolve, TargetTriple: target, ManualSig: manual,
				})
				if err == nil {
					bound.Module.Dispose()
				}
				ctx.Dispose()
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Errorf("%s GoModule lost source PC through float result: %v", target, err)
				}
			}
		})
	}
}

func requireARM64TypedCallGoSelectorObject(t *testing.T, source string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "source.s")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	help, err := exec.CommandContext(ctx, "go", "tool", "asm", "-h").CombinedOutput()
	if ctx.Err() != nil || err != nil && len(help) == 0 {
		t.Fatalf("Go assembler flag discovery: %v / %v\n%s", err, ctx.Err(), help)
	}
	args := []string{"tool", "asm", "-p", "runtime"}
	// Go1.20 requires an explicit runtime flag for source ABI selectors.
	// Current Go derives that permission from -p and removed this flag.
	if strings.Contains(string(help), "-compiling-runtime") {
		args = append(args, "-compiling-runtime")
	}
	args = append(args, "-o", filepath.Join(dir, "source.o"), path)
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Env = append(os.Environ(), "GOARCH=arm64", "GOOS=linux")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Go typed-call selector object: %v\n%s", err, out)
	}
}

func TestARM64TypedCallPartialResultRetainsOverlappingPC(t *testing.T) {
	state := &arm64ControlState{
		regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true})},
		memory: map[string]arm64ControlValue{"sp:12": arm64ControlFromMap(map[string]bool{"label:source_witness": true})},
	}
	sig := FuncSig{Ret: I32, Frame: FrameLayout{Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}}}
	arm64ControlWriteCallResults(state, sig, false, arm64ControlExternal())
	if !arm64ControlHas(state.memory["sp:16"], "label:source_witness") {
		t.Fatal("narrow result washed out code bits from an overlapping control cell")
	}
}
