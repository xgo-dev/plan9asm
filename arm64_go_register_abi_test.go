package plan9asm

import (
	"errors"
	"fmt"
	"go/types"
	"strings"
	"testing"
)

func TestARM64GoRegisterABIAbsentMalformedAndStackContexts(t *testing.T) {
	for _, declaration := range []string{
		"func Pass([2]uint64) uint64",
		"func Pass(uint64) [2]uint64",
		"func Pass(struct{}) uint64",
		"func Pass(struct{ Z [0]byte; I uint64 }) uint64",
		"func Pass(" + strings.TrimSuffix(strings.Repeat("uint64,", 17), ",") + ") uint64",
		"func Pass(" + strings.TrimSuffix(strings.Repeat("float64,", 17), ",") + ") uint64",
		"func Pass() (" + strings.TrimSuffix(strings.Repeat("uint64,", 17), ",") + ")",
	} {
		pkg := mustGoPackage(t, "test/stackinternal", "package stackinternal\n"+declaration+"\n")
		for _, target := range []string{"aarch64-unknown-linux-gnu", "aarch64-unknown-linux-musl", "aarch64-apple-darwin", "aarch64-pc-windows-msvc"} {
			tr, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0\nRET\n"), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: target,
				ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
			})
			if err == nil {
				tr.Module.Dispose()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s: stack/unrecognized contract must fail closed: %v", target, declaration, err)
			}
		}
	}

	sig := FuncSig{Name: "X", Args: []LLVMType{"{ ptr, { double, i64 } }"}, Ret: I64}
	valid, err := arm64GoRegisterABIForSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*FuncSig)
	}{
		{"absent", func(s *FuncSig) { s.ARM64GoRegisterABI = nil }},
		{"incomplete", func(s *FuncSig) { s.ARM64GoRegisterABI.Params = s.ARM64GoRegisterABI.Params[:2] }},
		{"wrong_bank", func(s *FuncSig) { s.ARM64GoRegisterABI.Params[1].Register = "R1" }},
		{"wrong_type", func(s *FuncSig) { s.ARM64GoRegisterABI.Params[0].Type = I64 }},
		{"wrong_path", func(s *FuncSig) { s.ARM64GoRegisterABI.Params[2].Path = []int{0} }},
		{"duplicate_register", func(s *FuncSig) { s.ARM64GoRegisterABI.Params[2].Register = "R0" }},
		{"wrong_result", func(s *FuncSig) { s.ARM64GoRegisterABI.Results[0].Register = "R1" }},
		{"mixed_custom", func(s *FuncSig) { s.ArgRegs = []Reg{"R9"} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copy := sig
			copy.ARM64GoRegisterABI = &ARM64GoRegisterABI{
				Params: append([]ARM64GoRegisterValue(nil), valid.Params...), Results: append([]ARM64GoRegisterValue(nil), valid.Results...),
			}
			tc.edit(&copy)
			if err := arm64ValidateGoRegisterABI(copy); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("malformed/absent typed contract accepted: %v", err)
			}
		})
	}
}

func TestARM64GoRegisterABISourceSelectorAndDeclarationRequired(t *testing.T) {
	pkg := mustGoPackage(t, "test/sourceinternal", "package sourceinternal\nfunc Pass(uint64) uint64\n")
	fn := pkg.Types.Scope().Lookup("Pass").(*types.Func)
	sig := sigWithClassicFrame("Pass", []LLVMType{I64}, I64)
	if _, err := DeriveARM64GoRegisterABI(nil, sig); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("absent declaration accepted: %v", err)
	}
	bad := sig
	bad.Args = []LLVMType{Ptr}
	if _, err := DeriveARM64GoRegisterABI(fn, bad); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("mismatched declaration accepted: %v", err)
	}
	for _, selector := range []string{"", "<ABI0>", "<ABIInternal>"} {
		source := fmt.Sprintf("TEXT ·Pass%s(SB),4,$0-16\nRET\n", selector)
		tr, err := TranslateGoModule(pkg, []byte(source), GoModuleOptions{
			GOARCH: "arm64", ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
		})
		if err != nil {
			t.Fatal(err)
		}
		hasContract := tr.Signatures["Pass"].ARM64GoRegisterABI != nil
		tr.Module.Dispose()
		if hasContract != (selector == "<ABIInternal>") {
			t.Fatalf("source %q: unexpected register proof=%t", selector, hasContract)
		}
	}

	tr, err := TranslateGoModule(pkg, []byte("TEXT ·Pass<ABIInternal>(SB),4,$0-16\nMOVD a+0(FP),R0\nRET\n"), GoModuleOptions{
		GOARCH: "arm64", ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
	})
	if err == nil {
		tr.Module.Dispose()
	}
	if !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("unmodeled ABIInternal FP spill access accepted: %v", err)
	}
}

func TestARM64GoRegisterABIControlEffectsUseTypedRegisterLeaves(t *testing.T) {
	for _, pointer := range []bool{false, true} {
		sig := sigWithClassicFrame("callee", nil, I64)
		if pointer {
			sig = sigWithClassicFrame("callee", []LLVMType{"{ ptr, i64 }"}, I64)
		}
		var err error
		sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
		if err != nil {
			t.Fatal(err)
		}
		state := &arm64ControlState{
			regs:   map[Reg]arm64ControlValue{SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R0": arm64ControlFromMap(map[string]bool{"sp:0": true}), "R30": arm64ControlFromMap(map[string]bool{"label:continuation": true})},
			memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{"label:outer": true}), "sp:8": arm64ControlFromMap(map[string]bool{"": true})},
		}
		ctx := &arm64Ctx{resolve: func(s string) string { return goStripABISuffix(strings.TrimPrefix(s, "·")) }, sigs: map[string]FuncSig{"callee": sig}}
		ctx.invalidateControlCallResults(state, Operand{Kind: OpSym, Sym: "·callee<ABIInternal>(SB)"})
		if pointer && !arm64ControlHas(state.memory["sp:0"], "") {
			t.Fatal("nested Ptr register argument failed to invalidate saved-link memory")
		}
		if !pointer && arm64ControlHas(state.memory["sp:8"], "label:continuation") {
			t.Fatal("register result was incorrectly stored in the classic ABI0 frame")
		}
	}
}

func TestARM64GoRegisterABITailCannotBorrowEntryProof(t *testing.T) {
	sig := FuncSig{Name: "Pass", Args: []LLVMType{I64}, Ret: I64}
	var err error
	sig.ARM64GoRegisterABI, err = arm64GoRegisterABIForSig(sig)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"·Missing<ABIInternal>(SB)", "·Missing<ABI0>(SB)", "·Missing(SB)"} {
		for _, op := range []string{"B", "JMP", "RET"} {
			source := "TEXT ·Pass<ABIInternal>(SB),4,$0-16\nADD $9,R0\n" + op + " " + target + "\n"
			requireARM64GoABIInternalObject(t, source)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm64", Sigs: map[string]FuncSig{"Pass": sig},
				ResolveSym: func(sym string) string { return strings.TrimPrefix(goStripABISuffix(sym), "·") },
			})
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("%s %s inherited a fabricated target entry/cross-ABI tail contract: %v", op, target, err)
			}
		}
	}
}
