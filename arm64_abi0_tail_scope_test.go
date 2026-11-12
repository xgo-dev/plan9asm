package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func TestARM64ABI0TailResultKeepFuncKeepsWholeAudit(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	declaration += "\nfunc Other(value uint64) (out uint64)"
	source += "TEXT ·Other(SB),516,$0-16\nMOVD value+0(FP),R0\nMOVD R0,out+8(FP)\nRET\n"
	for _, kept := range []string{"Slots", "Other"} {
		t.Run(kept, func(t *testing.T) {
			pkg, _ := arm64ABI0TailResultSignature(t, declaration)
			ctx := llvm.NewContext()
			defer ctx.Dispose()
			result, err := translateGoModuleInContext(ctx, pkg, []byte(source), GoModuleOptions{
				GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
				ResolveSym: func(name string) string { return strings.TrimPrefix(goTextSymbolForResolution(name), "·") },
				KeepFunc:   func(_, name string) bool { return name == kept },
			})
			if result != nil && !result.Module.IsNil() {
				defer result.Module.Dispose()
			}
			if err != nil {
				t.Fatalf("dropping an unused declaration must not counterfeit a signature mutation: %v", err)
			}
			if strings.Count(result.Module.String(), "define ") != 1 {
				t.Fatal("KeepFunc did not retain exactly the requested root")
			}
		})
	}
	for _, witness := range []string{
		"TEXT observer<>(SB),516,$0\nADR resultbody<>(SB),R7\nRET\n",
		"DATA escaped<>(SB)/8,$resultbody<>(SB)\nGLOBL escaped<>(SB),$8\n",
	} {
		pkg, _ := arm64ABI0TailResultSignature(t, declaration)
		ctx := llvm.NewContext()
		result, err := translateGoModuleInContext(ctx, pkg, []byte(source+witness), GoModuleOptions{
			GOARCH: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
			KeepFunc: func(_, _ string) bool { return false },
		})
		if result != nil && !result.Module.IsNil() {
			result.Module.Dispose()
		}
		ctx.Dispose()
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("KeepFunc hid a whole-file helper escape witness: %v", err)
		}
	}
}

func TestARM64ABI0TailResultSharedBudgetAndIdempotence(t *testing.T) {
	_, file, sigs := arm64ABI0BoundFixture(t)
	resolve := func(name string) string { return strings.TrimPrefix(goTextSymbolForResolution(name), "·") }
	prepared, err := PrepareGoARM64ABI0TailContinuations(file, sigs, resolve)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := PrepareGoARM64ABI0TailContinuations(prepared, sigs, resolve)
	if err != nil || !reflect.DeepEqual(prepared, repeated) {
		t.Fatalf("declaration-backed preparation is not idempotent: %v", err)
	}
	if _, err := PrepareGoARM64ABI0TailContinuations(nil, sigs, resolve); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("nil original source was not rejected: %v", err)
	}
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	call := "TEXT ·Run(SB),4,$0-16\nMOVD x+0(FP),R0\nCALL mix<>(SB)\nMOVD R0,ret+8(FP)\nRET\nTEXT mix<>(SB),516,$0-0\n" +
		strings.Repeat("ADD $1,R0\n", arm64PrivateRegisterExpansionBudget-4) + "RET\n"
	pkg, sig := arm64ABI0TailResultSignature(t, declaration)
	mixed, err := Parse(ArchARM64, source+call)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindGoARM64ABI0TailDeclarations(pkg, mixed, resolve, map[string]FuncSig{"Slots": sig})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareGoARM64ABI0TailContinuations(mixed, bound, resolve); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("ABI0 tail gained an independent expansion budget after CALL: %v", err)
	}
}

func TestARM64ABI0TailResultUnapprovedDomainsRemainContext(t *testing.T) {
	_, source := arm64ABI0TailResultFixture(false, "B")
	for _, declaration := range []string{
		"func Slots(value uint64) (out float64)",
		"func Slots(value uint64) (out *uint64)",
		"func Slots(value uint64) (out [1]uint64)",
		"func Slots(value uint64) (out bool)",
		"func Slots(value uint64)",
	} {
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(declaration+"/"+api, func(t *testing.T) {
				_, err := arm64ABI0TailResultTranslate(t, source, declaration, "aarch64-unknown-linux-gnu", api, nil)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("unapproved result/layout acquired its slot capability: %v", err)
				}
			})
		}
	}
}

func TestARM64ABI0TailResultAddressSyntaxCannotLaunderSlot(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	for _, address := range []string{"$8(R8)", "$(R8)"} {
		changed := strings.Replace(source, "B resultbody<>(SB)", "MOVD "+address+",R0\nB resultbody<>(SB)", 1)
		requireARM64GoABIInternalObject(t, changed)
		for _, api := range []string{"text", "module", "GoModule"} {
			t.Run(address+"/"+api, func(t *testing.T) {
				_, err := arm64ABI0TailResultTranslate(t, changed, declaration, "aarch64-unknown-linux-gnu", api, nil)
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("symbolic address syntax converted a live result-slot pointer to Plain: %v", err)
				}
			})
		}
	}
}

// Only assemble these sources. A valid Go object does not authorize a live
// source SP, closure register, scratch register or caller LR as a data address.
func TestARM64ABI0TailResultRootAddressSyntaxCannotExposeReservedState(t *testing.T) {
	declaration, source := arm64ABI0TailResultFixture(false, "B")
	for _, address := range []string{
		"$8(RSP)", "$(RSP)", "$8(R26)", "$(R26)",
		"$8(R27)", "$(R27)", "$8(R30)", "$(R30)",
	} {
		changed := strings.Replace(source, "B resultbody<>(SB)", "MOVD "+address+",R0\nB resultbody<>(SB)", 1)
		t.Run(address, func(t *testing.T) {
			requireARM64GoABIInternalObject(t, changed)
			for _, api := range []string{"text", "module", "GoModule"} {
				t.Run(api, func(t *testing.T) {
					ir, err := arm64ABI0TailResultTranslate(t, changed, declaration, "aarch64-unknown-linux-gnu", api, nil)
					if !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
						t.Fatalf("unbound reserved source address acquired ABI0 continuation permission: err=%v object=%t", err, ir != "")
					}
				})
			}
		})
	}
}

// These are typed-domain unit tripwires, not original-Go object certificates.
// The independently accepted source address variants are tested above.
func TestARM64ABI0TailResultTypedAddressEffectsDoNotLoseSlot(t *testing.T) {
	_, sig := arm64ABI0TailResultSignature(t, "func Slots(value uint64) (out uint64)")
	for _, source := range []Operand{
		{Kind: OpReg, Reg: "R8"},
		{Kind: OpFPAddr, FPOffset: 8},
	} {
		state := arm64ABI0ResultState{}
		state.assign("R8", 1)
		instruction := Instr{Op: "MOVD", Args: []Operand{source, {Kind: OpReg, Reg: "F0"}}}
		if err := state.step(instruction, sig); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("result-slot address acquired an untracked bank: %v", err)
		}
	}
	state := arm64ABI0ResultState{}
	state.assign("R8", 1)
	for _, source := range []Operand{
		{Kind: OpSym, Sym: "$8(R8)"},
		{Kind: OpSym, Sym: "$(R0)(R8)"},
		{Kind: OpMem, Mem: MemRef{Base: "R0", Index: "R8"}},
	} {
		if state.operand(source) {
			t.Fatalf("address representation dropped a slot alias: %+v", source)
		}
	}
}
