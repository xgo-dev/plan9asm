package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestARM64AtomicPairNamedEffectsMatchRealOutputBankAndMemory(t *testing.T) {
	for _, family := range []struct {
		ops   []string
		args  string
		lr    bool
		store bool
	}{
		{[]string{"CASPW", "CASPD"}, "(R30,ZR),(R16),(R4,R5)", true, true},
		{[]string{"CASPW", "CASPD"}, "(R0,R1),(R16),(R30,ZR)", false, true},
		{[]string{"LDXPW", "LDXP", "LDAXPW", "LDAXP"}, "(R16),(RSP,R1)", false, false},
		{[]string{"LDXPW", "LDXP", "LDAXPW", "LDAXP"}, "(R16),(R30,ZR)", true, false},
		{[]string{"STXPW", "STXP", "STLXPW", "STLXP"}, "(R30,ZR),(R16),R0", false, true},
		{[]string{"STXPW", "STXP", "STLXPW", "STLXP"}, "(R2,R3),(R16),R30", true, true},
	} {
		for _, op := range family.ops {
			t.Run(op+family.args, func(t *testing.T) {
				source := fmt.Sprintf("TEXT effects(SB),4,$0-0\n%s %s\nRET\n", op, family.args)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				state := &arm64ControlState{
					regs: map[Reg]arm64ControlValue{
						SP: arm64ControlFromMap(map[string]bool{"sp:0": true}), "R30": arm64ControlFromMap(map[string]bool{"label:caller": true}),
					},
					memory: map[string]arm64ControlValue{"sp:0": arm64ControlFromMap(map[string]bool{"label:caller": true})},
				}
				ins := file.Funcs[0].Instrs[1]
				state.transfer(ins, Op(op), false, nil)
				if !arm64ControlEqual(state.regs[SP], arm64ControlFromMap(map[string]bool{"sp:0": true})) {
					t.Errorf("data-pair RSP encodes ZR, not a stack-pointer write: %+v", state.regs[SP])
				}
				if tainted := arm64ControlHas(state.regs["R30"], ""); tainted != family.lr {
					t.Errorf("caller LR output taint=%v, want %v; state=%+v", tainted, family.lr, state.regs["R30"])
				}
				if tainted := arm64ControlHas(state.memory["sp:0"], ""); tainted != family.store {
					t.Errorf("saved-memory store taint=%v, want %v", tainted, family.store)
				}
			})
		}
	}
}

func TestARM64AtomicPairOutputCannotInventCallerReturn(t *testing.T) {
	for _, instruction := range []string{
		"CASPD (R30,ZR),(R16),(R4,R5)",
		"LDXP (R16),(R30,ZR)",
		"STLXP (R2,R3),(R16),R30",
	} {
		source := "TEXT effects(SB),516,$0-0\n" + instruction + "\nRET\n"
		requireARM64GoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
			Sigs: map[string]FuncSig{"effects": {Name: "effects", Ret: Void}},
		}); !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s overwrites caller LR and must need context, got %v", instruction, err)
		}
	}
}

func TestARM64AtomicPairNamedSPUsesGoPhysicalZeroOffset(t *testing.T) {
	for _, frame := range []int{0, 16, 24, 32768} {
		for _, op := range []string{"CASPW", "CASPD"} {
			t.Run(fmt.Sprintf("%s/frame%d", op, frame), func(t *testing.T) {
				offset := 0
				if frame != 0 {
					offset = -frame - 8 // Go asm7 NAME_AUTO: autosize - extrasize.
				}
				source := fmt.Sprintf("TEXT effects(SB),4,$%d-0\n%s (R0,R1),local%+d(SP),(R2,R3)\nUNDEF\n", frame, op, offset)
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				normalized, err := normalizeARM64AtomicPairNamedMemory(file.Funcs[0])
				if err != nil {
					t.Fatal(err)
				}
				memory := normalized.Instrs[1].Args[1].Mem
				if memory.Base != "RSP" || memory.Off != 0 || memory.OffRaw != "" {
					t.Fatalf("C_ZAUTO did not resolve to physical zero-offset SP: %+v", memory)
				}
				llc := findLLVM22Tool("llc")
				if llc == "" {
					t.Fatal("LLVM 22 llc not found")
				}
				for _, triple := range []string{
					"aarch64-apple-darwin", "aarch64-unknown-linux-gnu",
					"aarch64-unknown-linux-musl", "aarch64-pc-windows-msvc",
				} {
					ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
						Sigs: map[string]FuncSig{"effects": {Name: "effects", Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					compileLLVMToObject(t, llc, triple, "named-atomic.ll", "named-atomic.o", ir)
				}
				original := file.Funcs[0].Instrs[1].Args[1].Mem
				if original.Base != SP || original.Off != int64(offset) || original.OffRaw == "" {
					t.Fatalf("normalization mutated immutable source evidence: %+v", original)
				}
			})
		}
	}
}

func TestARM64AtomicPairNamedSPRejectsNonZeroPhysicalOffset(t *testing.T) {
	for _, offset := range []int{0, -16, -32} {
		source := fmt.Sprintf("TEXT effects(SB),4,$16-0\nCASPD (R0,R1),local%+d(SP),(R2,R3)\nUNDEF\n", offset)
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm64", TargetTriple: arm64LinuxGNUTriple,
			Sigs: map[string]FuncSig{"effects": {Name: "effects", Ret: Void}},
		}); err == nil {
			t.Errorf("accepted named SP offset %d despite Go's nonzero physical-offset rejection", offset)
		}
	}
}
