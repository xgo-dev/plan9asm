package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestARMSymbolMovePCRequiresRealContext(t *testing.T) {
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		for _, suffix := range []string{"", ".EQ", ".NE.P"} {
			for _, load := range []bool{false, true} {
				instruction := fmt.Sprintf("%s%s R15,·memory+3(SB)", op, suffix)
				want := "source instruction layout"
				if load {
					instruction = fmt.Sprintf("%s%s ·memory+3(SB),R15", op, suffix)
					want = "control-flow"
				}
				t.Run(instruction, func(t *testing.T) {
					source := "TEXT pcreference(SB),$0-0\n" + instruction + "\nRET\n"
					requireARMGoAssemblerResult(t, source, true)
					file, err := Parse(ArchARM, source)
					if err != nil {
						t.Fatal(err)
					}
					instruction := file.Funcs[0].Instrs[1]
					for _, err := range []error{
						ProbeInstruction(ArchARM, "arm", instruction),
						ProbeInstructionSequence(ArchARM, "arm", []Instr{instruction}),
					} {
						if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), want) {
							t.Fatalf("symbol PC probe must preserve %s context: %v", want, err)
						}
					}
					for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
						options := Options{Goarch: "arm", TargetTriple: triple,
							Sigs: map[string]FuncSig{"pcreference": {Name: "pcreference", Ret: Void}},
						}
						if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), want) {
							t.Fatalf("%s must fail closed with %s context, got %v", triple, want, err)
						}
						module, err := TranslateModule(file, options)
						if err == nil {
							module.Dispose()
							t.Fatal("direct module translation accepted a machine-PC contract as a normal register")
						}
						if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), want) {
							t.Fatalf("direct module translation lost context failure: %v", err)
						}
					}
				})
			}
		}
	}
	for _, suffix := range []string{"", ".EQ", ".NE"} {
		instruction := "MOVW" + suffix + " $·memory+3(SB),R15"
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT addresspc(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			for _, err := range []error{
				ProbeInstruction(ArchARM, "arm", instruction),
				ProbeInstructionSequence(ArchARM, "arm", []Instr{instruction}),
			} {
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "control-flow") {
					t.Fatalf("symbol PC address probe must preserve control-flow context: %v", err)
				}
			}
			for _, triple := range []string{"armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				options := Options{Goarch: "arm", TargetTriple: triple,
					Sigs: map[string]FuncSig{"addresspc": {Name: "addresspc", Ret: Void}},
				}
				if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "control-flow") {
					t.Fatalf("MOVW symbol address to PC must not fall through: %v", err)
				}
				module, err := TranslateModule(file, options)
				if err == nil {
					module.Dispose()
					t.Fatal("direct module translation accepted a symbol address to PC")
				}
				if !errors.Is(err, ErrProbeNeedsContext) || !strings.Contains(err.Error(), "control-flow") {
					t.Fatalf("direct module translation lost control-flow context: %v", err)
				}
			}
		})
	}
}

func TestARMSymbolMoveRejectsPseudoRegistersExactlyLikeGo(t *testing.T) {
	var instructions []string
	for _, reg := range []string{"PC", "SP"} {
		for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
			instructions = append(instructions, op+" "+reg+",·memory(SB)", op+" ·memory(SB),"+reg)
		}
		instructions = append(instructions, "MOVW $·memory(SB),"+reg)
	}
	for _, instruction := range instructions {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT pseudopc(SB),$0-0\n" + instruction + "\nRET\n"
			requireARMGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM, source)
			if err != nil {
				return
			}
			if err := ProbeInstruction(ArchARM, "arm", file.Funcs[0].Instrs[1]); err == nil || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("Go-illegal pseudo-register must not be accepted or hidden as context: %v", err)
			}
			if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"pseudopc": {Name: "pseudopc", Ret: Void}},
			}); err == nil {
				t.Fatalf("accepted Go-illegal pseudo-register form %q", instruction)
			}
		})
	}
}

func TestARMSymbolMoveKeepsHardwareSPForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT hardwaresp(SB),$0-0\n")
	for _, op := range []string{"MOVW", "MOVB", "MOVBS", "MOVBU", "MOVH", "MOVHS", "MOVHU"} {
		fmt.Fprintf(&source, "%s R13,·memory+3(SB)\n%s ·memory+3(SB),R13\n", op, op)
	}
	source.WriteString("MOVW $·memory+3(SB),R13\nRET\n")
	requireARMGoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
		ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple,
			Sigs: map[string]FuncSig{"hardwaresp": {Name: "hardwaresp", Ret: Void}},
		})
		if err != nil {
			t.Fatalf("hardware R13 must remain distinct from pseudo SP: %v", err)
		}
		// This checks grammar and object generation only. Executing a fixture
		// that arbitrarily overwrites the machine SP would not be a safe oracle.
		compileLLVMToObject(t, llc, triple, "hardware-sp.ll", "hardware-sp.o", ir)
	}
}
