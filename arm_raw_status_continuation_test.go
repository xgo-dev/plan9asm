package plan9asm

import (
	"errors"
	"fmt"
	"testing"
)

func TestARMRawVectorKeepsSourceDefinedNZCV(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, word := range []uint32{
		0xf2200842, // VADD.I32 Q0,Q0,Q1
		0xf3066150, // VEOR Q3,Q3,Q0
		0xf3b460c6, // VREV32.16 Q3,Q3
		0xf3ac2078, // VSHR.U32 Q1,Q12,#20
		0xf3ac2578, // VSLI.32 Q1,Q12,#12
		0xf423228f, // VLD1.32 {Q1,Q2},[R3]
		0xedcd8b11, // VSTR D24,[SP,#68]
		0x1e300a00, // VADDNE.F32 S0,S0,S0
	} {
		t.Run(fmt.Sprintf("%08x", word), func(t *testing.T) {
			source := fmt.Sprintf("TEXT flags(SB),$128\n MOVW $2,R0\nloop:\n SUB.S $1,R0,R0\n WORD $%#08x\n B.NE loop\n MOVW CPSR,R0\n RET\n", word)
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			for _, triple := range []string{"armv5te-unknown-linux-gnueabi", "armv7-unknown-linux-gnueabihf", "thumbv7-pc-windows-msvc"} {
				ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: triple, Sigs: map[string]FuncSig{
					"flags": {Name: "flags", Ret: I32},
				}})
				if err != nil {
					t.Fatal(err)
				}
				compileLLVMToObject(t, llc, triple, "raw-flags.ll", "raw-flags.o", ir)
			}
		})
	}
}

func TestARMRawVectorDoesNotInventPredicates(t *testing.T) {
	for _, body := range []string{
		"WORD $0x1e300a00", // Conditional scalar VFP.
		"WORD $0x1ee00b10", // Conditional core VDUP.
		"WORD $0xf2200842\n B.NE done\ndone:",
		"CMP R0,R0\n WORD $0xffffffff\n B.NE done\ndone:",
		"CMP R0,R0\n WORD $0xeef1fa10\n B.NE done\ndone:",
		"B join\n CMP R0,R0\njoin:\n WORD $0xf2200842\n B.NE done\ndone:",
	} {
		source := "TEXT flags(SB),$0\n MOVW $0,R0\n" + body + "\n RET\n"
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
			"flags": {Name: "flags", Ret: Void},
		}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatalf("raw source cannot invent or preserve unproved flags: %s: %v", body, err)
		}
	}
}

func TestARMRawDataStatusCFGAndGPOutputGuards(t *testing.T) {
	tests := []struct {
		name, body string
		accepted   bool
	}{
		{name: "diamond", body: "CMP R0,R0\n B.EQ alternate\n WORD $0xf2200842\n B join\nalternate:\n WORD $0xf3066150\njoin:\n MOVW CPSR,R0", accepted: true},
		{name: "unknown_join", body: "CMP R0,R0\n B.EQ alternate\n WORD $0xf2200842\n B join\nalternate:\n WORD $0xffffffff\njoin:\n MOVW CPSR,R0"},
		{name: "call_flags", body: "CMP R0,R0\n WORD $0xf2200842\n BL other<>(SB)\n B.NE done\ndone:"},
		{name: "partial_NZ", body: "TST R0,R0\n WORD $0xf2200842\n B.HI done\ndone:"},
		{name: "lane_GP_output", body: "CMP R0,R0\n WORD $0xee100b10\n MOVW R0,CPSR"},
		{name: "pair_GP_outputs", body: "CMP R0,R0\n WORD $0xec510b10\n MOVW R0,CPSR"},
		{name: "extend_GP_output", body: "CMP R0,R0\n WORD $0xe6af0070\n MOVW R0,CPSR"},
		{name: "NEON_writeback", body: "CMP R0,R0\n WORD $0xf420070d\n MOVW R0,CPSR"},
		{name: "VFP_writeback", body: "CMP R0,R0\n WORD $0xeca00b04\n MOVW R0,CPSR"},
		{name: "overwrite_killed_GP", body: "CMP R0,R0\n WORD $0xee100b10\n MOVW $0x60000000,R0\n MOVW R0,CPSR\n MOVW CPSR,R0", accepted: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT flags(SB),$128\n MOVW $0,R0\n" + test.body + "\n RET\nTEXT other<>(SB),$0\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"flags": {Name: "flags", Ret: Void}, "other<>": {Name: "other<>", Ret: Void},
			}})
			if test.accepted {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("raw data did not retain the source/CFG guard: %v", err)
			}
		})
	}
}
