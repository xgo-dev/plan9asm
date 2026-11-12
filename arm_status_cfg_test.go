package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestARMStatusReadRequiresInitializedNZCVOnEveryPath(t *testing.T) {
	tests := []struct{ name, body string }{
		{"native_entry", "MOVW CPSR,R0"},
		{"bypassed_writer", "B read\n CMP R0,R0\nread:\n MOVW CPSR,R0"},
		{"conditional_writer", "CMP.EQ R0,R0\n MOVW CPSR,R0"},
		{"only_logic_flags", "TST R0,R0\n MOVW CPSR,R0"},
		{"only_shift_flags", "SLL.S $1,R0\n MOVW CPSR,R0"},
		{"only_multiply_flags", "MULL.S R0,R0,(R1,R2)\n MOVW CPSR,R0"},
		{"unproved_call_status", "BL other<>(SB)\n MOVW CPSR,R0"},
		{"conditional_status_write", "MOVW.EQ R0,CPSR\n MOVW CPSR,R0"},
		{"unbound_status_source", "MOVW R7,CPSR\n MOVW CPSR,R0"},
		{"raw_status_without_fp_witness", "CMP R0,R0\n WORD $0xeef1fa10\n MOVW CPSR,R0"},
		{"raw_status_after_gp_overwrite", "MOVD $0.0,F0\n CMPD F0,F0\n CMP R0,R0\n WORD $0xeef1fa10\n MOVW CPSR,R0"},
		{"loop_first_iteration", "B read\nloop:\n CMP R0,R0\nread:\n MOVW CPSR,R0\n B loop"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := "TEXT flags(SB),$0\n MOVW $0,R0\n " + test.body + "\n RET\nTEXT other<>(SB),$0\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			options := Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"flags": {Name: "flags", Ret: I32}, "other<>": {Name: "other<>", Ret: Void},
			}}
			if _, err := Translate(file, options); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("CPSR cannot read generic zero slots or unbound physical entry/callee flags: %v", err)
			}
			module, err := TranslateModule(file, options)
			if err == nil {
				module.Dispose()
				t.Fatal("direct module translation lost the initial/CFG NZCV context failure")
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("direct module did not preserve status-context failure: %v", err)
			}
		})
	}
}

func TestARMConditionalComparePreservesSkippedNZCV(t *testing.T) {
	for _, op := range []string{"CMP", "CMN", "TST", "TEQ"} {
		for _, condition := range []string{"EQ", "NE", "CS", "CC", "HS", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE"} {
			source := "TEXT flags(SB),$0\n MOVW $0,R0\n CMP R0,R0\n " + op + "." + condition + " $1,R0\n MOVW CPSR,R0\n RET\n"
			requireARMGoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
				"flags": {Name: "flags", Ret: I32},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ir, "br i1") {
				t.Fatalf("%s.%s must preserve one source instruction's predicate", op, condition)
			}
		}
	}
}

func TestARMStatusReadKeepsModeledShifterAndMultiplyEffects(t *testing.T) {
	for _, instruction := range []string{"TST R0<<1,R0", "TEQ R0>>1,R0", "AND.S R0<<1,R0", "ORR.S R0>>1,R0", "EOR.S R0->1,R0", "BIC.S R0@>1,R0", "MUL.S R0,R0"} {
		source := "TEXT flags(SB),$0\n MOVW $0,R0\n CMP R0,R0\n " + instruction + "\n MOVW CPSR,R0\n RET\n"
		requireARMGoAssemblerResult(t, source, true)
		file, err := Parse(ArchARM, source)
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{
			"flags": {Name: "flags", Ret: I32},
		}})
		if err != nil {
			t.Fatalf("ordinary shifter/multiply effects must now be modeled, not become source N/A: %s: %v", instruction, err)
		}
	}
}

func TestARMStatusReadKeepsSourceDefinedCFGFlags(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc not found")
	}
	for _, body := range []string{
		"CMP R0,R0\n CMP.EQ R0,R0\n MOVW CPSR,R0",
		"CMP R0,R0\n BEQ alternate\n CMP $1,R0\n B read\nalternate:\n CMP $2,R0\nread:\n MOVW CPSR,R0",
		"CMP R0,R0\nloop:\n MOVW CPSR,R0\n CMP $0,R0\n BNE loop",
		"B setup\nread:\n MOVW CPSR,R0\n RET\nsetup:\n CMP R0,R0\n B read",
		"MOVW $0x60000000,R0\n MOVW R0,CPSR\n MOVW CPSR,R0",
		"MOVW.S $4(R0),R1\n MOVW CPSR,R0",
		"CMP R0,R0\n MOVW.S R0,R1\n MOVW CPSR,R0",
		"CMP R0,R0\n MOVW.NE.S $4(R0),R1\n MOVW CPSR,R0",
		"MOVD $0.0,F0\n CMPD F0,F0\n WORD $0xeef1fa10\n MOVW CPSR,R0",
	} {
		source := "TEXT flags(SB),$0\n MOVW $0,R0\n " + body + "\n RET\n"
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
			compileLLVMToObject(t, llc, triple, "source-cfg-status.ll", "source-cfg-status.o", ir)
		}
	}
}
