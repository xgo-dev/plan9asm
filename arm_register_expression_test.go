package plan9asm

import "testing"

func TestNormalizeARMParenthesizedRegistersMatchesGoPrefixTables(t *testing.T) {
	for _, tc := range []struct {
		arch Arch
		in   string
		want string
	}{
		{ArchARM, "12(R(1))", "12(R1)"},
		{ArchARM, "R0>>R(1)", "R0>>R1"},
		{ArchARM, "R(1)<<2(R(3))", "R1<<2(R3)"},
		{ArchARM, "[R(0)-R(7)]", "[R0-R7]"},
		{ArchARM, "F(15)", "F15"},
		{ArchARM, "R(16)", "R(16)"},
		{ArchARM64, "R(30)", "R30"},
		{ArchARM64, "R(31)", "R(31)"},
		{ArchARM64, "F(31), V(31).B16, Z(31).D2, P(15).B, PN(15).D", "F31, V31.B16, Z31.D2, P15.B, PN15.D"},
		{ArchARM64, "P(16), PN(16)", "P(16), PN(16)"},
		{ArchARM64, "SPR(269)", "SPR(269)"},
	} {
		if got := normalizeARMParenthesizedRegisters(tc.arch, tc.in); got != tc.want {
			t.Errorf("normalizeARMParenthesizedRegisters(%v, %q) = %q, want %q", tc.arch, tc.in, got, tc.want)
		}
	}
}

func TestParseARMNumericRegisterExpressionsFromOfficialAssemblerCorpus(t *testing.T) {
	file, err := Parse(ArchARM, "TEXT probe(SB),NOSPLIT,$0-0\nADD R(1)<<R(2), R(3), R(4)\nRET\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Funcs) != 1 || len(file.Funcs[0].Instrs) != 3 {
		t.Fatalf("parsed functions = %#v", file.Funcs)
	}
	ins := file.Funcs[0].Instrs[1]
	if len(ins.Args) != 3 || ins.Args[0].Kind != OpRegShift || ins.Args[0].Reg != "R1" || ins.Args[0].ShiftReg != "R2" || ins.Args[1].Kind != OpReg || ins.Args[1].Reg != "R3" || ins.Args[2].Kind != OpReg || ins.Args[2].Reg != "R4" {
		t.Fatalf("ADD operands = %#v, want R1<<R2, R3, R4", ins.Args)
	}
	if err := ProbeInstruction(ArchARM, "arm", ins); err != nil {
		t.Fatalf("official ARM ADD register-expression form is not lowerable: %v", err)
	}
}
