package plan9asm

import "testing"

func TestTypeHelperCoverage(t *testing.T) {
	cases := []struct {
		op   Operand
		want string
	}{
		{Operand{Kind: OpImm, Imm: 7}, "$7"},
		{Operand{Kind: OpImm, ImmRaw: "$(A+1)"}, "$(A+1)"},
		{Operand{Kind: OpReg, Reg: AX}, "AX"},
		{Operand{Kind: OpRegExtend, Reg: "R2", Ext: ExtendUXTB}, "R2.UXTB"},
		{Operand{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftLeft, ShiftAmount: 2}, "R1<<2"},
		{Operand{Kind: OpRegShift, Reg: "R2", ShiftOp: ShiftRight, ShiftReg: "R3"}, "R2>>R3"},
		{Operand{Kind: OpFP, FPName: "arg", FPOffset: 8}, "arg+8(FP)"},
		{Operand{Kind: OpFPAddr, FPName: "arg", FPOffset: 16}, "$arg+16(FP)"},
		{Operand{Kind: OpIdent, Ident: "MIDR_EL1"}, "MIDR_EL1"},
		{Operand{Kind: OpSym, Sym: "foo(SB)"}, "foo(SB)"},
		{Operand{Kind: OpLabel, Sym: "loop"}, "loop:"},
		{Operand{Kind: OpMem, Mem: MemRef{Base: SI, Off: 8}}, "8(SI)"},
		{Operand{Kind: OpMem, Mem: MemRef{Base: BX, Off: -4, Index: CX, Scale: 2}}, "-4(BX)(CX*2)"},
		{Operand{Kind: OpMem, Mem: MemRef{Base: "R1", Index: "R2", IndexExt: ExtendUXTW, Scale: 4}}, "0(R1)(R2.UXTW<<2)"},
		{Operand{Kind: OpMem, Mem: MemRef{Base: BX, Index: CX, Segment: GS}}, "0(BX)(CX)(GS)"},
		{Operand{Kind: OpMem, Mem: MemRef{Sym: "table<>(SB)", Index: BX}}, "table<>(SB)(BX)"},
		{Operand{Kind: OpMem, Mem: MemRef{Off: 0x30, Segment: GS}}, "48(GS)"},
		{Operand{Kind: OpMem, Mem: MemRef{Base: CX, Segment: GS}}, "0(CX)(GS)"},
		{Operand{Kind: OpRegList, RegList: []Reg{"R0", "R1"}}, "(R0, R1)"},
		{Operand{}, "<invalid>"},
	}
	for _, want := range []Reg{FS, GS} {
		if got, ok := parseReg(string(want)); !ok || got != want {
			t.Fatalf("parseReg(%q) = (%q, %v)", want, got, ok)
		}
	}
	for _, tc := range cases {
		if got := tc.op.String(); got != tc.want {
			t.Fatalf("Operand.String() = %q, want %q", got, tc.want)
		}
	}

	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"foo(SB)", true},
		{"label<>", true},
		{"$foo+4(SB)", true},
		{"pkg/path.sym[SB]", true},
		{"runtime·bar+8(SB)", true},
		{"plainIdent", false},
		{"bad sym with space", false},
	} {
		_, ok := parseSym(tc.in)
		if ok != tc.want {
			t.Fatalf("parseSym(%q) ok = %v, want %v", tc.in, ok, tc.want)
		}
	}

	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"8(SI)", true},
		{"-4(BX)(CX*2)", true},
		{"(AX)(BX)", true},
		{"(R1)(R2<<3)", true},
		{"(R1)(R2.UXTW<<2)", true},
		{"(R1)(R2.SXTW)", true},
		{"(R1)(R2.UXTB)", false},
		{"(R1)(R2.UXTW<<5)", false},
		{"-1(AX*2)", true},
		{"(0*8)(R8)(BX*8)", true},
		{"(symSize)(R14)", true},
		{"0x30(GS)", true},
		{"0(CX)(GS)", true},
		{"0(GS)(FS)", false},
		{"not-mem", false},
	} {
		_, ok := parseMem(tc.in)
		if ok != tc.want {
			t.Fatalf("parseMem(%q) ok = %v, want %v", tc.in, ok, tc.want)
		}
	}
	if mem, ok := parseMem("(R1)(R2.SXTW<<2)"); !ok || mem.Base != "R1" || mem.Index != "R2" || mem.IndexExt != ExtendSXTW || mem.Scale != 4 {
		t.Fatalf("parseMem(extended index) = (%#v, %v)", mem, ok)
	}

	for _, tc := range []struct {
		in   string
		want uint64
		ok   bool
	}{
		{"1+2*3", 7, true},
		{"8/2", 4, true},
		{"9%4", 1, true},
		{"1<<65", 0, true},
		{"8>>65", 0, true},
		{"7&3", 3, true},
		{"7|8", 15, true},
		{"7^3", 4, true},
		{"7&^3", 4, true},
		{"~1", ^uint64(1), true},
		{"1/0", 0, false},
	} {
		got, ok := parseImmExpr(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseImmExpr(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	for _, tc := range []struct {
		in   string
		want float64
		ok   bool
	}{
		{"1.5+2.5", 4.0, true},
		{"-(3.0)", -3.0, true},
		{"6/2", 3.0, true},
		{"1/0", 0, false},
	} {
		got, ok := parseImmFloatExpr(tc.in)
		if ok != tc.ok || (ok && got != tc.want) {
			t.Fatalf("parseImmFloatExpr(%q) = (%v, %v), want (%v, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestTypeParserEdgeCoverage(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Reg
		ok   bool
	}{
		{"rax", AX, true},
		{"ah", AH, true},
		{"w3", "R3", true},
		{"g", "R28", true},
		{"lr", "R30", true},
		{"r18_platform", "R18", true},
		{"k7", "K7", true},
		{"v2.b16", "V2.B16", true},
		{"f31", "F31", true},
		{"zz", "", false},
	} {
		got, ok := parseReg(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("parseReg(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}

	for _, tc := range []struct {
		in    string
		want  int64
		raw   bool
		valid bool
	}{
		{"$0xffffffffffffffff", -1, false, true},
		{"$64-31", 33, false, true},
		{"$1.25", 4608308318706860032, false, true},
		{"$(16 + callbackArgs__size)", 0, true, true},
		{"$()", 0, false, false},
	} {
		got, ok := parseImm(tc.in)
		if got != tc.want || ok != tc.valid {
			t.Fatalf("parseImm(%q) = (%d, %v), want (%d, %v)", tc.in, got, ok, tc.want, tc.valid)
		}
		if tc.valid && isSymbolicImmPlaceholder(tc.in) != tc.raw {
			t.Fatalf("isSymbolicImmPlaceholder(%q) = %v, want %v", tc.in, !tc.raw, tc.raw)
		}
	}
	if isSymbolicImmPlaceholder("$symbol") {
		t.Fatalf("isSymbolicImmPlaceholder($symbol) unexpectedly succeeded")
	}

	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"arg+8(FP)", true},
		{"arg(FP)", true},
		{"arg-8(FP)", true},
		{"arg+8(SP)", false},
		{"$ret+16(FP)", true},
		{"$ret(FP)", true},
	} {
		if _, _, ok := parseFP(tc.in); ok != tc.want && tc.in[0] != '$' {
			t.Fatalf("parseFP(%q) ok = %v, want %v", tc.in, ok, tc.want)
		}
		if tc.in[0] == '$' {
			if _, _, ok := parseFPAddr(tc.in); ok != tc.want {
				t.Fatalf("parseFPAddr(%q) ok = %v, want %v", tc.in, ok, tc.want)
			}
		}
	}

	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"R1@>3", true},
		{"R2->R3", true},
		{"R4<<1+2", true},
		{"R4<<bad", false},
		{"<<2", false},
	} {
		_, _, _, _, ok := parseRegShift(tc.in)
		if ok != tc.want {
			t.Fatalf("parseRegShift(%q) ok = %v, want %v", tc.in, ok, tc.want)
		}
	}

	if regs, ok := expandRegRange("R7-R5"); !ok || len(regs) != 3 || regs[0] != "R7" || regs[2] != "R5" {
		t.Fatalf("expandRegRange(desc) = (%v, %v)", regs, ok)
	}
	if _, ok := expandRegRange("R1-V3"); ok {
		t.Fatalf("expandRegRange(mixed) unexpectedly succeeded")
	}
	if _, _, _, ok := regRangeParts("SP"); ok {
		t.Fatalf("regRangeParts(SP) unexpectedly succeeded")
	}
	if regs, ok := expandRegRange("Z22.B-Z23.B"); !ok || len(regs) != 2 || regs[0] != "Z22.B" || regs[1] != "Z23.B" {
		t.Fatalf("expandRegRange(SVE vectors) = (%v, %v)", regs, ok)
	}
	if regs, ok := expandRegRange("P10.H"); !ok || len(regs) != 1 || regs[0] != "P10.H" {
		t.Fatalf("expandRegRange(SVE predicate) = (%v, %v)", regs, ok)
	}
	if _, ok := expandRegRange("Z22.B-Z23.H"); ok {
		t.Fatalf("expandRegRange(mixed SVE lane widths) unexpectedly succeeded")
	}

	for _, tc := range []struct {
		in   string
		want OperandKind
	}{
		{"[R0-R2, R5]", OpRegList},
		{"[Z22.B-Z23.B]", OpRegList},
		{"[P10.H, P11.H]", OpRegList},
		{"(R0, R1)", OpRegList},
		{"MIDR_EL1", OpIdent},
		{"helper<>(SB)", OpSym},
		{"R1@>2", OpRegShift},
		{"R2.UXTB", OpRegExtend},
	} {
		op, err := parseOperand(tc.in)
		if err != nil || op.Kind != tc.want {
			t.Fatalf("parseOperand(%q) = (%v, %v), want kind %v", tc.in, err, op.Kind, tc.want)
		}
	}
	rangeOperand, err := parseOperand("[Z4.Q-Z5.Q]")
	if err != nil || !rangeOperand.RegListRange {
		t.Fatalf("parseOperand(SVE range) = (%+v, %v), want range provenance", rangeOperand, err)
	}
	listOperand, err := parseOperand("[Z4.Q, Z5.Q]")
	if err != nil || listOperand.RegListRange {
		t.Fatalf("parseOperand(SVE list) = (%+v, %v), want non-range provenance", listOperand, err)
	}
	if reg, ext, ok := parseRegExtend("r3.sxtw"); !ok || reg != "R3" || ext != ExtendSXTW {
		t.Fatalf("parseRegExtend(r3.sxtw) = (%q, %q, %v)", reg, ext, ok)
	}
	if _, _, ok := parseRegExtend("R2.BAD"); ok {
		t.Fatalf("parseRegExtend(R2.BAD) unexpectedly succeeded")
	}
	if _, err := parseOperand("[]"); err == nil {
		t.Fatalf("parseOperand([]) unexpectedly succeeded")
	}
	if _, err := parseOperand("[R0, bad]"); err == nil {
		t.Fatalf("parseOperand([R0, bad]) unexpectedly succeeded")
	}
}
