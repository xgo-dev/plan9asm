//go:build !llgo
// +build !llgo

package plan9asm

import "testing"

func TestTranslateAMD64PEXTRDToMemory(t *testing.T) {
	src := `
TEXT pextrdmem(SB),NOSPLIT,$0-0
	PEXTRD $3, X5, 16(DI)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"pextrdmem": {Name: "pextrdmem", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64PEXTRQToMemory(t *testing.T) {
	src := `
TEXT pextrqmem(SB),NOSPLIT,$0-0
	PEXTRQ $1, X5, 16(DI)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"pextrqmem": {Name: "pextrqmem", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64VectorBroadcastForms(t *testing.T) {
	src := `
TEXT broadcastvec(SB),NOSPLIT,$0-0
	VBROADCASTI128 (AX), Y0
	VBROADCASTF32X2 (AX), Z0
	VBROADCASTSD (AX), Y1
	VXORPD Y0, Y1, Y1
	VPTERNLOGD $0x96, Y0, Y1, Y1
	VGF2P8AFFINEQB $0, Y0, Y1, Y1
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"broadcastvec": {Name: "broadcastvec", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestAMD64VectorLoweringBranchCoverage(t *testing.T) {
	c, _ := newAMD64CtxWithFuncForTest(t, Func{}, FuncSig{Name: "example.vectorEdges", Ret: Void}, nil)
	imm := func(v int64) Operand { return Operand{Kind: OpImm, Imm: v} }
	reg := func(r string) Operand { return Operand{Kind: OpReg, Reg: Reg(r)} }
	ident := func(name string) Operand { return Operand{Kind: OpIdent, Ident: name} }
	mem := func(base string) Operand {
		return Operand{Kind: OpMem, Mem: MemRef{Base: Reg(base)}}
	}
	check := func(name string, op Op, ins Instr, wantErr bool, wantOK bool) {
		t.Helper()
		ok, _, err := c.lowerVec(op, ins)
		if wantErr && err == nil {
			t.Fatalf("%s: lowerVec(%s) error = nil", name, op)
		}
		if !wantErr && err != nil {
			t.Fatalf("%s: lowerVec(%s) error = %v", name, op, err)
		}
		if ok != wantOK {
			t.Fatalf("%s: lowerVec(%s) ok = %v, want %v", name, op, ok, wantOK)
		}
	}

	check("gf2-z-source-class", "VGF2P8AFFINEQB", Instr{Args: []Operand{imm(0), reg("Z0"), reg("X1"), reg("Z2")}}, false, false)
	check("gf2-z-source-error", "VGF2P8AFFINEQB", Instr{Args: []Operand{imm(0), reg("Z0"), ident("bad"), reg("Z2")}}, true, true)
	check("gf2-y-source-class", "VGF2P8AFFINEQB", Instr{Args: []Operand{imm(0), reg("Y0"), reg("X1"), reg("Y2")}}, false, false)
	check("gf2-y-source-error", "VGF2P8AFFINEQB", Instr{Args: []Operand{imm(0), reg("Y0"), ident("bad"), reg("Y2")}}, true, true)
	check("gf2-unsupported-dst", "VGF2P8AFFINEQB", Instr{Args: []Operand{imm(0), reg("Y0"), reg("Y1"), reg("X2")}}, false, false)

	check("broadcast-i128-args", "VBROADCASTI128", Instr{Args: []Operand{reg("X0")}}, true, true)
	check("broadcast-i128-dst", "VBROADCASTI128", Instr{Args: []Operand{reg("X0"), reg("X1")}}, false, false)
	check("broadcast-i128-source", "VBROADCASTI128", Instr{Args: []Operand{ident("bad"), reg("Y1")}}, true, true)
	check("broadcast-scalar-args", "VBROADCASTSD", Instr{Args: []Operand{imm(1)}}, true, true)
	check("broadcast-scalar-source", "VBROADCASTSD", Instr{Args: []Operand{ident("bad"), reg("Y1")}}, true, true)
	check("broadcast-scalar-dst", "VBROADCASTSD", Instr{Args: []Operand{imm(1), reg("X1")}}, false, false)

	check("xorpd-args", "VXORPD", Instr{Args: []Operand{reg("X0")}}, true, true)
	check("xorpd-z", "VXORPD", Instr{Args: []Operand{reg("Z0"), reg("Z1"), reg("Z2")}}, false, true)
	check("xorpd-z-source1", "VXORPD", Instr{Args: []Operand{ident("bad"), reg("Z1"), reg("Z2")}}, true, true)
	check("xorpd-z-source2", "VXORPD", Instr{Args: []Operand{reg("Z0"), ident("bad"), reg("Z2")}}, true, true)
	check("xorpd-y", "VXORPD", Instr{Args: []Operand{reg("Y0"), reg("Y1"), reg("Y2")}}, false, true)
	check("xorpd-y-source1", "VXORPD", Instr{Args: []Operand{ident("bad"), reg("Y1"), reg("Y2")}}, true, true)
	check("xorpd-y-source2", "VXORPD", Instr{Args: []Operand{reg("Y0"), ident("bad"), reg("Y2")}}, true, true)
	check("xorpd-x", "VXORPD", Instr{Args: []Operand{reg("X0"), reg("X1"), reg("X2")}}, false, true)
	check("xorpd-x-source1", "VXORPD", Instr{Args: []Operand{ident("bad"), reg("X1"), reg("X2")}}, true, true)
	check("xorpd-x-source2", "VXORPD", Instr{Args: []Operand{reg("X0"), ident("bad"), reg("X2")}}, true, true)
	check("xorpd-unsupported-dst", "VXORPD", Instr{Args: []Operand{reg("X0"), reg("X1"), reg("AX")}}, false, false)

	check("ternlog-y-source1-class", "VPTERNLOGD", Instr{Args: []Operand{imm(0x96), reg("X0"), reg("Y1"), reg("Y2")}}, false, false)
	check("ternlog-y-source2-class", "VPTERNLOGD", Instr{Args: []Operand{imm(0x96), reg("Y0"), reg("X1"), reg("Y2")}}, false, false)
	check("ternlog-y-imm", "VPTERNLOGD", Instr{Args: []Operand{imm(0x95), reg("Y0"), reg("Y1"), reg("Y2")}}, true, true)
	check("ternlog-y-source1", "VPTERNLOGD", Instr{Args: []Operand{imm(0x96), ident("bad"), reg("Y1"), reg("Y2")}}, true, true)
	check("ternlog-y-source2", "VPTERNLOGD", Instr{Args: []Operand{imm(0x96), reg("Y0"), ident("bad"), reg("Y2")}}, true, true)

	check("pextrq-args", "PEXTRQ", Instr{Args: []Operand{imm(0)}}, true, true)
	check("pextrq-source", "PEXTRQ", Instr{Args: []Operand{imm(0), reg("AX"), reg("BX")}}, false, false)
	check("pextrq-reg", "PEXTRQ", Instr{Args: []Operand{imm(0), reg("X0"), reg("AX")}}, false, true)
	check("pextrq-mem", "PEXTRQ", Instr{Args: []Operand{imm(0), reg("X0"), mem("BAD")}}, false, true)
	check("pextrq-dst", "PEXTRQ", Instr{Args: []Operand{imm(0), reg("X0"), ident("bad")}}, true, true)

	if got := llvmRepeatI8Mask(0, 3); got != "<i32 0, i32 0, i32 0>" {
		t.Fatalf("llvmRepeatI8Mask(0, 3) = %q", got)
	}
}

func TestTranslateAMD64CallThroughMemory(t *testing.T) {
	src := `
TEXT callmem(SB),NOSPLIT,$0-0
	CALL (BX)(CX*8)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"callmem": {Name: "callmem", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateAMD64MovDAliasToGPR(t *testing.T) {
	src := `
TEXT movdalias(SB),NOSPLIT,$0-0
	MOVD $0, BP
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"movdalias": {Name: "movdalias", Ret: Void},
		},
		Goarch: "amd64",
	})
	if err != nil {
		t.Fatal(err)
	}
}
