package plan9asm

import (
	"strings"
	"testing"
)

func TestARMEvalCoverage(t *testing.T) {
	c, b := newARMCtxForTest(t, FuncSig{
		Name: "example.eval",
		Args: []LLVMType{Ptr, I1, I8, I16, I32, I64, "{ ptr, i64 }"},
		Ret:  Void,
		Frame: FrameLayout{
			Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 4, Type: I1, Index: 1, Field: -1},
				{Offset: 8, Type: I8, Index: 2, Field: -1},
				{Offset: 12, Type: I16, Index: 3, Field: -1},
				{Offset: 16, Type: I32, Index: 4, Field: -1},
				{Offset: 20, Type: I64, Index: 5, Field: -1},
				{Offset: 24, Type: I64, Index: 6, Field: 1},
			},
			Results: []FrameSlot{{Offset: 32, Type: I32, Index: 0}},
		},
	}, nil)

	if got, base, inc, err := c.addrI32(MemRef{Base: "R1", Index: "R2", Scale: 4, Off: 8}, true); err != nil || got == "" || base != "R1" || inc != 8 {
		t.Fatalf("addrI32() = (%q, %q, %d, %v)", got, base, inc, err)
	}
	if err := c.updatePostInc("R1", 8); err != nil {
		t.Fatalf("updatePostInc() error = %v", err)
	}
	if _, err := c.loadMem(MemRef{Base: "R3"}, 64, false, false); err != nil {
		t.Fatalf("loadMem(64) error = %v", err)
	}
	if _, err := c.loadMem(MemRef{Base: "R4", Off: 1}, 8, false, true); err != nil {
		t.Fatalf("loadMem(8 signed) error = %v", err)
	}
	if err := c.storeMem(MemRef{Base: "R5"}, 32, false, "7"); err != nil {
		t.Fatalf("storeMem(32) error = %v", err)
	}
	if err := c.storeMem(MemRef{Base: "R6"}, 8, false, "9"); err != nil {
		t.Fatalf("storeMem(8) error = %v", err)
	}

	ops := []Operand{
		{Kind: OpImm, Imm: 7},
		{Kind: OpReg, Reg: "R0"},
		{Kind: OpRegShift, Reg: "R1", ShiftOp: ShiftLeft, ShiftAmount: 2},
		{Kind: OpFP, FPName: "p", FPOffset: 0},
		{Kind: OpFP, FPName: "b", FPOffset: 4},
		{Kind: OpFP, FPName: "c", FPOffset: 8},
		{Kind: OpFP, FPName: "d", FPOffset: 12},
		{Kind: OpFP, FPName: "e", FPOffset: 16},
		{Kind: OpFP, FPName: "f", FPOffset: 20},
		{Kind: OpFP, FPName: "agg", FPOffset: 24},
		{Kind: OpFPAddr, FPName: "ret", FPOffset: 32},
		{Kind: OpMem, Mem: MemRef{Base: "R7", Off: 4}},
		{Kind: OpSym, Sym: "$runtime·main+4(SB)"},
		{Kind: OpIdent, Ident: "CS"},
	}
	if got, err := c.evalFPAddr32(Operand{Kind: OpFPAddr, FPName: "argframe", FPOffset: 99}); err != nil || got != "0" {
		t.Fatalf("evalFPAddr32(dynamic) = (%q, %v), want (0, nil)", got, err)
	}
	if got, err := c.evalFPValue32(Operand{Kind: OpFP, FPName: "f_hi", FPOffset: 24}); err != nil || got == "" {
		t.Fatalf("evalFPValue32(split i64 high) = (%q, %v)", got, err)
	}
	for _, op := range ops {
		if got, err := c.eval32(op, op.Kind == OpMem); err != nil || got == "" {
			t.Fatalf("eval32(%s) = (%q, %v)", op.String(), got, err)
		}
	}
	if _, err := c.eval32(Operand{Kind: OpImm, ImmRaw: "$(bad)"}, false); err == nil {
		t.Fatalf("eval32(unresolved imm) unexpectedly succeeded")
	}
	if _, err := c.evalShift(Operand{Kind: OpRegShift, Reg: "R0", ShiftOp: ShiftRotate, ShiftReg: "R1"}); err != nil {
		t.Fatalf("evalShift(register rotate) error = %v", err)
	}

	out := b.String()
	for _, want := range []string{
		"mul i32",
		"sext i8",
		"store i32 7, ptr",
		"trunc i32 9 to i8",
		"extractvalue { ptr, i64 } %arg6, 1",
		`getelementptr i8, ptr @"runtime.main", i32 4`,
		"ptrtoint ptr",
		"call i32 @llvm.fshr.i32",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMFPAndRetCoverage(t *testing.T) {
	t.Run("StoreAndLoadFPResults", func(t *testing.T) {
		c, b := newARMCtxForTest(t, FuncSig{
			Name: "example.fp",
			Ret:  I64,
			Frame: FrameLayout{
				Results: []FrameSlot{
					{Offset: 8, Type: I32, Index: 0},
					{Offset: 16, Type: I1, Index: 1},
					{Offset: 24, Type: Ptr, Index: 2},
					{Offset: 32, Type: I64, Index: 3},
				},
			},
		}, nil)

		if _, ok := c.fpResultSlotByOffset(8); !ok {
			t.Fatalf("fpResultSlotByOffset(8) not found")
		}
		if _, ok := c.fpResultSlotByOffset(99); ok {
			t.Fatalf("fpResultSlotByOffset(99) unexpectedly found")
		}
		if err := c.storeFPResult32(8, "11"); err != nil {
			t.Fatalf("storeFPResult32(i32) error = %v", err)
		}
		if err := c.storeFPResult32(16, "1"); err != nil {
			t.Fatalf("storeFPResult32(i1) error = %v", err)
		}
		if err := c.storeFPResult32(24, "12"); err != nil {
			t.Fatalf("storeFPResult32(ptr) error = %v", err)
		}
		if err := c.storeFPResult32(32, "13"); err != nil {
			t.Fatalf("storeFPResult32(i64) error = %v", err)
		}
		if _, err := c.loadFPResult(FrameSlot{Index: 3, Type: I64}); err != nil {
			t.Fatalf("loadFPResult() error = %v", err)
		}
		if _, err := c.loadFPResult(FrameSlot{Index: 99, Type: I64}); err == nil {
			t.Fatalf("loadFPResult(missing) unexpectedly succeeded")
		}
		if _, err := c.loadRetSlotFallback(FrameSlot{Type: I16}); err != nil {
			t.Fatalf("loadRetSlotFallback(i16) error = %v", err)
		}

		out := b.String()
		for _, want := range []string{
			"store i32 11, ptr %fp_ret_0",
			"trunc i32 1 to i1",
			"inttoptr i32 12 to ptr",
			"zext i32 13 to i64",
			"load i64, ptr %fp_ret_3",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("missing %q in output:\n%s", want, out)
			}
		}
	})

	t.Run("LowerRETVariants", func(t *testing.T) {
		for _, tc := range []struct {
			ret  LLVMType
			want string
		}{
			{ret: Void, want: "ret void"},
			{ret: I1, want: "ret i1"},
			{ret: I8, want: "ret i8"},
			{ret: I16, want: "ret i16"},
			{ret: I32, want: "ret i32"},
			{ret: Ptr, want: "ret ptr"},
		} {
			c, b := newARMCtxForTest(t, FuncSig{Name: "example.ret", Ret: tc.ret}, nil)
			if err := c.lowerRET(); err != nil {
				t.Fatalf("lowerRET(%s) error = %v", tc.ret, err)
			}
			if !strings.Contains(b.String(), tc.want) {
				t.Fatalf("lowerRET(%s) missing %q in:\n%s", tc.ret, tc.want, b.String())
			}
		}

		c1, b1 := newARMCtxForTest(t, FuncSig{
			Name: "example.ret1",
			Ret:  I32,
			Frame: FrameLayout{
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0}},
			},
		}, nil)
		if err := c1.storeFPResult32(8, "99"); err != nil {
			t.Fatalf("storeFPResult32() error = %v", err)
		}
		if err := c1.lowerRET(); err != nil {
			t.Fatalf("lowerRET(single written) error = %v", err)
		}
		if !strings.Contains(b1.String(), "ret i32 %t") {
			t.Fatalf("lowerRET(single written) missing loaded return in:\n%s", b1.String())
		}

		c2, b2 := newARMCtxForTest(t, FuncSig{
			Name: "example.rettuple",
			Ret:  "{ i32, ptr }",
			Frame: FrameLayout{
				Results: []FrameSlot{
					{Offset: 8, Type: I32, Index: 0},
					{Offset: 16, Type: Ptr, Index: 1},
				},
			},
		}, nil)
		if err := c2.storeFPResult32(8, "5"); err != nil {
			t.Fatalf("storeFPResult32(tuple) error = %v", err)
		}
		c2.markFPResultAddrTaken(16)
		if err := c2.lowerRET(); err != nil {
			t.Fatalf("lowerRET(tuple) error = %v", err)
		}
		for _, want := range []string{"insertvalue { i32, ptr }", "ret { i32, ptr }"} {
			if !strings.Contains(b2.String(), want) {
				t.Fatalf("lowerRET(tuple) missing %q in:\n%s", want, b2.String())
			}
		}

		c3, _ := newARMCtxForTest(t, FuncSig{Name: "example.bad", Ret: LLVMType("token")}, nil)
		if err := c3.lowerRET(); err == nil {
			t.Fatalf("lowerRET(unsupported) unexpectedly succeeded")
		}

		c4, b4 := newARMCtxForTest(t, FuncSig{
			Name: "example.ret64split",
			Ret:  I64,
			Frame: FrameLayout{Results: []FrameSlot{
				{Offset: 0, Type: I32, Index: 0},
				{Offset: 4, Type: I32, Index: 1},
			}},
		}, nil)
		if err := c4.storeFPResult32(0, "1"); err != nil {
			t.Fatal(err)
		}
		if err := c4.storeFPResult32(4, "2"); err != nil {
			t.Fatal(err)
		}
		if err := c4.lowerRET(); err != nil {
			t.Fatalf("lowerRET(split i64) error = %v", err)
		}
		for _, want := range []string{"zext i32", "shl i64", "or i64", "ret i64"} {
			if !strings.Contains(b4.String(), want) {
				t.Fatalf("lowerRET(split i64) missing %q in:\n%s", want, b4.String())
			}
		}

		c5, b5 := newARMCtxForTest(t, FuncSig{
			Name:  "example.ret64writes",
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}},
		}, nil)
		if err := c5.storeFPResult32(0, "1"); err != nil {
			t.Fatal(err)
		}
		if err := c5.storeFPResult32(4, "2"); err != nil {
			t.Fatal(err)
		}
		if err := c5.lowerRET(); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"and i64", "shl i64", "or i64", "ret i64"} {
			if !strings.Contains(b5.String(), want) {
				t.Fatalf("split i64 writes missing %q in:\n%s", want, b5.String())
			}
		}
	})
}

func TestARMArithCoverageDeep(t *testing.T) {
	c, b := newARMCtxForTest(t, FuncSig{Name: "example.arith", Ret: Void}, nil)

	if err := c.lowerARMCompare("CMP", Instr{Raw: "CMP R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMCompare(CMP) error = %v", err)
	}
	for _, ins := range []struct {
		op       string
		cond     string
		setFlags bool
		ins      Instr
	}{
		{op: "ADD", setFlags: true, ins: Instr{Raw: "ADD $1, R0", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R0"}}}},
		{op: "SUB", ins: Instr{Raw: "SUB R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}},
		{op: "AND", cond: "EQ", setFlags: true, ins: Instr{Raw: "AND.EQ.S R0, R2, R3", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R3"}}}},
		{op: "ORR", ins: Instr{Raw: "ORR R1, R3, R4", Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R3"}, {Kind: OpReg, Reg: "R4"}}}},
		{op: "EOR", ins: Instr{Raw: "EOR R2, R4, R5", Args: []Operand{{Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R4"}, {Kind: OpReg, Reg: "R5"}}}},
		{op: "RSB", ins: Instr{Raw: "RSB $10, R5, R6", Args: []Operand{{Kind: OpImm, Imm: 10}, {Kind: OpReg, Reg: "R5"}, {Kind: OpReg, Reg: "R6"}}}},
		{op: "BIC", setFlags: true, ins: Instr{Raw: "BIC.S $1, R6, R7", Args: []Operand{{Kind: OpImm, Imm: 1}, {Kind: OpReg, Reg: "R6"}, {Kind: OpReg, Reg: "R7"}}}},
	} {
		if err := c.lowerARMALU(ins.op, ins.cond, ins.setFlags, ins.ins); err != nil {
			t.Fatalf("lowerARMALU(%s) error = %v", ins.op, err)
		}
	}
	for _, op := range []string{"CMN", "TST", "TEQ"} {
		if err := c.lowerARMCompare(op, Instr{Raw: op + " R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); err != nil {
			t.Fatalf("lowerARMCompare(%s) error = %v", op, err)
		}
	}
	if err := c.lowerARMMVN("EQ", true, Instr{Raw: "MVN.EQ.S R0, R8", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R8"}}}); err != nil {
		t.Fatalf("lowerARMMVN() error = %v", err)
	}
	if err := c.lowerARMADCSBC("ADC", "EQ", true, Instr{Raw: "ADC.EQ.S R1, R8, R9", Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R8"}, {Kind: OpReg, Reg: "R9"}}}); err != nil {
		t.Fatalf("lowerARMADCSBC(ADC) error = %v", err)
	}
	if err := c.lowerARMADCSBC("SBC", "", true, Instr{Raw: "SBC.S R1, R9, R10", Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R9"}, {Kind: OpReg, Reg: "R10"}}}); err != nil {
		t.Fatalf("lowerARMADCSBC(SBC) error = %v", err)
	}
	if err := c.lowerARMMUL("", Instr{Raw: "MUL R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); err != nil {
		t.Fatalf("lowerARMMUL(2-arg) error = %v", err)
	}
	if err := c.lowerARMMUL("EQ", Instr{Raw: "MUL.EQ R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err != nil {
		t.Fatalf("lowerARMMUL(3-arg) error = %v", err)
	}
	if err := c.lowerARMMULLU("EQ", Instr{Raw: "MULLU.EQ R0, R1, (R3, R4)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpRegList, RegList: []Reg{"R3", "R4"}}}}); err != nil {
		t.Fatalf("lowerARMMULLU() error = %v", err)
	}
	if err := c.lowerARMMULA("", Instr{Raw: "MULA R0, R1, R2, R5", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R5"}}}); err != nil {
		t.Fatalf("lowerARMMULA() error = %v", err)
	}
	if err := c.lowerARMMULAL("EQ", Instr{Raw: "MULAL.EQ R0, R1, (R6, R7)", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpRegList, RegList: []Reg{"R6", "R7"}}}}); err != nil {
		t.Fatalf("lowerARMMULAL() error = %v", err)
	}
	if err := c.lowerARMMULAWT("", Instr{Raw: "MULAWT R0, R1, R2, R8", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R8"}}}); err != nil {
		t.Fatalf("lowerARMMULAWT() error = %v", err)
	}
	if err := c.lowerARMDIVUHW("EQ", Instr{Raw: "DIVUHW.EQ R1, R2, R9", Args: []Operand{{Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}, {Kind: OpReg, Reg: "R9"}}}); err != nil {
		t.Fatalf("lowerARMDIVUHW() error = %v", err)
	}
	if err := c.lowerARMCLZ("", Instr{Raw: "CLZ R9, R10", Args: []Operand{{Kind: OpReg, Reg: "R9"}, {Kind: OpReg, Reg: "R10"}}}); err != nil {
		t.Fatalf("lowerARMCLZ() error = %v", err)
	}
	if err := c.lowerARMMRC(Instr{Raw: "MRC $15, $0, R11, $1, $0, $0", Args: []Operand{{Kind: OpImm, Imm: 15}, {Kind: OpImm, Imm: 0}, {Kind: OpReg, Reg: "R11"}, {Kind: OpImm, Imm: 1}, {Kind: OpImm, Imm: 0}, {Kind: OpImm, Imm: 0}}}); err != nil {
		t.Fatalf("lowerARMMRC() error = %v", err)
	}
	if ok, _, err := c.lowerArith("MULU", "", false, Instr{Raw: "MULU R0, R1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}}}); !ok || err != nil {
		t.Fatalf("lowerArith(MULU) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerArith("UNKNOWN", "", false, Instr{}); ok || err != nil {
		t.Fatalf("lowerArith(UNKNOWN) = (%v, %v), want (false, nil)", ok, err)
	}
	if err := c.selectRegPairWrite("R1", "R2", "EQ", "1", "2"); err != nil {
		t.Fatalf("selectRegPairWrite(EQ) error = %v", err)
	}
	if err := c.lowerARMALU("ADD", "", false, Instr{Raw: "ADD R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMALU(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMCompare("CMP", Instr{Raw: "CMP R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMCompare(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMVN("", false, Instr{Raw: "MVN R0, $1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMMVN(invalid dst) unexpectedly succeeded")
	}
	if err := c.lowerARMADCSBC("ADC", "", false, Instr{Raw: "ADC R0, $1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMADCSBC(invalid dst) unexpectedly succeeded")
	}
	if err := c.lowerARMMULLU("", Instr{Raw: "MULLU R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULLU(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULA("", Instr{Raw: "MULA R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULA(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULAL("", Instr{Raw: "MULAL R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULAL(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMULAWT("", Instr{Raw: "MULAWT R0, R1, R2", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpReg, Reg: "R1"}, {Kind: OpReg, Reg: "R2"}}}); err == nil {
		t.Fatalf("lowerARMMULAWT(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMDIVUHW("", Instr{Raw: "DIVUHW R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMDIVUHW(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMCLZ("", Instr{Raw: "CLZ R0, $1", Args: []Operand{{Kind: OpReg, Reg: "R0"}, {Kind: OpImm, Imm: 1}}}); err == nil {
		t.Fatalf("lowerARMCLZ(invalid) unexpectedly succeeded")
	}
	if err := c.lowerARMMRC(Instr{Raw: "MRC $15, R0", Args: []Operand{{Kind: OpImm, Imm: 15}, {Kind: OpReg, Reg: "R0"}}}); err == nil {
		t.Fatalf("lowerARMMRC(invalid) unexpectedly succeeded")
	}

	out := b.String()
	for _, want := range []string{
		"add i32",
		"sub i32",
		"and i32",
		"or i32",
		"xor i32",
		"mul i64",
		"udiv i32",
		"call i32 @llvm.ctlz.i32",
		`asm sideeffect "mrc p15, #0, $0, c1, c0, #0"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestARMBranchMovmAndSyscallCoverage(t *testing.T) {
	sigs := map[string]FuncSig{
		"example.helper": {Name: "example.helper", Ret: Void},
		"example.tail":   {Name: "example.tail", Ret: Void},
	}
	c, b := newARMCtxForTest(t, FuncSig{Name: "example.branch", Ret: Void}, sigs)
	c.flagsWritten = true
	c.blocks = []armBlock{{name: "entry"}, {name: "fall"}}

	var gotBr string
	var gotCond [3]string
	emitBr := func(target string) { gotBr = target }
	emitCondBr := func(cond, target, fall string) error {
		gotCond = [3]string{cond, target, fall}
		return nil
	}
	if ok, term, err := c.lowerBranch(0, "JMP", "", Instr{Raw: "JMP loop", Args: []Operand{{Kind: OpIdent, Ident: "loop"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(JMP) = (%v, %v, %v)", ok, term, err)
	}
	if gotBr != "loop" {
		t.Fatalf("emitBr target = %q, want loop", gotBr)
	}
	if ok, term, err := c.lowerBranch(0, "B", "EQ", Instr{Raw: "B.EQ done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(B.EQ) = (%v, %v, %v)", ok, term, err)
	}
	if gotCond != [3]string{"EQ", "done", "fall"} {
		t.Fatalf("emitCondBr args = %#v", gotCond)
	}
	if ok, term, err := c.lowerBranch(0, "B", "", Instr{Raw: "B tail(SB)", Args: []Operand{{Kind: OpSym, Sym: "tail(SB)"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(B sym) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "BEQ", "", Instr{Raw: "BEQ done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(BEQ) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "BHI", "", Instr{Raw: "BHI done", Args: []Operand{{Kind: OpIdent, Ident: "done"}}}, emitBr, emitCondBr); !ok || !term || err != nil {
		t.Fatalf("lowerBranch(BHI) = (%v, %v, %v)", ok, term, err)
	}
	if ok, term, err := c.lowerBranch(0, "CALL", "", Instr{Raw: "CALL helper(SB)", Args: []Operand{{Kind: OpSym, Sym: "helper(SB)"}}}, emitBr, emitCondBr); !ok || term || err != nil {
		t.Fatalf("lowerBranch(CALL sym) = (%v, %v, %v)", ok, term, err)
	}

	if ok, _, err := c.lowerMOVM("MOVM.IB", Instr{Raw: "MOVM.IB (R13), [R0,R1]", Args: []Operand{{Kind: OpMem, Mem: MemRef{Base: "R13"}}, {Kind: OpRegList, RegList: []Reg{"R0", "R1"}}}}); !ok || err != nil {
		t.Fatalf("lowerMOVM(IB load) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerMOVM("MOVM.DA", Instr{Raw: "MOVM.DA [R2,R3], (R13)", Args: []Operand{{Kind: OpRegList, RegList: []Reg{"R2", "R3"}}, {Kind: OpMem, Mem: MemRef{Base: "R13"}}}}); !ok || err != nil {
		t.Fatalf("lowerMOVM(DA store) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerSyscall("SWI", Instr{Raw: "SWI $1", Args: []Operand{{Kind: OpImm, Imm: 1}}}); !ok || err != nil {
		t.Fatalf("lowerSyscall(SWI imm) = (%v, %v)", ok, err)
	}
	if ok, _, err := c.lowerSyscall("SWI", Instr{Raw: "SWI R0", Args: []Operand{{Kind: OpReg, Reg: "R0"}}}); !ok || err == nil {
		t.Fatalf("lowerSyscall(SWI invalid) = (%v, %v), want error", ok, err)
	}

	c2, _ := newARMCtxForTest(t, FuncSig{Name: "example.callers", Ret: I32}, map[string]FuncSig{
		"example.ret32":     {Name: "example.ret32", Ret: I32},
		"example.retVoid":   {Name: "example.retVoid", Ret: Void},
		"example.retBad":    {Name: "example.retBad", Ret: LLVMType("vector")},
		"example.tailFloat": {Name: "example.tailFloat", Ret: LLVMType("double")},
	})
	if err := c2.callSym(Operand{Kind: OpSym, Sym: "ret32(SB)"}); err != nil {
		t.Fatalf("callSym(ret32) error = %v", err)
	}
	if err := c2.callSym(Operand{Kind: OpSym, Sym: "retVoid(SB)"}); err != nil {
		t.Fatalf("callSym(retVoid) error = %v", err)
	}
	if err := c2.callSym(Operand{Kind: OpSym, Sym: "retBad(SB)"}); err == nil {
		t.Fatalf("callSym(retBad) unexpectedly succeeded")
	}
	if err := c2.callSym(Operand{Kind: OpReg, Reg: "R0"}); err == nil {
		t.Fatalf("callSym(non-sym) unexpectedly succeeded")
	}
	if err := c2.callSym(Operand{Kind: OpSym, Sym: "ret32"}); err == nil {
		t.Fatalf("callSym(no sb) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(Operand{Kind: OpReg, Reg: "R0"}); err == nil {
		t.Fatalf("tailCallAndRet(non-sym) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(Operand{Kind: OpSym, Sym: "ret32"}); err == nil {
		t.Fatalf("tailCallAndRet(no sb) unexpectedly succeeded")
	}
	if err := c2.tailCallAndRet(Operand{Kind: OpSym, Sym: "missing(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(missing sig) error = %v", err)
	}
	if err := c2.tailCallAndRet(Operand{Kind: OpSym, Sym: "tailFloat(SB)"}); err == nil {
		t.Fatalf("tailCallAndRet(mismatch) unexpectedly succeeded")
	}

	cTailPtr, bTailPtr := newARMCtxForTest(t, FuncSig{Name: "example.tailptr", Ret: Ptr}, map[string]FuncSig{
		"example.tailword": {Name: "example.tailword", Ret: I32},
	})
	if err := cTailPtr.tailCallAndRet(Operand{Kind: OpSym, Sym: "tailword(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(i32 -> ptr) error = %v", err)
	}
	if got := bTailPtr.String(); !strings.Contains(got, "inttoptr i32") || !strings.Contains(got, "ret ptr") {
		t.Fatalf("tailCallAndRet(i32 -> ptr) output:\n%s", got)
	}

	cTailWord, bTailWord := newARMCtxForTest(t, FuncSig{Name: "example.tailword", Ret: I32}, map[string]FuncSig{
		"example.tailptr": {Name: "example.tailptr", Ret: Ptr},
	})
	if err := cTailWord.tailCallAndRet(Operand{Kind: OpSym, Sym: "tailptr(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(ptr -> i32) error = %v", err)
	}
	if got := bTailWord.String(); !strings.Contains(got, "ptrtoint ptr") || !strings.Contains(got, "ret i32") {
		t.Fatalf("tailCallAndRet(ptr -> i32) output:\n%s", got)
	}

	floatSig := FuncSig{Name: "example.floatcaller", Args: []LLVMType{LLVMType("float")}, Ret: LLVMType("float")}
	cTailFloat, bTailFloat := newARMCtxForTest(t, floatSig, map[string]FuncSig{
		"example.floatcallee": {Name: "example.floatcallee", Args: []LLVMType{LLVMType("float")}, Ret: LLVMType("float")},
	})
	if err := cTailFloat.tailCallAndRet(Operand{Kind: OpSym, Sym: "floatcallee(SB)"}); err != nil {
		t.Fatalf("tailCallAndRet(identical float signature) error = %v", err)
	}
	if got := bTailFloat.String(); !strings.Contains(got, `call float @"example.floatcallee"(float %arg0)`) || !strings.Contains(got, "ret float") {
		t.Fatalf("tailCallAndRet(identical float signature) output:\n%s", got)
	}

	out := b.String()
	for _, want := range []string{
		`call void @"example.tail"()`,
		"ret void",
		"load i32, ptr",
		"store i32",
		"call i64 @syscall(",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestTranslateARMStraightLineCoverageDeep(t *testing.T) {
	ll := translateARMForTest(t, `TEXT ·linear(SB),NOSPLIT,$0-0
	MOVB $1, R1
	MOVBU $2, R2
	ADD R5, R4, R7
	SUB R1, R7
	AND R2, R7, R8
	ORR R8, R7, R9
	EOR R9, R8, R10
	RSB $1, R10, R11
	MOVW R11<<2, R0
	RET
`, map[string]FuncSig{
		"example.linear": {
			Name:    "example.linear",
			Args:    []LLVMType{I32, I32, I32},
			ArgRegs: []Reg{"R4", "R5", "R6"},
			Ret:     I32,
		},
	})
	for _, want := range []string{
		"store i32 1",
		"store i32 2",
		"add i32",
		"sub i32",
		"and i32",
		"or i32",
		"xor i32",
		"shl i32",
		"ret i32",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in output:\n%s", want, ll)
		}
	}
}
