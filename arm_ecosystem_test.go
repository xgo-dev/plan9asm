package plan9asm

import (
	"strings"
	"testing"
)

func translateARMCompleteForms(t *testing.T, src string, sigs map[string]FuncSig) string {
	t.Helper()
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs:         sigs,
	})
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-complete-forms.ll", "arm-complete-forms.o", ll)
	return ll
}

func rejectARMFormsOutsideGo127Optabs(t *testing.T, instructions []string) {
	t.Helper()
	for _, instruction := range instructions {
		t.Run(strings.NewReplacer(" ", "_", "(", "_", ")", "_").Replace(instruction), func(t *testing.T) {
			file, err := Parse(ArchARM, "TEXT bad(SB),0,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Goarch:       "arm",
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ARM optabs", instruction)
			}
		})
	}
}

func TestTranslateARMScalarFloatMoveFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT floatmoves(SB),0,$0-0
	CMP R0, R0
	MOVF F0, F1
	MOVD F1, F2
	MOVF $0.5, F3
	MOVD $0.5, F4
	MOVF F0, 4(R1)
	MOVF 4(R1), F0
	MOVD F1, 8(R1)
	MOVD 8(R1), F1
	MOVF F0, 8192(R1)
	MOVF 8192(R1), F0
	MOVD F1, 8192(R1)
	MOVD 8192(R1), F1
	MOVF F0, float32global(SB)
	MOVF float32global(SB), F0
	MOVD F1, float64global(SB)
	MOVD float64global(SB), F1
	MOVF.EQ F0, F1
	MOVD.NE F1, F2
	MOVF.P F0, 4(R1)
	MOVD.W 8(R1), F0
	MOVF.PW F0, 4(R1)
	MOVD.U 8(R1), F0
	RET

TEXT floatframe(SB),0,$0-8
	MOVF x+0(FP), F0
	MOVF F0, ret+4(FP)
	RET

TEXT doubleframe(SB),0,$0-16
	MOVD x+0(FP), F0
	MOVD F0, ret+8(FP)
	RET
`, map[string]FuncSig{
		"floatmoves": {Name: "floatmoves", Ret: Void},
		"floatframe": {
			Name: "floatframe", Args: []LLVMType{LLVMType("float")}, Ret: LLVMType("float"),
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: LLVMType("float"), Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 4, Type: LLVMType("float"), Index: 0, Field: -1}},
			},
		},
		"doubleframe": {
			Name: "doubleframe", Args: []LLVMType{LLVMType("double")}, Ret: LLVMType("double"),
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: LLVMType("double"), Index: 0, Field: -1}},
			},
		},
	})
	for _, want := range []string{
		"load i32", "store i32", "load i64", "store i64", "add i32",
		"load i32, ptr %fp_arg_0", "load i64, ptr %fp_arg_0", "br i1",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM float-move family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMScalarFloatMoveFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"MOVF R0, F0",
		"MOVD F0, R0",
		"MOVF (R0), (R1)",
		"MOVD $0.5, (R0)",
		"MOVF F0",
		"MOVD.S F0, F1",
		"MOVF.P F0, F1",
	})
}

func TestTranslateARMFloatUnaryAndConvertFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT floatunary(SB),0,$0-0
	CMP R0, R0
	NEGF F0, F1
	NEGD.EQ F1, F2
	ABSF F2, F3
	ABSD.NE F3, F4
	SQRTF F4, F5
	SQRTD F5, F6
	MOVFD F6, F7
	MOVDF F7, F0
	RET
`, map[string]FuncSig{"floatunary": {Name: "floatunary", Ret: Void}})
	for _, want := range []string{
		"fneg float", "fneg double", "@llvm.fabs.f32", "@llvm.fabs.f64",
		"@llvm.sqrt.f32", "@llvm.sqrt.f64", "fpext float", "fptrunc double", "br i1",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM float unary/convert family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMFloatUnaryAndConvertFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"SQRTD F0",
		"SQRTF F0, R1",
		"ABSD (R0), F1",
		"ABSF F0, (R1)",
		"NEGD F0, F1, F2",
		"MOVFD.S F0, F1",
		"MOVDF.P F0, F1",
	})
}

func TestTranslateARMScalarFloatArithmeticFamilyCompleteGo127Forms(t *testing.T) {
	// Go 1.27 routes this whole family through AADDF's two optab rows. Plain
	// arithmetic permits both Fsrc,Fdst and Fsrc1,Fsrc2,Fdst; accumulating
	// variants require the explicit three-register form.
	ll := translateARMCompleteForms(t, `
TEXT floatarithmetic(SB),0,$0-0
	CMP R0, R0
	ADDF F0, F1
	ADDD.EQ F0, F1, F2
	SUBF F0, F1
	SUBD.NE F0, F1, F2
	MULF F0, F1
	MULD F0, F1, F2
	NMULF F0, F1
	NMULD F0, F1, F2
	DIVF F0, F1
	DIVD F0, F1, F2
	MULAF F0, F1, F2
	MULAD F0, F1, F2
	MULSF F0, F1, F2
	MULSD F0, F1, F2
	NMULAF F0, F1, F2
	NMULAD F0, F1, F2
	NMULSF F0, F1, F2
	NMULSD F0, F1, F2
	FMULAF F0, F1, F2
	FMULAD F0, F1, F2
	FMULSF F0, F1, F2
	FMULSD F0, F1, F2
	FNMULAF F0, F1, F2
	FNMULAD F0, F1, F2
	FNMULSF F0, F1, F2
	FNMULSD F0, F1, F2
	RET
`, map[string]FuncSig{"floatarithmetic": {Name: "floatarithmetic", Ret: Void}})
	for _, want := range []string{"fadd float", "fadd double", "fsub float", "fmul float", "fdiv float", "fneg float", "br i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM scalar float-arithmetic family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMScalarFloatArithmeticFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"ADDF F0",
		"ADDF R0, F1",
		"ADDD F0, R1",
		"SUBF F0, F1, F2, F3",
		"MULAF F0, F1",
		"NMULSD F0, F1",
		"FMULAF F0, F1",
		"FNMULSD F0, F1",
		"DIVF F0, (R1)",
		"ADDF.S F0, F1",
	})
}

func TestTranslateARMWordFloatConversionFamilyCompleteGo127Forms(t *testing.T) {
	// MOV{W}{F,D} converts signed/unsigned 32-bit integers to floating point;
	// MOV{F,D}W truncates floating point to signed/unsigned 32-bit integers.
	// Go's optab permits the integer bits to live in either an R or F register.
	ll := translateARMCompleteForms(t, `
TEXT wordfloatconversions(SB),0,$0-0
	CMP R0, R0
	MOVWF R0, F0
	MOVWF F0, F1
	MOVWF.U R1, F2
	MOVWF.EQ F2, F3
	MOVWD R2, F4
	MOVWD F4, F5
	MOVWD.U R3, F6
	MOVWD.NE F6, F7
	MOVFW F0, R4
	MOVFW F1, F2
	MOVFW.U F2, R5
	MOVFW.EQ F3, F4
	MOVDW F4, R6
	MOVDW F5, F6
	MOVDW.U F6, R7
	MOVDW.NE F7, F8
	RET
`, map[string]FuncSig{"wordfloatconversions": {Name: "wordfloatconversions", Ret: Void}})
	for _, want := range []string{"sitofp i32", "uitofp i32", "fptosi float", "fptoui float", "fptosi double", "br i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM word/float conversion family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMWordFloatConversionFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"MOVWF R0",
		"MOVWF (R0), F0",
		"MOVWF R0, R1",
		"MOVWD F0, R0",
		"MOVFW R0, F0",
		"MOVFW F0, (R1)",
		"MOVDW F0, F1, F2",
		"MOVFW.P F0, R0",
		"MOVWD.S R0, F0",
	})
}

func TestTranslateARMWordRegisterBitTransferSubfamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT wordregisterbittransfers(SB),0,$0-0
	CMP R0, R0
	MOVW R0, F0
	MOVW F0, R1
	MOVW.EQ R2, F3
	MOVW.NE F3, R4
	RET
`, map[string]FuncSig{"wordregisterbittransfers": {Name: "wordregisterbittransfers", Ret: Void}})
	for _, want := range []string{"trunc i64", "zext i32", "br i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM MOVW R/F bit-transfer IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMWordRegisterBitTransferSubfamilyRejectsNonGoForms(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"MOVW $1, F0",
		"MOVW (R0), F0",
		"MOVW F0, (R1)",
		"MOVW F0, F1",
		"MOVW.S R0, F0",
	})
}

func TestTranslateARMPreloadFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT preloadforms(SB),0,$0-0
	CMP R0, R0
	PLD (R0)
	PLD 4095(R1)
	PLD -4095(R2)
	PLD (2*64)(R3)
	PLD.EQ 64(R4)
	RET
`, map[string]FuncSig{"preloadforms": {Name: "preloadforms", Ret: Void}})
	if !strings.Contains(ll, "@llvm.prefetch.p0") || !strings.Contains(ll, "br i1") {
		t.Fatalf("ARM PLD family IR is incomplete:\n%s", ll)
	}
}

func TestTranslateARMPreloadFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"PLD",
		"PLD R0",
		"PLD 4096(R0)",
		"PLD -4096(R0)",
		"PLD (R0)(R1)",
		"PLD source(SB)",
		"PLD.P (R0)",
		"PLD.W (R0)",
		"PLD.U (R0)",
		"PLD.S (R0)",
	})
}

func TestTranslateARMScalarFloatCompareFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT floatcompareforms(SB),0,$0-0
	CMP R0, R0
	CMPF F0
	BGT compare1
compare1:
	CMPF F0, F1
	BLT compare2
compare2:
	CMPD F2
	BEQ compare3
compare3:
	CMPD.EQ F2, F3
	BVS done
done:
	RET
`, map[string]FuncSig{"floatcompareforms": {Name: "floatcompareforms", Ret: Void}})
	for _, want := range []string{"fcmp oeq float", "fcmp olt float", "fcmp uge float", "fcmp uno float", "fcmp oeq double"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM scalar float-compare family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMScalarFloatCompareFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"CMPF",
		"CMPF R0",
		"CMPF F0, R1",
		"CMPD (R0)",
		"CMPD F0, F1, F2",
		"CMPF.S F0, F1",
	})
}

func TestTranslateARMRawVFPCompareAndVMRSFamily(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT rawvfpcompare(SB),0,$0-0
	WORD $0xeeb56ac0 // VCMPE.F32 F6, #0
	WORD $0xeef1fa10 // VMRS APSR_nzcv, FPSCR
	BGT rawgreater
rawgreater:
	WORD $0xeeb42ac0 // VCMPE.F32 F2, F0
	WORD $0xeef1fa10
	BLT done
	WORD $0xeeb41ac4 // VCMPE.F32 S2, S8 (Go F1, F4)
	WORD $0xeef1fa10
	MOVF.GT F1, F4
done:
	RET
`, map[string]FuncSig{"rawvfpcompare": {Name: "rawvfpcompare", Ret: Void}})
	if !strings.Contains(ll, "fcmp") || !strings.Contains(ll, "br i1") {
		t.Fatalf("raw ARM VFP compare/VMRS sequence was not modeled:\n%s", ll)
	}
}

func TestDecodeARMRawVFPCompareFamily(t *testing.T) {
	tests := []struct {
		name    string
		word    uint32
		bits    int
		zeroRHS bool
	}{
		{"vcmp-f32-register", 0xeeb40a40, 32, false},
		{"vcmpe-f32-register", 0xeeb40ac0, 32, false},
		{"vcmp-f32-zero", 0xeeb50a40, 32, true},
		{"vcmpe-f32-zero", 0xeeb50ac0, 32, true},
		{"vcmp-f64-register", 0xeeb40b40, 64, false},
		{"vcmpe-f64-register", 0xeeb40bc0, 64, false},
		{"vcmp-f64-zero", 0xeeb50b40, 64, true},
		{"vcmpe-f64-zero", 0xeeb50bc0, 64, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			word := test.word | 3<<12
			if !test.zeroRHS {
				word |= 2
			}
			decoded, ok := decodeARMRawVFPCompare(word)
			if !ok {
				t.Fatalf("decodeARMRawVFPCompare(%#08x) failed", test.word)
			}
			wantLHS := 6
			if test.bits == 64 {
				wantLHS = 3
			}
			if decoded.bits != test.bits || decoded.zeroRHS != test.zeroRHS || decoded.lhs != wantLHS {
				t.Fatalf("decodeARMRawVFPCompare(%#08x) = %#v", test.word, decoded)
			}
			if test.zeroRHS && decoded.rhs != 0 {
				t.Fatalf("zero comparison rhs = %d, want zero encoding", decoded.rhs)
			}
		})
	}
	for _, word := range []uint32{
		0xeeb50a41, // zero form must encode Vm=0.
		0xeeb50a60, // zero form must also have M=0.
		0xfeb40a40, // unconditional/reserved condition field.
	} {
		if decoded, ok := decodeARMRawVFPCompare(word); ok {
			t.Fatalf("decodeARMRawVFPCompare(%#08x) = %#v, want rejected", word, decoded)
		}
	}
}

func TestTranslateARMDivModFamilyCompleteGo127Forms(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT divmod(SB),0,$0-0
	CMP R0, R0
	DIV R0, R1
	DIV R0, R1, R2
	DIVU R0, R1
	DIVU.EQ R0, R1, R2
	MOD R0, R1
	MOD.NE R0, R1, R2
	MODU R0, R1
	MODU R0, R1, R2
	RET
`, map[string]FuncSig{"divmod": {Name: "divmod", Ret: Void}})
	for _, want := range []string{"sdiv i32", "udiv i32", "srem i32", "urem i32", "select i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM div/mod family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMDivModFamilyRejectsFormsOutsideGo127Optabs(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"DIV $2, R1",
		"DIV (R0), R1",
		"DIV R0, (R1)",
		"DIV R0, R1, (R2)",
		"DIVU R0",
		"MODU R0, R1, R2, R3",
		"MOD.S R0, R1",
	})
}

func TestTranslateARMFrameAddressIncludesParametersAndInteriorOffsets(t *testing.T) {
	ll := translateARMCompleteForms(t, `
TEXT frameaddr(SB),0,$0-12
	MOVW $word+0(FP), R0
	MOVW $wordhi+4(FP), R1
	MOVW $ret+8(FP), R2
	RET
`, map[string]FuncSig{
		"frameaddr": {
			Name: "frameaddr", Args: []LLVMType{I64}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
	})
	for _, want := range []string{"ptrtoint ptr %fp_arg_0 to i32", "getelementptr i8, ptr %fp_arg_0, i32 4", "ptrtoint ptr %fp_ret_0 to i32"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM frame-address IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMExplicitShiftFamily(t *testing.T) {
	file, err := Parse(ArchARM, `
TEXT shifts(SB),NOSPLIT,$0-0
	CMP $0, R0
	SLL $3, R0
	SLL $5, R0, R1
	SLL R2, R1
	SLL R2, R1, R3
	SRL $3, R3
	SRL $5, R3, R4
	SRL R2, R4
	SRL R2, R4, R5
	SRA $3, R5
	SRA $5, R5, R6
	SRA R2, R6
	SRA.EQ.S R2, R6, R7
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs:         map[string]FuncSig{"shifts": {Name: "shifts", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shl i32", "lshr i32", "ashr i32", "and i32", "icmp ugt i32", "select i1"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("shift-family IR missing %q:\n%s", want, ll)
		}
	}
}

func TestTranslateARMExplicitShiftFamilyRejectsNonGoForms(t *testing.T) {
	for _, instruction := range []string{
		"SLL R0",
		"SRL $257, R0",
		"SRA $1, $2, R0",
		"SLL $1, R0, 0(R1)",
		"SRL R0, R1, R2, R3",
	} {
		file, err := Parse(ArchARM, "TEXT bad(SB),NOSPLIT,$0-0\n"+instruction+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "armv7-unknown-linux-gnueabihf",
			Goarch:       "arm",
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate(%q) unexpectedly succeeded", instruction)
		}
	}
}

func TestTranslateARMFallbackI64Return(t *testing.T) {
	file, err := Parse(ArchARM, `
TEXT helper(SB),NOSPLIT,$0-0
	MOVW $1, R0
	MOVW $2, R1
	B done
done:
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs: map[string]FuncSig{
			"helper": {Name: "helper", Ret: I64},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARMRawTSTFeedsConditionalInstruction(t *testing.T) {
	file, err := Parse(ArchARM, `
TEXT rawtst(SB),NOSPLIT,$0-0
	WORD $0xe1180008
	MOVW.EQ $1, R0
	WORD $0xe31e0003
	MOVW.NE $2, R0
	RET
`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		Sigs:         map[string]FuncSig{"rawtst": {Name: "rawtst", Ret: Void}},
	}); err != nil {
		t.Fatal(err)
	}
}
