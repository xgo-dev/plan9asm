package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARM64ScalarSquareRootFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 maps both scalar square-root opcodes to the AFCVTSD optab:
	// exactly one F-register source and one F-register destination.
	src := `
TEXT scalarsquarerootforms(SB),NOSPLIT,$0-0
	FSQRTS F0, F9
	FSQRTD F14, F27
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"scalarsquarerootforms": {Name: "scalarsquarerootforms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, intrinsic := range []string{"@llvm.sqrt.f32", "@llvm.sqrt.f64"} {
		if !strings.Contains(ll, intrinsic) {
			t.Fatalf("scalar square-root lowering omitted %s:\n%s", intrinsic, ll)
		}
	}
}

func TestTranslateARM64ScalarSquareRootFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"FSQRTS F0",
		"FSQRTD F0, F1, F2",
		"FSQRTS R0, F1",
		"FSQRTD F0, R1",
		"FSQRTS.P F0, F1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidscalarsquareroot(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"invalidscalarsquareroot": {Name: "invalidscalarsquareroot", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's AFCVTSD optab", instruction)
			}
		})
	}
}

func TestTranslateARM64ScalarPrecisionConversionCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 maps all six scalar precision conversions to AFCVTSD's single
	// C_FREG -> C_FREG optab row; mnemonic letters specify source then result.
	src := `
TEXT scalarprecisionconversionforms(SB),$0-0
	FCVTSD F0, F31
	FCVTDS F30, F1
	FCVTSH F2, F29
	FCVTHS F28, F3
	FCVTDH F4, F27
	FCVTHD F26, F5
	RET
`
	requireARM64GoAssemblerResult(t, src, true)
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		file, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatal(err)
		}
		ll, err := Translate(file, Options{
			TargetTriple: triple,
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"scalarprecisionconversionforms": {Name: "scalarprecisionconversionforms", Ret: Void},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{
			"fpext float", "fptrunc double",
			"fptrunc float", "to half", "fpext half", "to float",
			"fptrunc double", "to half", "fpext half", "to double",
		} {
			if !strings.Contains(ll, want) {
				t.Fatalf("scalar precision conversion for %s omitted %q:\n%s", triple, want, ll)
			}
		}
		llc := findLLVM22Tool("llc")
		if llc == "" {
			t.Fatal("LLVM 22 llc not found")
		}
		compileLLVMToObject(t, llc, triple, "scalar-precision-conversion.ll", "scalar-precision-conversion.o", ll)
	}
}

func TestTranslateARM64ScalarPrecisionConversionRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"FCVTSD F0",
		"FCVTDS F0, F1, F2",
		"FCVTSH F0",
		"FCVTHS F0, F1, F2",
		"FCVTDH R0, F1",
		"FCVTHD F0, R1",
		"FCVTSD R0, F1",
		"FCVTDS F0, R1",
		"FCVTSD.P F0, F1",
	} {
		src := "TEXT invalidscalarprecisionconversion(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
		file, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs: map[string]FuncSig{
				"invalidscalarprecisionconversion": {Name: "invalidscalarprecisionconversion", Ret: Void},
			},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's scalar precision-conversion optab", instruction)
		}
	}
}

func TestTranslateARM64IntegerToScalarFloatFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 maps these eight opcodes to ASCVTFD's single C_ZREG->C_FREG
	// row. The W spellings consume the low i32; the others consume i64.
	src := `
TEXT integerfloatforms(SB),NOSPLIT,$0-0
	SCVTFD R0, F0
	SCVTFS R1, F1
	SCVTFWD R2, F2
	SCVTFWS R3, F3
	UCVTFD R4, F4
	UCVTFS R5, F5
	UCVTFWD R6, F6
	UCVTFWS ZR, F7
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"integerfloatforms": {Name: "integerfloatforms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"sitofp i64", "sitofp i32", "uitofp i64", "uitofp i32", "to float", "to double"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 integer-to-float family IR omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{"darwin", "arm64-apple-macosx"},
		{"linux", "aarch64-unknown-linux-gnu"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"integerfloatforms": {Name: "integerfloatforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "integer-float-forms.ll", "integer-float-forms.o", ir)
		})
	}
}

func TestTranslateARM64IntegerToScalarFloatFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"SCVTFS F0, F1",
		"SCVTFD (R0), F1",
		"SCVTFWS R0, R1",
		"UCVTFS RSP, F0",
		"UCVTFD R0, F1, F2",
		"UCVTFWS.P R0, F1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT invalidintegerfloat(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"invalidintegerfloat": {Name: "invalidintegerfloat", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's ASCVTFD optab family", instruction)
			}
		})
	}
}

func TestTranslateARM64ScalarFloatBinaryFamilyCompleteGoAssemblerForms(t *testing.T) {
	// All eighteen opcodes share AFADDS's two C_FREG optab rows. Exercise both
	// destructive two-register and explicit three-register forms for each one.
	ops := []string{
		"FADDS", "FADDD", "FSUBS", "FSUBD", "FMULS", "FMULD",
		"FNMULS", "FNMULD", "FDIVS", "FDIVD",
		"FMAXS", "FMAXD", "FMINS", "FMIND",
		"FMAXNMS", "FMAXNMD", "FMINNMS", "FMINNMD",
	}
	var src strings.Builder
	src.WriteString("TEXT scalarfloatbinaryforms(SB),NOSPLIT,$0-0\n")
	for _, op := range ops {
		fmt.Fprintf(&src, "\t%s F0, F1\n", op)
		fmt.Fprintf(&src, "\t%s F2, F3, F4\n", op)
	}
	src.WriteString("\tRET\n")
	file, err := Parse(ArchARM64, src.String())
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"scalarfloatbinaryforms": {Name: "scalarfloatbinaryforms", Ret: Void},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"fadd float", "fadd double", "fsub float", "fmul float", "fneg float", "fdiv float",
		"@llvm.maximum.f32", "@llvm.minimum.f64", "@llvm.maxnum.f32", "@llvm.minnum.f64",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("ARM64 scalar binary floating family IR omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{"darwin", "arm64-apple-macosx"},
		{"linux", "aarch64-unknown-linux-gnu"},
		{"windows", "aarch64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			file, err := Parse(ArchARM64, src.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"scalarfloatbinaryforms": {Name: "scalarfloatbinaryforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-float-binary-forms.ll", "scalar-float-binary-forms.o", ir)
		})
	}
}

func TestTranslateARM64ScalarFloatBinaryFamilyRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"FMULS F0",
		"FMULD F0, F1, F2, F3",
		"FMAXS R0, F1",
		"FMIND F0, R1",
		"FMAXNMS $1, F0",
		"FMINNMD (R0), F1",
		"FNMULS.P F0, F1",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			file, err := Parse(ArchARM64, "TEXT invalidfloatbinary(SB),NOSPLIT,$0-0\n\t"+instruction+"\n\tRET\n")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"invalidfloatbinary": {Name: "invalidfloatbinary", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's AFADDS optab family", instruction)
			}
		})
	}
}

func TestTranslateARM64ScalarFloatMoveFamilyCompleteGoAssemblerForms(t *testing.T) {
	// Go 1.27 gives FMOVS and FMOVD the same complete shape family: floating
	// constant, F<->F, R/ZR<->F, and F<->memory through stack, symbol,
	// immediate-offset, register-offset, post-index, and pre-index addresses.
	src := `
TEXT scalarfloatmoveforms(SB),NOSPLIT,$0-32
	FMOVS $(4.0), F0
	FMOVS F0, F1
	FMOVS R2, F2
	FMOVS ZR, F3
	FMOVS F2, R3
	FMOVS F3, ZR
	FMOVS (R4), F4
	FMOVS F4, 4(R4)
	FMOVS scalar(SB), F5
	FMOVS F5, scalar(SB)
	FMOVS input32+0(FP), F6
	FMOVS F6, result32+16(FP)
	FMOVS.P 4(R7), F7
	FMOVS.P F7, 4(R7)
	FMOVS.W 4(R8), F8
	FMOVS.W F8, 4(R8)
	FMOVS (R9)(R10), F9
	FMOVS F9, (R9)(R10<<2)
	FMOVD $(28.0), F10
	FMOVD F10, F11
	FMOVD R12, F12
	FMOVD ZR, F13
	FMOVD F12, R13
	FMOVD F13, ZR
	FMOVD (R14), F14
	FMOVD F14, 8(R14)
	FMOVD scalar(SB), F15
	FMOVD F15, scalar(SB)
	FMOVD input64+8(FP), F16
	FMOVD F16, result64+24(FP)
	FMOVD.P 8(R17), F17
	FMOVD.P F17, 8(R17)
	FMOVD.W 8(R18), F18
	FMOVD.W F18, 8(R18)
	FMOVD (R19)(R20), F19
	FMOVD F19, (R19)(R20<<3)
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		ResolveSym:   func(sym string) string { return strings.TrimPrefix(sym, "·") },
		Sigs: map[string]FuncSig{
			"scalarfloatmoveforms": {
				Name: "scalarfloatmoveforms",
				Args: []LLVMType{LLVMType("float"), LLVMType("double")},
				Ret:  LLVMType("{ float, double }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: LLVMType("float"), Index: 0, Field: -1},
						{Offset: 8, Type: LLVMType("double"), Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: LLVMType("float"), Index: 0, Field: -1},
						{Offset: 24, Type: LLVMType("double"), Index: 1, Field: -1},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"load i32", "store i32", "load i64", "store i64", "bitcast float", "bitcast double"} {
		if !strings.Contains(ll, want) {
			t.Fatalf("complete scalar float-move lowering omitted %q:\n%s", want, ll)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "aarch64-unknown-linux-gnu", "scalar-float-moves.ll", "scalar-float-moves.o", ll)
}

func TestTranslateARM64ScalarFloatMoveFamilyRejectsFormsOutsideGoOptabs(t *testing.T) {
	for _, instruction := range []string{
		"FMOVS F0",
		"FMOVD F0, F1, F2",
		"FMOVS (R0), R1",
		"FMOVD R0, (R1)",
		"FMOVS $(1.0), R1",
		"FMOVD.P F0, F1",
		"FMOVS.Z F0, F1",
		"FMOVS (R0)(R1<<3), F0",
		"FMOVD F0, (R0)(R1<<2)",
	} {
		t.Run(strings.ReplaceAll(instruction, " ", "_"), func(t *testing.T) {
			src := "TEXT invalidscalarfloatmove(SB),NOSPLIT,$0-0\n\t" + instruction + "\n\tRET\n"
			file, err := Parse(ArchARM64, src)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"invalidscalarfloatmove": {Name: "invalidscalarfloatmove", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q, which is absent from Go 1.27's FMOVS/FMOVD optabs", instruction)
			}
		})
	}
}

func TestTranslateARM64BranchMinus(t *testing.T) {
	src := `
TEXT branchminus(SB),NOSPLIT,$0-0
loop:
	SUBS $32, R2
	BMI complete
	SUBS $32, R2
	BPL loop
complete:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"branchminus": {Name: "branchminus", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "br i1") {
		t.Fatalf("BMI did not lower to a conditional branch:\n%s", ll)
	}
}

func TestTranslateARM64RawFlagWords(t *testing.T) {
	src := `
TEXT rawflags(SB),NOSPLIT,$0-0
	MOVD $2, R0
	WORD $0xea00001f // TST X0, X0
	BEQ done
loop:
	WORD $0xf1000400 // SUBS X0, X0, #1
	BNE loop
done:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"rawflags": {Name: "rawflags", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "sub i64") || strings.Count(ll, "br i1") != 2 {
		t.Fatalf("raw TST/SUBS flag words did not lower as expected:\n%s", ll)
	}
}

func TestTranslateARM64TST(t *testing.T) {
	src := `
TEXT testflags(SB),NOSPLIT,$0-0
	MOVD $1, R0
	TST R0, R0
	BEQ done
done:
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"testflags": {Name: "testflags", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ll, "and i64") || !strings.Contains(ll, "br i1") {
		t.Fatalf("TST did not lower to flags and a conditional branch:\n%s", ll)
	}
}

func TestTranslateARM64FLDPQ(t *testing.T) {
	src := `
TEXT pairload(SB),NOSPLIT,$0-0
	MOVD $4096, R1
	FLDPQ (R1), (F0, F1)
	FLDPQ.P 32(R1), (F0, F1)
	VMOVI $7, V2.B16
	VMOVI $3, V3.B8
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"pairload": {Name: "pairload", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ll, "load <16 x i8>") != 4 || !strings.Contains(ll, "store <16 x i8>") || !strings.Contains(ll, "i8 7") || !strings.Contains(ll, "i8 3") {
		t.Fatalf("FLDPQ/VMOVI did not lower as expected:\n%s", ll)
	}
}

func TestTranslateARM64NarrowImmediateAndFPVectorAlias(t *testing.T) {
	src := `
TEXT aliases(SB),NOSPLIT,$0-0
	MOVW $0x89abcdef, R2
	MOVD $0x89abcdef, R3
	MOVW R3, R4
	MOVD $4096, R1
	FMOVQ (R1), F0
	FMOVD F0, R2
	FMOVD R2, F1
	FMOVQ F1, (R1)
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"aliases": {Name: "aliases", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"zext i32",
		"sext i32",
		"extractelement <2 x i64>",
		"insertelement <2 x i64> zeroinitializer",
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in narrow/alias lowering:\n%s", want, ll)
		}
	}
	for _, unwanted := range []string{"%reg_F0 = alloca i64", "%reg_F1 = alloca i64"} {
		if strings.Contains(ll, unwanted) {
			t.Fatalf("found split scalar FP state %q:\n%s", unwanted, ll)
		}
	}
}

func TestTranslateARM64SHA3Families(t *testing.T) {
	src := `
TEXT sha3ops(SB),NOSPLIT,$0-0
	VEOR3	V20.B16, V15.B16, V10.B16, V25.B16
	VRAX1	V27.D2, V25.D2, V30.D2
	VXAR	$63, V30.D2, V1.D2, V25.D2
	VBCAX	V8.B16, V22.B16, V26.B16, V20.B16
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"sha3ops": {Name: "sha3ops", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64BarrierFamilies(t *testing.T) {
	src := `
TEXT barrierops(SB),NOSPLIT,$0-0
	DSB $7
	ISB $15
	DC ZVA, R0
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"barrierops": {Name: "barrierops", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64FeatureProbeMRS(t *testing.T) {
	src := `
TEXT featureprobe(SB),NOSPLIT,$0-0
	MRS ID_AA64ISAR0_EL1, R0
	MRS ID_AA64PFR0_EL1, R1
	MRS ID_AA64ZFR0_EL1, R2
	MRS MIDR_EL1, R3
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"featureprobe": {Name: "featureprobe", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64CompareWithExtendedRegister(t *testing.T) {
	src := `
TEXT countcmp(SB),NOSPLIT,$0-0
	CMP	R2.UXTB, R5
	CINC	EQ, R11, R11
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"countcmp": {Name: "countcmp", Ret: Void},
		},
		Goarch: "arm64",
	})
	if err != nil {
		t.Fatal(err)
	}
}
