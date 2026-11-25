package plan9asm

import (
	"strings"
	"testing"
)

func verifyDeclarativeIR(t *testing.T, arch Arch, goarch string, src string) string {
	t.Helper()
	file, err := Parse(arch, src)
	if err != nil {
		t.Fatalf("Parse(%s) failed: %v\n%s", goarch, err, src)
	}
	sigs := map[string]FuncSig{}
	for _, fn := range file.Funcs {
		sigs[fn.Sym] = FuncSig{Name: fn.Sym, Ret: Void}
	}
	opts := Options{
		Goarch: goarch,
		Sigs:   sigs,
	}
	ir, err := Translate(file, opts)
	if err != nil {
		t.Fatalf("Translate(%s) failed: %v\n%s", goarch, err, src)
	}
	mod, err := TranslateModule(file, opts)
	if err != nil {
		t.Fatalf("TranslateModule(%s) failed LLVM verification: %v\nIR:\n%s", goarch, err, ir)
	}
	mod.Dispose()
	return ir
}

func TestDeclarativeARMLLVMVerify(t *testing.T) {
	src := `
TEXT ·armAll(SB),0,$0-0
	RSC R1, R2, R3
	SLL $3, R1, R2
	SRL R1, R2, R3
	SRA $2, R2, R3
	XTAB R1, R2, R3
	XTABU R1, R2, R3
	XTAH R1, R2, R3
	XTAHU R1, R2, R3
	BFC $4, $8, R3
	BFI $4, $8, R1, R3
	BFX $4, $8, R1, R3
	BFXU $4, $8, R1, R3
	RBIT R1, R2
	REV R1, R2
	REV16 R1, R2
	REVSH R1, R2
	DIVHW R1, R2, R3
	DIVUHW R1, R2
	MULL R1, R2, (R3, R4)
	MULS R1, R2, R3, R4
	MMUL R1, R2, R3
	MMULA R1, R2, R3, R4
	MMULS R1, R2, R3, R4
	MULBB R1, R2, R3
	MULABB R1, R2, R3, R4
	SWPW R1, (R2), R3
	SWPBU R1, (R2), R3
	PLD (R1)
	ADDF F1, F2, F3
	ADDD F1, F2, F3
	SUBF F1, F2, F3
	SUBD F1, F2, F3
	MULF F1, F2, F3
	MULD F1, F2, F3
	DIVF F1, F2, F3
	DIVD F1, F2, F3
	NMULF F1, F2, F3
	ABSF F1, F2
	NEGD F1, F2
	SQRTF F1, F2
	SQRTD F1, F2
	CMPF F1, F2
	CMPD F1, F2
	MOVDF F1, F2
	MOVFD F1, F2
	MOVDW F1, F2
	MOVWD F1, F2
	MOVFW F1, F2
	MOVWF F1, F2
	MULAF F1, F2, F3
	MULSD F1, F2, F3
	FMULAD F1, F2, F3
	FNMULSF F1, F2, F3
	MOVF $(1.5), F1
	MOVD $(2.25), F2
	RET
`
	ir := verifyDeclarativeIR(t, ArchARM, "arm", src)
	for _, want := range []string{"@llvm.bitreverse.i32", "@llvm.bswap.i32", "@llvm.sqrt.f32", "@llvm.fma.f64"} {
		if !strings.Contains(ir, want) {
			t.Errorf("ARM IR missing expected intrinsic %s", want)
		}
	}
}

func TestDeclarativeARM64LLVMVerify(t *testing.T) {
	src := `
TEXT ·arm64All(SB),0,$0-0
	// Scalar ALU/Bit/MulDiv/PAC
	ADDSW R1, R2, R3
	ADCW R1, R2, R3
	ADCSW R1, R2, R3
	SBCW R1, R2, R3
	SBCSW R1, R2, R3
	BICS R1, R2, R3
	BICSW R1, R2, R3
	EON R1, R2, R3
	ORNW R1, R2, R3
	CMNW R1, R2
	NEGS R1, R2
	NGC R1, R2
	SXTB R1, R2
	SXTHW R1, R2
	SXTW R1, R2
	UXTBW R1, R2
	UXTHW R1, R2
	MOVK $(0x1234<<16), R2
	CLZW R1, R2
	CLS R1, R2
	CLSW R1, R2
	RBITW R1, R2
	EXTRW $5, R1, R2, R3
	SDIV R1, R2, R3
	SDIVW R1, R2, R3
	UDIVW R1, R2, R3
	MNEG R1, R2, R3
	SMULL R1, R2, R3
	UMULL R1, R2, R3
	SMADDL R1, R2, R3, R4
	UMSUBL R1, R2, R3, R4
	SMULH R1, R2, R3
	PACIASP
	AUTIASP
	BTI
	HINT $7
	CLREX

	// LSE Atomics & Exclusives
	LDADDALW R1, (R2), R3
	LDCLRALD R1, (R2), R3
	LDEORALH R1, (R2), R3
	LDORALB R1, (R2), R3
	LDSMAXALD R1, (R2), R3
	LDUMINALW R1, (R2), R3
	SWPALD R1, (R2), R3
	CASALD R1, (R2), R3
	CASPALD (R0, R1), (R2), (R4, R5)
	LDARH (R2), R3
	STLRH R3, (R2)
	LDXRW (R2), R3
	STXRW R3, (R2), R4
	LDXP (R2), (R3, R4)
	STXP (R3, R4), (R2), R5

	// Scalar FP + FCCMP + FCSELS
	FADDS F1, F2, F3
	FSUBS F1, F2, F3
	FMULS F1, F2, F3
	FDIVS F1, F2, F3
	FNMULS F1, F2, F3
	FMAXS F1, F2, F3
	FMINS F1, F2, F3
	FMAXNMD F1, F2, F3
	FMINNMS F1, F2, F3
	FABSS F1, F2
	FNEGS F1, F2
	FNEGD F1, F2
	FSQRTS F1, F2
	FSQRTD F1, F2
	FRINTNS F1, F2
	FRINTAD F1, F2
	FMADDS F1, F2, F3, F4
	FNMADDD F1, F2, F3, F4
	FCMPS F1, F2
	FCCMPS LT, F1, F2, $1
	FCCMPD EQ, F1, F2, $4
	FCSELS EQ, F1, F2, F3
	FCVTZSS F1, R1
	FCVTZUDW F2, R2
	SCVTFS R1, F1
	UCVTFWD R2, F2
	FMOVS $(0.0), F1
	FLDPS (R2), (F1, F2)
	FSTPS (F1, F2), (R2)

	// NEON / ASIMD Declarative Matrix
	VABS V0.S4, V1.S4
	VNEG V0.H8, V1.H8
	VNOT V0.B16, V1.B16
	VCLZ V0.S4, V1.S4
	VCNT V0.B16, V1.B16
	VRBIT V0.B16, V1.B16
	VREV16 V0.B16, V1.B16
	VSUB V0.S4, V1.S4, V2.S4
	VMUL V0.H8, V1.H8, V2.H8
	VSMAX V0.S4, V1.S4, V2.S4
	VUMAX V0.B16, V1.B16, V2.B16
	VSQADD V0.H8, V1.H8, V2.H8
	VUQSUB V0.B16, V1.B16, V2.B16
	VSHADD V0.S4, V1.S4, V2.S4
	VBSL V0.B16, V1.B16, V2.B16
	VMLA V0.S4, V1.S4, V2.S4
	VCMGT V0.S4, V1.S4, V2.S4
	VUSHL V0.D2, V1.D2, V2.D2
	VFADD V0.S4, V1.S4, V2.S4
	VFMUL V0.D2, V1.D2, V2.D2
	VFSQRT V0.S4, V1.S4
	VFMLA V0.S4, V1.S4, V2.S4
	VADDV V0.S4, V1
	VADDP V0.D2, V1.D2, V2.D2
	VTRN1 V0.S4, V1.S4, V2.S4
	VUZP2 V0.H8, V1.H8, V2.H8
	VSXTL V0.H4, V1.S4
	VUXTL2 V0.B16, V1.H8
	VUMULL V0.S2, V1.S2, V2.D2
	VXTN V0.S4, V1.H4
	VLD2 (R2), [V0.B16, V1.B16]
	VST2 [V0.B16, V1.B16], (R2)
	RET
`
	ir := verifyDeclarativeIR(t, ArchARM64, "arm64", src)
	for _, want := range []string{"atomicrmw add", "@llvm.abs.v4i32", "@llvm.sadd.sat.v8i16", "@llvm.roundeven.f32", "@llvm.ctpop.v16i8"} {
		if !strings.Contains(ir, want) {
			t.Errorf("ARM64 IR missing expected construct %s", want)
		}
	}
}

func TestDeclarativeAMD64LLVMVerify(t *testing.T) {
	src := `
TEXT ·amd64All(SB),0,$0-0
	// Scalar CMOV/SET/Bit/BMI/Shifts/Narrow/System
	CMPQ AX, BX
	CMOVQGE AX, BX
	CMOVLNE CX, DX
	CMOVWLT SI, DI
	SETEQ AL
	SETNE (BX)
	ADCW AX, BX
	SBBB AL, BL
	INCB AL
	DECW AX
	NEGW BX
	NOTB CL
	LEAW 8(BX), AX
	MOVBLSX AL, DX
	MOVBQSX BL, CX
	MOVWLSX SI, DI
	MOVBWSX AL, DX
	ROLB $3, AL
	RORW $5, AX
	RCLQ $2, AX
	RCRQ CL, BX
	SHRB $2, AL
	SHLW $3, AX, BX
	SHRW $4, CX, DX
	IMUL3W $7, AX, BX
	MULXL CX, R8, R9
	ADCXL AX, BX
	ADOXL CX, DX
	BTQ AX, BX
	BTSL $5, CX
	BTRW AX, DX
	BTCQ $7, SI
	TZCNTL AX, BX
	LZCNTQ CX, DX
	POPCNTW SI, DI
	ANDNQ AX, BX, CX
	BLSIQ AX, BX
	BLSMSKL CX, DX
	BLSRQ SI, DI
	BEXTRL AX, BX, CX
	BZHIL AX, BX, CX
	SHLXQ AX, BX, CX
	SHRXL AX, BX, CX
	SARXQ AX, BX, CX
	RORXQ $7, BX, CX
	CLC
	STC
	CMC
	CBW
	CWDE
	CDQE
	CDQ
	CQO
	ENDBR64
	SLDTQ AX
	SMSWL BX
	STRW CX

	// K-Mask + Scalar FP + Packed SIMD + AVX-512 EVEX masking & broadcast
	KADDB K1, K2, K3
	KANDNW K1, K2, K3
	KXNORQ K1, K2, K3
	KNOTD K1, K2
	KSHIFTLW $3, K1, K2
	KMOVD AX, K1
	ADDSS X1, X2
	MULSS (BX), X2
	VADDSS X1, X2, X3
	VSUBSD X1, X2, K1, X3
	CVTSL2SS AX, X1
	CVTSS2SQ X1, AX
	PABSB X1, X2
	VPABSD Y1, K1, Y2
	VPABSQ.Z Z1, K1, Z2
	PMOVSXBW X1, X2
	VPMOVZXWD X1, Y2
	VPMOVZXBD (BX), K1, Z2
	VPADDSW Y1, Y2, K1, Y3
	VPSUBUSB.Z Z1, Z2, K1, Z3
	VPANDND Z1, Z2, K1, Z3
	VPMULLQ Z1, Z2, K1, Z3
	VADDPS.BCST (BX), Y1, K1, Y2
	VMOVDQU32.Z (BX), K1, Z2
	VPSHUFD $0x1b, (BX), K1, Z2
	VPSHUFB Y1, Y2, K1, Y3
	VPALIGNR $3, X1, X2, K1, X3
	VPBLENDD $5, X1, X2, X3
	VPMOVMSKB X1, AX
	VPMOVMSKB Y1, BX
	PUNPCKLWL X1, X2
	PUNPCKHQDQ X1, X2
	PACKUSWB X1, X2
	VPACKSSDW Y1, Y2, Y3
	VALIGND $2, Z1, Z2, K1, Z3
	VPERMQ $0x1b, Y1, Y2
	VEXTRACTI32X4 $1, Z1, K1, X2
	VINSERTI32X4 $1, X1, Z2, K1, Z3
	VPEXTRW $2, X1, AX
	VPINSRD $1, AX, X1, X2
	PSLLW X1, X2
	PSRLQ X1, X2
	VPSLLD X1, X2, X3
	VPSLLDQ $4, Z1, Z2
	VPSRLVD Y1, Y2, Y3
	VPSRAVQ Z1, Z2, K1, Z3
	PCLMULQDQ $0x11, (BX), X1
	VPCLMULQDQ $0x11, Y1, Y2, Y3
	VAESENC Y1, Y2, Y3
	DPPS $0xf1, X1, X2
	VPSADBW Y1, Y2, Y3
	PHMINPOSUW X1, X2
	PCMPESTRI $0x08, X1, X2
	VPCMPISTRM $0x00, X1, X2
	MOVD X1, DX
	MOVD (BX), X2
	ADCQ R8, 8(DI)
	SBBQ R8, 8(DI)
	VPADDD Z1, Z0, Z0
	VPMULUDQ Y1, Y2, Y3
	VPMULHW Y1, Y2, Y3
	VPRORD $16, Z1, Z2
	VPROLQ $7, Y1, K1, Y2
	VPBROADCASTD 4(DX), Y2
	VPBROADCASTW X1, Y3
	VSHUFI32X4 $0x88, Z2, Z3, Z4
	VMOVSLDUP Y1, Y2
	VPBLENDMD Z1, Z2, K1, Z3
	RET
`
	ir := verifyDeclarativeIR(t, ArchAMD64, "amd64", src)
	for _, want := range []string{"@llvm.cttz.i32", "@llvm.ctlz.i64", "@llvm.abs.v8i32", "@llvm.sadd.sat.v16i16", "@llvm.x86.aesni.aesenc.256", "@llvm.x86.pclmulqdq"} {
		if !strings.Contains(ir, want) {
			t.Errorf("AMD64 IR missing expected intrinsic %s", want)
		}
	}
}
