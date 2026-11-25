package plan9asm

import (
	"strings"
	"testing"
)

func translateAndVerifyAMD64(t *testing.T, fnName, src string) string {
	t.Helper()
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse %s failed: %v", fnName, err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return "m2." + strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m2." + fnName: {Name: "m2." + fnName, Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate %s failed: %v", fnName, err)
	}
	verifyLLVMIRWithOpt(t, ir)
	verifyLLVMIRWithHaswellLLC(t, ir)
	return ir
}

func TestM2_AMD64FMAAndCVT(t *testing.T) {
	ir := translateAndVerifyAMD64(t, "fmaCvt", `
GLOBL gbuf<>(SB), NOPTR, $64
TEXT ·fmaCvt(SB),NOSPLIT,$0-0
	// Family 1: FMA3 packed + scalar + 4FMA
	VFMADD132PS X0, X1, X2
	VFMADD213PD Y0, Y1, Y2
	VFMADD231PS.BCST.Z 8(BX), Z1, K1, Z2
	VFMSUB132PD Z0, Z1, K2, Z2
	VFNMADD213PS.RN_SAE Z0, Z1, K3, Z2
	VFNMSUB231PD Y0, Y1, K1, Y2
	VFMADDSUB132PS Z0, Z1, K1, Z2
	VFMSUBADD213PD X0, X1, X2
	VFMADD132SS 8(BX), X1, K1, X2
	VFMSUB213SD.Z X0, X1, K2, X2
	VFNMADD231SS X0, X1, X2
	VFNMSUB132SD 8(BX), X1, X2
	V4FMADDPS 8(BX), [Z0-Z3], K1, Z4
	V4FNMADDPS.Z gbuf<>(SB), [Z0-Z3], K2, Z5
	V4FMADDSS 8(BX), [X0-X3], K1, X4
	V4FNMADDSS.Z gbuf<>(SB), [X0-X3], K2, X5

	// Family 2: Conversions (SSE, VEX, EVEX, FP16, widening, narrowing, scalar)
	CVTPD2PL (BX), X1
	CVTTPD2PL X0, X1
	CVTPD2PS X0, X1
	CVTPL2PD (BX), X1
	CVTPL2PS X0, X1
	CVTPS2PD X0, X1
	CVTPS2PL X0, X1
	CVTTPS2PL X0, X1
	VCVTDQ2PD X0, Y1
	VCVTDQ2PD gbuf<>(SB), Y1
	VCVTDQ2PS.BCST 8(BX), K1, Z1
	VCVTUDQ2PD 8(BX), K2, Y1
	VCVTUDQ2PS Z0, K1, Z1
	VCVTQQ2PD X0, K1, X1
	VCVTQQ2PS Z0, K1, Y1
	VCVTQQ2PSX (BX), K1, X1
	VCVTQQ2PSY (BX), K1, X1
	VCVTUQQ2PD Y0, Y1
	VCVTUQQ2PS Y0, X1
	VCVTPD2DQ Z0, K1, Y1
	VCVTPD2DQX (BX), X1
	VCVTPD2DQY.Z (BX), K1, X1
	VCVTTPD2UDQ Z0, K1, Y1
	VCVTPD2PS Z0, Y1
	VCVTPD2PSX (BX), X1
	VCVTPD2PSY (BX), X1
	VCVTPS2PD X0, Y1
	VCVTPS2PD Y0, K1, Z1
	VCVTPD2QQ Z0, K1, Z1
	VCVTTPD2UQQ X0, K1, X1
	VCVTPS2DQ Z0, K1, Z1
	VCVTTPS2UDQ Z0, K1, Z1
	VCVTPS2QQ Y0, K1, Z1
	VCVTTPS2UQQ.BCST.Z gbuf<>(SB), K2, Z1
	VCVTPH2PS X0, Y1
	VCVTPH2PS 8(BX), K1, Z1
	VCVTPS2PH $7, X0, X1
	VCVTPS2PH $1, Z0, K1, Y1
	VCVTPS2PH $0, X0, (BX)
	VCVTPS2PH $0, Y0, K1, 8(BX)
	VCVTPS2PH $0, X0, gbuf<>(SB)
	VCVTSD2SI X0, AX
	VCVTSD2SIQ 8(BX), AX
	VCVTSD2USIL X0, R9
	VCVTSD2USIQ X0, R9
	VCVTSS2SI X0, AX
	VCVTTSS2USIQ 8(BX), AX
	VCVTUSI2SDL AX, X0, X1
	VCVTUSI2SDQ 8(BX), X0, X1
	VCVTUSI2SSL AX, X0, X1
	VCVTUSI2SSQ AX, X0, X1
	RET
`)
	for _, want := range []string{"@llvm.fma.v16f32", "fptrunc <16 x float>", "fpext <16 x half>"} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in FMA/CVT IR", want)
		}
	}
}

func TestM2_AMD64VecExtFamilies3To6(t *testing.T) {
	ir := translateAndVerifyAMD64(t, "vecExt", `
GLOBL gbuf2<>(SB), NOPTR, $64
TEXT ·vecExt(SB),NOSPLIT,$0-0
	// Family 3: Packed Int Extended
	VPMAXSQ Z0, Z1, K1, Z2
	VPMAXUQ Y0, Y1, Y2
	VPMINSQ X0, X1, X2
	VPMINUQ Z0, Z1, K2, Z2
	VPSLLVW Z0, Z1, K1, Z2
	VPSRLVW Y0, Y1, Y2
	VPSRAVW X0, X1, X2
	PSHUFW $0x1b, M0, M1
	VPMOVB2M Z0, K1
	VPMOVW2M Y0, K2
	VPMOVD2M X0, K3
	VPMOVQ2M Z0, K4
	VPMOVM2B K1, Z0
	VPMOVM2W K2, Y0
	VPMOVM2D K3, X0
	VPMOVM2Q K4, Z0
	VPMOVWB Z0, K1, Y1
	VPMOVDB Z0, K1, X1
	VPMOVDB X0, (BX)
	VPMOVSDB Z0, K2, 8(BX)
	VPMOVSDW.Z Z0, K2, Y1
	VPMOVUSQB Y0, K1, gbuf2<>(SB)
	VPMOVUSQD Z0, K1, Y1
	PHADDW X0, X1
	PHADDD 8(BX), X1
	PHADDSW X0, X1
	PHSUBW X0, X1
	PHSUBD X0, X1
	PHSUBSW X0, X1
	VPHADDW Y0, Y1, Y2
	VPHADDSW X0, X1, X2
	VPHSUBD Y0, Y1, Y2
	VPHSUBSW Y0, Y1, Y2
	PMADDWL X0, X1
	VPMADDWD Z0, Z1, K1, Z2
	PMADDUBSW X0, X1
	VPMADDUBSW Y0, Y1, K2, Y2
	PMULHRSW X0, X1
	VPMULHRSW Z0, Z1, K1, Z2
	VPMADD52LUQ X0, X1, K1, X2
	VPMADD52HUQ.BCST 8(BX), Y1, K2, Y2
	VPDPBUSD X0, X1, K1, X2
	VPDPBUSDS Y0, Y1, K1, Y2
	VPDPWSSD Z0, Z1, K1, Z2
	VPDPWSSDS.Z Z0, Z1, K2, Z2
	VP4DPWSSD 8(BX), [Z0-Z3], K1, Z4
	VP4DPWSSDS.Z 8(BX), [Z0-Z3], K2, Z5
	VPSHLDW $3, X0, X1, K1, X2
	VPSHLDD.BCST $5, 8(BX), Z1, K1, Z2
	VPSHRDQ $7, Y0, Y1, K2, Y2
	VPSHLDVW X0, X1, K1, X2
	VPSHRDVQ.Z Z0, Z1, K2, Z2
	MPSADBW $3, X0, X1
	VMPSADBW $5, Y0, Y1, Y2
	VDBPSADBW $0x1b, Z0, Z1, K1, Z2
	VPMULTISHIFTQB.BCST 8(BX), Y1, K2, Y2

	// Family 4: Vec Compare & Test
	VCMPPS $0, X0, X1, X2
	VCMPPD $14, Y0, Y1, Y2
	VCMPPS $42, Z0, Z1, K1, K2
	VCMPPD.BCST $5, 8(BX), Z1, K1, K2
	VCMPSS $7, 8(BX), X1, X2
	VCMPSD.SAE $0, X0, X1, K1, K2
	VPTESTMB Z0, Z1, K1, K2
	VPTESTMW Y0, Y1, K2
	VPTESTMD.BCST 8(BX), Z1, K1, K2
	VPTESTNMQ Z0, Z1, K1, K2
	PTEST X0, X1
	VTESTPS Y0, Y1
	VTESTPD 8(BX), X1

	// Family 5: Gather & Scatter (AVX2 + AVX-512 + baseless VSIB)
	VGATHERDPS X0, 8(X1*1), X2
	VGATHERDPS X0, (BX)(X1), X2
	VGATHERDPD Y0, (BX)(X1*4), Y2
	VPGATHERQQ Y0, (BP)(Y1*2), Y2
	VGATHERQPD (DX)(Z1*1), K1, Z2
	VPGATHERDD 16(R8)(Z1*4), K2, Z2
	VPGATHERQD gbuf2<>(SB)(X1*2), K3, X2
	VPSCATTERDD Z0, K1, (AX)(Z1*2)
	VSCATTERDPD Z0, K2, (R10)(Y1*8)
	VSCATTERQPS X0, K3, (R14)(Y1*8)
	VPSCATTERQQ Y0, K4, (BP)(Y1*4)

	// Family 6: Permute / Expand / Conflict / LZCNT / Rotate / Broadcast / K-Test
	VPLZCNTD Z0, K1, Z1
	VPLZCNTQ.BCST.Z 8(BX), K2, Z1
	VPROLVD Z0, Z1, K1, Z2
	VPRORVQ.BCST 8(BX), Y1, K2, Y2
	VPERMD Y0, Y1, Y2
	VPERMPS Z0, Z1, K1, Z2
	VPERMW X0, X1, K2, X2
	VPERMI2W X0, X1, K1, X2
	VPERMI2D Z0, Z1, K1, Z2
	VPERMI2PD.BCST 8(BX), Y1, K2, Y2
	VPERMT2B X0, X1, K1, X2
	VPERMT2Q.Z Z0, Z1, K2, Z2
	VPEXPANDB X0, K1, X1
	VPEXPANDW.Z Y0, K2, Y1
	VPEXPANDD 8(BX), K3, Z1
	VEXPANDPD Z0, Z1
	VPCONFLICTD X0, K1, X1
	VPCONFLICTQ.Z Y0, K2, Y1
	VBROADCASTF128 8(BX), Y1
	VBROADCASTF32X4 8(BX), K1, Z1
	VBROADCASTF32X8.Z 8(BX), K2, Z1
	VBROADCASTI32X2 X0, K1, Y1
	VBROADCASTI64X2 8(BX), K2, Y1
	VPBROADCASTMB2Q K1, Z1
	VPBROADCASTMW2D K2, Y1
	KTESTB K1, K2
	KTESTW K1, K2
	KTESTD K1, K2
	KTESTQ K1, K2
	KORTESTB K1, K2
	KORTESTW K1, K2
	KORTESTD K1, K2
	KORTESTQ K1, K2
	KUNPCKBW K1, K2, K3
	KUNPCKWD K1, K2, K3
	KUNPCKDQ K1, K2, K3
	VPSHUFBITQMB X0, X1, K1, K2
	VPSHUFBITQMB Z0, Z1, K2
	RET
`)
	for _, want := range []string{
		"@llvm.masked.gather.",
		"@llvm.masked.scatter.",
		"@llvm.fshl.",
		"@llvm.fshr.",
		"@llvm.ctlz.",
	} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in VecExt IR", want)
		}
	}
}

func TestM2_ErrorPaths(t *testing.T) {
	bad := []string{
		"VFMADD132PS X0, X1",
		"VFMADD132PS X0, X1, AX",
		"VFMADD132SS X0, X1, AX",
		"V4FMADDPS X0, X1, Z2",
		"V4FMADDPS $1, [Z0-Z3], Z2",
		"V4FMADDPS (BX), [Z0-Z3], AX",
		"V4FMADDPS (BX), [AX-DX], Z2",
		"VCVTUSI2SDL AX, X0",
		"VCVTSD2USIL X0",
		"VCVTPS2PH X0, X1",
		"VCVTPS2PH $0, X0, $1",
		"VCVTPS2PH $0, AX, X1",
		"VCVTDQ2PS X0",
		"VCVTDQ2PS (BX), (BX)",
		"VCVTDQ2PS $1, X1",
		"VCVTDQ2PD X0, (BX)",
		"VCVTDQ2PS X0, AX",
		"PSHUFW $1, M0, X1",
		"VPMOVB2M Z0",
		"VPMOVB2M Z0, AX",
		"VPMOVB2M AX, K1",
		"VPMOVM2B AX, Z0",
		"VPMOVM2B K1, AX",
		"VPMOVDB Z0",
		"VPMOVDB AX, X1",
		"VPMOVDB Z0, AX",
		"VPMOVDB Z0, $1",
		"PHADDW X0",
		"VPHADDW X0, X1",
		"VPHADDW X0, X1, AX",
		"VP4DPWSSD (BX), $1, Z1",
		"VP4DPWSSD (BX), [Z0-Z3], AX",
		"VP4DPWSSD (BX), [AX-DX], Z2",
		"PMADDWL X0",
		"VPMADDWD X0, X1",
		"VPMADDWD X0, X1, AX",
		"VPSHLDW X0, X1, X2",
		"VPSHLDW $1, X0, X1, AX",
		"VPSHLDVW X0, X1",
		"VPSHLDVW X0, X1, AX",
		"VPMULTISHIFTQB X0, X1",
		"VPMULTISHIFTQB X0, X1, AX",
		"MPSADBW X0, X1",
		"MPSADBW $1, X0, AX",
		"VMPSADBW $1, X0, X1",
		"VCMPPS X0, X1, X2",
		"VCMPPS $0, (BX), (BX), K1",
		"VPTESTMB Z0, Z1",
		"VPTESTMB (BX), (BX), K1",
		"PTEST X0",
		"PTEST X0, AX",
		"VGATHERDPS X0, X1",
		"VGATHERDPS X0, (BX), X2",
		"VGATHERDPS X0, (BX)(X1*4), $1",
		"VGATHERDPS X0, (BX)(X1*4), AX",
		"VGATHERDPS $1, (BX)(X1*4), X2",
		"VGATHERDPS AX, (BX)(X1*4), X2",
		"VPSCATTERDD Z0, AX, (BX)(Z1*4)",
		"VPSCATTERDD AX, K1, (BX)(Z1*4)",
		"VPSCATTERDD Z0, K1, (BX)",
		"VPLZCNTD Z0",
		"VPLZCNTD Z0, AX",
		"VPERMD X0, X1",
		"VPERMD X0, X1, AX",
		"VPEXPANDD X0",
		"VPEXPANDD X0, AX",
		"VPCONFLICTD X0",
		"VPCONFLICTD X0, AX",
		"VBROADCASTF32X4 (BX)",
		"VBROADCASTF32X4 (BX), AX",
		"VPBROADCASTMB2Q AX, Z1",
		"VPBROADCASTMB2Q K1, AX",
		"KTESTB K1",
		"KUNPCKBW K1, K2",
		"VPSHUFBITQMB X0, X1",
		"VPSHUFBITQMB (BX), (BX), K1",
	}
	for _, body := range bad {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
		file, err := Parse(ArchAMD64, src)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			ResolveSym:   func(s string) string { return "m2." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m2.bad": {Name: "m2.bad", Ret: Void}},
		})
		if err == nil {
			t.Errorf("expected error for: %s", body)
		}
	}
}
