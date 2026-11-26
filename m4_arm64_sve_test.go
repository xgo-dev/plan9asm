package plan9asm

import (
	"os/exec"
	"strings"
	"testing"
)

func verifyARM64LLVMAndLLC(t *testing.T, ir string) string {
	t.Helper()
	verifyLLVMIRWithOpt(t, ir)
	llc, err := exec.LookPath("llc")
	if err != nil {
		return ""
	}
	var linuxAsm string
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "arm64-apple-darwin"} {
		args := []string{"-mtriple=" + triple}
		if triple == "aarch64-unknown-linux-gnu" {
			args = append(args, "-filetype=asm", "-o", "-")
		} else {
			args = append(args, "-filetype=null")
		}
		cmd := exec.Command(llc, args...)
		cmd.Stdin = strings.NewReader(ir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("llc (%s) codegen failed: %v\noutput:\n%s", triple, err, string(out))
		}
		if triple == "aarch64-unknown-linux-gnu" {
			linuxAsm = string(out)
		}
	}
	return linuxAsm
}

func TestM4_ARM64SVEAndSysOps(t *testing.T) {
	src := `
GLOBL gsve<>(SB), NOPTR, $64
TEXT ·sveAll(SB),NOSPLIT,$0-0
	// 1. Privileged / System ops (12 ops)
	ADR gsve<>(SB), R11
	ADR next, R12
	DCPS1 $1
	DCPS2 $2
	DCPS3 $3
	DRPS
	ERET
	HLT $1
	HVC $2
	SMC $3
	SYS $32768
	SYS $32768, R1
	SYSL $285440, R12
	TLBI VAE1IS, R0
	TLBI VMALLE1
next:
	// 2. Scalable SVE scalar control & VL math
	RDVL $2, R1
	ADDVL $4, R1, RSP
	ADDPL $3, R2, R3
	CNTB R4
	CNTH R5
	CNTW R6
	CNTD R7
	CTERMEQ R1, R2
	CTERMEQW R1, R2
	CTERMNE R1, R2
	CTERMNEW R1, R2

	// 3. Scalable SVE predicate engine
	PPRFB (R8)(RSP), P3, PSTL3KEEP
	PPRFD (R8<<3)(RSP), P3, PSTL3KEEP
	PLDR (-VL*2)(RSP), P5
	PSTR P5, (-VL*1)(R0)
	PPFALSE P1.B
	PPTRUE P2.B
	PPTRUE P6.S
	PWRFFR P2.B
	PRDFFR P3.B
	PRDFFRS P2.B, P4.B
	PPTEST P2.B, P3
	PAND P4.B, P2.B, P1.Z, P5.B
	PANDS P4.B, P2.B, P1.Z, P5.B
	PBIC P4.B, P2.B, P1.Z, P5.B
	PEOR P4.B, P2.B, P1.Z, P5.B
	PNAND P4.B, P2.B, P1.Z, P5.B
	PNOR P4.B, P2.B, P1.Z, P5.B
	PORN P4.B, P2.B, P1.Z, P5.B
	PORR P4.B, P2.B, P1.Z, P5.B
	PREV P2.B, P3.B
	PBRKA P5.B, P2.Z, P4.B
	PBRKB P5.B, P2.Z, P4.B
	PPUNPKLO P2.B, P3.H
	PZIP1 P2.B, P3.B, P4.B
	PWHILELT R1, R2, P3.S
	PWHILELEW R1, R2, P4.H
	PWHILELO R1, R2, P5.B
	PWHILELS R1, R2, P6.D
	PWHILEGE R1, R2, P7.H
	PWHILEGT R1, R2, P7.H
	PWHILEHI R1, R2, P3.S
	PWHILEHS R1, R2, P3.S
	PCNTP P2.B, P3, R4
	PINCP P2.S, R4
	PDECP P2.S, R4
	PSQINCPW R4, P2.D, R4
	PUQDECP P2.S, R4

	// 4. Scalable SVE Load / Store / Gather / Scatter / Broadcast / Narrow-extend / Prefetch
	ZPRFB 8(Z10.S), P3, PSTL3KEEP
	ZLD1B (R6)(R14), P4.Z, [Z1.B]
	ZLD1B (R6)(R14), P4.Z, [Z8.S]
	ZLD1SB (R6)(R14), P4.Z, [Z9.S]
	ZLD1H (R6<<1)(R14), P4.Z, [Z2.H]
	ZLD1D (-VL*6)(R3), P4.Z, [Z4.D-Z5.D]
	ZLD1RB 6(R14), P4.Z, [Z3.B]
	ZLD1RSB 6(R14), P4.Z, [Z3.S]
	ZLD1B 6(Z7.S), P4.Z, [Z8.S]
	ZLD1H (Z4.S.UXTW<<1)(R3), P3.Z, [Z4.S]
	ZLDNT1B (R6)(Z7.S), P4.Z, [Z9.S]
	ZST1B [Z8.S], P3, (R6)(RSP)
	ZST1D [Z4.D-Z5.D], P3, (R6<<3)(RSP)
	ZST1D [Z8.D], P3, (Z6.D<<3)(RSP)
	ZST1W [Z9.S], P2, (Z5.S)
	ZLD1B gsve<>(SB), P3.Z, [Z10.B]

	// 5. Scalable SVE Compares
	ZCMPEQ Z1.S, Z2.S, P3.Z, P4.S
	ZCMPNE $0, Z1.D, P3.Z, P4.D
	ZCMPGE Z1.H, Z2.H, P3.Z, P4.H
	ZCMPGT Z1.B, Z2.B, P3.Z, P4.B
	ZCMPHI Z1.S, Z2.S, P3.Z, P4.S
	ZCMPHS Z1.S, Z2.S, P3.Z, P4.S
	ZFACGE Z1.S, Z2.S, P3.Z, P4.S
	ZFACGT Z1.D, Z2.D, P3.Z, P4.D
	ZFCMEQ Z1.S, Z2.S, P3.Z, P4.S
	ZFCMGE Z1.D, Z2.D, P3.Z, P4.D
	ZFCMGT Z1.H, Z2.H, P3.Z, P4.H
	ZFCMLE $0, Z1.S, P3.Z, P4.S
	ZFCMLT $0, Z1.S, P3.Z, P4.S
	ZFCMNE Z1.S, Z2.S, P3.Z, P4.S
	ZFCMUO Z1.S, Z2.S, P3.Z, P4.S

	// 6. Scalable SVE FP ALU, FMA, Rounding, Conversions
	ZFADD Z1.S, Z2.S, P3.M, Z2.S
	ZFSUB Z1.D, Z2.D, P3.Z, Z2.D
	ZFMUL Z1.H, Z2.H, P3.M, Z2.H
	ZFDIV Z1.S, Z2.S, P3.M, Z2.S
	ZFMAX Z1.S, Z2.S, P3.M, Z2.S
	ZFMAXNM Z1.S, Z2.S, P3.M, Z2.S
	ZFMIN Z1.D, Z2.D, P3.M, Z2.D
	ZFMINNM Z1.D, Z2.D, P3.M, Z2.D
	ZFSQRT Z1.S, P3.M, Z2.S
	ZFABS Z1.D, P3.M, Z2.D
	ZFNEG Z1.S, P3.M, Z2.S
	ZFRINTM Z1.S, P3.M, Z2.S
	ZFRINTP Z1.S, P3.M, Z2.S
	ZFRINTZ Z1.S, P3.M, Z2.S
	ZFMLA Z1.S, Z2.S, P3.M, Z3.S
	ZSCVTF Z1.S, P3.M, Z2.S
	ZUCVTF Z1.D, P3.M, Z2.D
	ZFCVTZS Z1.S, P3.M, Z2.S
	ZFCVTZU Z1.D, P3.M, Z2.D

	// 7. Scalable SVE Int ALU / Unary / Shifts / Select / Unpredicated Load/Store
	ZADD Z1.S, Z2.S, Z3.S
	ZADD $6, Z7.D, Z7.D
	ZSUB Z1.B, Z2.B, P3.M, Z2.B
	ZMUL Z1.H, Z2.H, P3.Z, Z2.H
	ZAND Z1.D, Z2.D, Z3.D
	ZORR Z1.S, Z2.S, Z3.S
	ZEOR Z1.B, Z2.B, Z3.B
	ZBIC Z1.S, Z2.S, P3.M, Z2.S
	ZLSL Z1.S, Z2.S, P3.M, Z2.S
	ZLSR $2, Z1.D, P3.M, Z1.D
	ZASR Z1.B, Z2.B, P3.M, Z2.B
	ZABS Z1.D, P3.M, Z2.D
	ZNEG Z1.S, P3.M, Z2.S
	ZNOT Z1.B, P3.M, Z2.B
	ZCNT Z1.B, P3.M, Z2.B
	ZCLZ Z1.S, P3.M, Z2.S
	ZRBIT Z1.D, P3.M, Z2.D
	ZSQADD Z1.H, Z2.H, Z3.H
	ZUQADD Z1.B, Z2.B, Z3.B
	ZSQSUB Z1.S, Z2.S, Z3.S
	ZUQSUB Z1.D, Z2.D, Z3.D
	ZSMAX Z1.S, Z2.S, P3.M, Z2.S
	ZSMIN Z1.S, Z2.S, P3.M, Z2.S
	ZUMAX Z1.S, Z2.S, P3.M, Z2.S
	ZUMIN Z1.S, Z2.S, P3.M, Z2.S
	ZSEL Z1.S, Z2.S, P3, Z3.S
	ZLDR (-VL*2)(R1), Z4
	ZLDR (VL*3)(R1), Z5
	ZSTR Z5, (VL*1)(R1)
	ZLD1H (R6<<1)(R1), P1/Z, Z4.H
	ZLD1W 16(R1)(Z2.S.UXTW), P1/Z, Z4.S
	ZST1D Z4.D, P1, (R1)(R2<<3)
	ZLD1W 8(Z1.D), P1/Z, Z4.D
	ZFADD Z1.H, P1/M, Z2.H, Z2.H
	ZFADD Z1.D, P1/M, Z2.D, Z2.D
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse arm64 SVE failed: %v", err)
	}
	ir, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return "m4." + strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m4.sveAll": {Name: "m4.sveAll", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("Translate arm64 SVE failed: %v", err)
	}
	for _, want := range []string{
		"@llvm.vscale.i64()",
		"<vscale x 16 x i8>",
		"<vscale x 16 x i1>",
		"@llvm.aarch64.sve.whilelt.",
		"@llvm.aarch64.sve.cntp.",
		"@llvm.aarch64.sve.cntb(",
		"@llvm.masked.load.nxv",
		"@llvm.masked.store.nxv",
		"@llvm.masked.gather.nxv",
		"@llvm.masked.scatter.nxv",
		`"+sve,+sve2"`,
	} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in ARM64 scalable SVE IR", want)
		}
	}
	asmOut := verifyARM64LLVMAndLLC(t, ir)
	if asmOut != "" {
		for _, wantAsm := range []string{"rdvl", "addvl", "whilelt", "cntp", "ld1b", "st1d"} {
			if !strings.Contains(asmOut, wantAsm) {
				t.Errorf("expected hardware SVE instruction %q in llc output", wantAsm)
			}
		}
	}
}

func TestM4_ARM64SVEErrorPaths(t *testing.T) {
	bad := []string{
		"ADR R1",
		"SYSL $1",
		"DRPS R1",
		"DCPS1 $1, $2",
		"TLBI",
		"RDVL R1, R2",
		"ADDVL $1, R1",
		"CTERMEQ R1",
		"PLDR (R1)",
		"PLDR (R1), R2",
		"PSTR (R1)",
		"PSTR R1, (R2)",
		"PPFALSE",
		"PPTRUE",
		"PPTRUE PN14.S",
		"PWRFFR",
		"PRDFFR",
		"PPTEST P1",
		"PWHILELT R1, R2",
		"PWHILEGT VLx4, R1, R2, PN12.H",
		"PCNTP P1",
		"PAND P1",
		"ZLD1B (R1)",
		"ZLD1D (-VL*6)(R3), PN10.Z, [Z4.D-Z5.D]",
		"ZCMPEQ Z1.S, Z2.S",
		"ZCMPEQ Z1.S, Z2.S, R1",
		"ZFADD Z1.S",
		"ZFADD Z1.S, R1",
		"ZADD",
		// Unmodeled SVE/SVE2/SME instructions must fail explicitly (no fake fallback).
		"PPEXT PN11[1], [P13.S, P14.S]",
		"ZBFCVT Z1.S, P3.M, Z2.H",
		"ZBFDOT Z1.H, Z2.H, Z3.S",
		"ZFADDQV Z1.S, P3, V5.S4",
		"ZADDQV Z1.S, P3, V5.S4",
		"ZADDQP Z0.S, Z1.S, Z2.S",
		"ZANDVB Z1.B, P3, V2",
		"ZLASTA Z1.D, P3, R15",
		"ZCLASTA Z1.H, R10, P3, R10",
		"ZAESE Z1.Q[1], [Z2.B-Z3.B], [Z2.B-Z3.B]",
		"ZPMOV P4.S, Z1[2]",
		"ZADR (Z1.S)(Z2.S), Z3.S",
		"ZLD2B (R1), P0.Z, [Z0.B, Z1.B]",
		"ZLDFF1B (R1), P0.Z, [Z0.B]",
		"ZLDNF1B (R1), P0.Z, [Z0.B]",
		"ZMATCH Z0.B, Z1.B, P0.Z, P1.B",
		// Invalid gather/scatter width or shift scaling must be rejected.
		"ZLD1W 8(Z1.D), P1/Z, Z4.S",
		"ZLD1H (Z4.S.UXTW<<2)(R3), P3.Z, [Z4.S]",
		"ZLD1B (Z4.S.UXTW<<1)(R3), P3.Z, [Z4.S]",
	}
	for _, body := range bad {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
		file, err := Parse(ArchARM64, src)
		if err != nil {
			continue
		}
		_, err = Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return "m4." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m4.bad": {Name: "m4.bad", Ret: Void}},
		})
		if err == nil {
			t.Errorf("expected error for: %s", body)
		}
	}
}

// TestM4_ARM64SVEGatherScalingAndBroadcastFaultSafety verifies:
//  1. SVE gather/scatter preserves index extension (UXTW/SXTW) and shift scaling
//     (e.g. ZLD1H (Z4.S.UXTW<<1)(R3) computes base + 2*zext(index), not base+index).
//  2. SVE broadcast loads (ZLD1RB/H/W/D/RSB/RSH/RSW) guard memory access with
//     @llvm.aarch64.sve.ptest.any + @llvm.masked.load.v1i* so an all-false
//     predicate (e.g. PPFALSE P4.B) performs NO memory load.
func TestM4_ARM64SVEGatherScalingAndBroadcastFaultSafety(t *testing.T) {
	t.Run("gather and scatter preserve extension and scaling", func(t *testing.T) {
		src := `
TEXT ·gatherScaled(SB),NOSPLIT,$0-0
	ZLD1H (Z4.S.UXTW<<1)(R3), P3.Z, [Z4.S]
	ZLD1W (Z4.S.SXTW<<2)(R3), P3.Z, [Z5.S]
	ZST1D [Z8.D], P3, (Z6.D<<3)(RSP)
	ZLD1H (R6<<1)(R14), P4.Z, [Z2.H]
	RET
`
		file, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		ir, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return "m4." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m4.gatherScaled": {Name: "m4.gatherScaled", Ret: Void}},
		})
		if err != nil {
			t.Fatalf("Translate failed: %v", err)
		}
		for _, want := range []string{
			"zext <vscale x 4 x i32>",
			"sext <vscale x 4 x i32>",
			"shl <vscale x 4 x i64>",
			"shl <vscale x 2 x i64>",
			"shl i64",
			"@llvm.masked.gather.nxv4i16.nxv4p0",
			"@llvm.masked.gather.nxv4i32.nxv4p0",
			"@llvm.masked.scatter.nxv2i64.nxv2p0",
		} {
			if !strings.Contains(ir, want) {
				t.Errorf("missing %q in gather/scatter IR:\n%s", want, ir)
			}
		}
		verifyARM64LLVMAndLLC(t, ir)
	})

	t.Run("broadcast load suppresses memory access when predicate is all-false", func(t *testing.T) {
		src := `
TEXT ·bcastAllFalse(SB),NOSPLIT,$0-0
	PPFALSE P4.B
	ZLD1RB 6(R14), P4.Z, [Z3.B]
	ZLD1RSB 6(R14), P4.Z, [Z4.S]
	RET
`
		file, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatalf("Parse failed: %v", err)
		}
		ir, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return "m4." + strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"m4.bcastAllFalse": {Name: "m4.bcastAllFalse", Ret: Void}},
		})
		if err != nil {
			t.Fatalf("Translate failed: %v", err)
		}
		for _, want := range []string{
			"@llvm.aarch64.sve.ptest.any",
			"@llvm.masked.load.v1i8.p0(",
		} {
			if !strings.Contains(ir, want) {
				t.Errorf("missing %q in broadcast load IR:\n%s", want, ir)
			}
		}
		if strings.Contains(ir, " = load i8, ptr ") {
			t.Errorf("broadcast load emitted unconditional scalar load i8:\n%s", ir)
		}
		verifyARM64LLVMAndLLC(t, ir)
	})
}
