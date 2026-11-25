package plan9asm

import (
	"os/exec"
	"strings"
	"testing"
)

func verifyARM64LLVMAndLLC(t *testing.T, ir string) {
	t.Helper()
	verifyLLVMIRWithOpt(t, ir)
	llc, err := exec.LookPath("llc")
	if err != nil {
		return
	}
	for _, triple := range []string{"aarch64-unknown-linux-gnu", "arm64-apple-darwin"} {
		cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=null")
		cmd.Stdin = strings.NewReader(ir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("llc (%s) codegen failed: %v\noutput:\n%s", triple, err, string(out))
		}
	}
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
	// 2. SVE scalar control & VL math
	RDVL $2, R1
	ADDVL $4, R1, RSP
	ADDPL $3, R2, R3
	CTERMEQ R1, R2
	CTERMEQW R1, R2
	CTERMNE R1, R2
	CTERMNEW R1, R2

	// 3. SVE Predicate engine
	PPRFB (R8)(RSP), P3, PSTL3KEEP
	PPRFD (R8<<3)(RSP), P3, PSTL3KEEP
	PLDR (-VL*2)(RSP), P5
	PSTR P5, (-VL*1)(R0)
	PPFALSE P1.B
	PPTRUE P2.B
	PPTRUE PN14.S
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
	PPEXT PN11[1], [P13.S, P14.S]
	PWHILELT R1, R2, P3.S
	PWHILELEW R1, R2, P4.H
	PWHILELO R1, R2, P5.B
	PWHILELS R1, R2, P6.D
	PWHILEGE R1, R2, [P7.H, P8.H]
	PWHILEGT VLx4, R1, R2, PN12.H
	PWHILEHI R1, R2, P3.S
	PWHILEHS R1, R2, P3.S
	PCNTP P2.B, P3, R4
	PCNTP VLx2, PN13.D, R5
	PINCP P2.S, R4
	PDECP P2.S, R4
	PSQINCPW R4, P2.D, R4
	PUQDECP P2.S, R4

	// 4. SVE Load / Store / Gather / Scatter / Broadcast / Prefetch
	ZPRFB 8(Z10.S), P3, PSTL3KEEP
	ZLD1B (R6)(R14), P4.Z, [Z1.B]
	ZLD1H (R6<<1)(R14), P4.Z, [Z2.H]
	ZLD1D (-VL*6)(R3), PN10.Z, [Z4.D-Z5.D]
	ZLD1RB 6(R14), P4.Z, [Z3.B]
	ZLD1B 6(Z7.S), P4.Z, [Z8.S]
	ZLD1H (Z4.S.UXTW<<1)(R3), P3.Z, [Z4.S]
	ZLDNT1B (R6)(Z7.S), P4.Z, [Z9.S]
	ZST1D [Z4.D-Z5.D], P3, (R6<<3)(RSP)
	ZST1D [Z8.D], P3, (Z6.D<<3)(RSP)
	ZST1W [Z9.S], P2, (Z5.S)
	ZLD1B gsve<>(SB), P3.Z, [Z10.B]

	// 5. SVE Compares
	ZCMPEQ Z1.S, Z2.S, P3.Z, P4.S
	ZCMPNE $0, Z1.D, P3.Z, P4.D
	ZCMPGE Z1.H, Z2.H, P3.Z, P4.H
	ZCMPGT Z1.B, Z2.B, P3.Z, P4.B
	ZCMPHI Z1.S, Z2.S, P3.Z, P4.S
	ZCMPHS Z1.S, Z2.S, P3.Z, P4.S
	ZFCMEQ Z1.S, Z2.S, P3.Z, P4.S
	ZFCMGE Z1.D, Z2.D, P3.Z, P4.D
	ZFCMGT Z1.H, Z2.H, P3.Z, P4.H
	ZFCMLE $0, Z1.S, P3.Z, P4.S
	ZFCMLT $0, Z1.S, P3.Z, P4.S
	ZFCMNE Z1.S, Z2.S, P3.Z, P4.S
	ZFCMUO Z1.S, Z2.S, P3.Z, P4.S

	// 6. SVE FP & BF16
	ZFADD Z1.S, Z2.S, P3.M, Z2.S
	ZFSUB Z1.D, Z2.D, P3.Z, Z2.D
	ZFMUL Z1.H, Z2.H, P3.M, Z2.H
	ZFDIV Z1.S, Z2.S, P3.M, Z2.S
	ZFMAX Z1.S, Z2.S, P3.M, Z2.S
	ZFMIN Z1.D, Z2.D, P3.M, Z2.D
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
	ZBFCVT Z1.S, P3.M, Z2.H
	ZBFDOT Z1.H, Z2.H, Z3.S
	ZFADDQV Z1.S, P3, V5.S4

	// 7. SVE Int ALU / Unary / Shifts / Crypto / Permutes / Reductions
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
	ZADDQV Z1.S, P3, V5.S4
	ZANDVB Z1.B, P3, V2
	ZLASTA Z1.D, P3, R15
	ZCLASTA Z1.H, R10, P3, R10
	ZAESE Z1.Q[1], [Z2.B-Z3.B], [Z2.B-Z3.B]
	ZPMOV P4.S, Z1[2]
	ZADR (Z1.S)(Z2.S), Z3.S
	ZLDR (-VL*2)(R1), Z4
	ZLDR (VL*3)(R1), Z5
	ZLD1H (R6<<1)(R1), P1/Z, Z4.H
	ZLD1W 16(R1)(Z2.S.UXTW), P1/Z, Z4.S
	ZST1D Z4.D, P1, (R1)(R2<<3)
	ZLD1W 8(Z1.D), P1/Z, Z4.S
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
		"@llvm.masked.load.",
		"@llvm.masked.store.",
		"@llvm.masked.gather.",
		"@llvm.masked.scatter.",
		"@llvm.ctpop.i16",
		"@llvm.bitreverse.i16",
	} {
		if !strings.Contains(ir, want) {
			t.Errorf("missing %q in ARM64 SVE IR", want)
		}
	}
	verifyARM64LLVMAndLLC(t, ir)
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
		"PWRFFR",
		"PRDFFR",
		"PPTEST P1",
		"PWHILELT R1, R2",
		"PCNTP P1",
		"PAND P1",
		"ZLD1B (R1)",
		"ZCMPEQ Z1.S, Z2.S",
		"ZCMPEQ Z1.S, Z2.S, R1",
		"ZFADD Z1.S",
		"ZFADD Z1.S, R1",
		"ZADD",
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
