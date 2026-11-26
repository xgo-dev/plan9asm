package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

// TestM6_ARM64XArchDiffSemantics verifies all M6 ARM64 extensions (ADRP, MOVP*,
// LDTR*/STTR*/LDUR*, 3-arg LDNP/STNP/LDPSW, VLDNP/VSTNP, VMOVI/VMVNI/VMVN/VBIC/VORR imm,
// SMOV/SMOVW, FCVT*W, scalar/vector FP variants, and all 90+ x/arch NEON ops) under opt +
// default-CPU llc, and executes bit-for-bit assertions natively on arm64.
func TestM6_ARM64XArchDiffSemantics(t *testing.T) {
	src := `
TEXT ·arm64M6Exec(SB),NOSPLIT,$0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1

	// [0..3] LDTR* / LDUR* / STTR*
	LDTR 0(R1), R2
	STTR 0(R0), R2
	LDTRW 0(R1), R3
	MOVD R3, 8(R0)
	LDTRSW 0(R1), R4
	MOVD R4, 16(R0)
	LDTRH 0(R1), R5
	MOVD R5, 24(R0)
	LDTRSH 0(R1), R6
	MOVD R6, 32(R0)
	LDTRSHW 0(R1), R7
	MOVD R7, 40(R0)
	LDTRBW 0(R1), R8
	MOVD R8, 48(R0)
	LDTRSB 0(R1), R9
	MOVD R9, 56(R0)
	LDTRSBW 0(R1), R10
	MOVD R10, 64(R0)
	LDURBW 0(R1), R11
	LDURHW 0(R1), R12
	LDURSB 0(R1), R13
	LDURSBW 0(R1), R14
	LDURSH 0(R1), R15
	LDURSHW 0(R1), R16
	LDURSW 0(R1), R17
	MOVD R17, 72(R0)
	STTRW 80(R0), R3
	STTRHW 88(R0), R5
	STTRBW 96(R0), R8

	// [13..15] 3-arg LDNP / STNP / LDPSW (incl. ZR) + MOVPD / MOVPSW
	LDNP 0(R1), R2, R3
	STNP 104(R0), R3, R2
	LDPSW 0(R1), R4, R5
	MOVD R4, 120(R0)
	MOVD R5, 128(R0)
	LDNP 0(R1), R6, ZR
	LDNPW 0(R1), ZR, R7
	STNPW 136(R0), R7, ZR

	// [18..21] VMOVI (16-bit), VMVNI, VMVN, VBIC imm, VORR imm, SMOV, SMOVW, FMOV V.D[1]
	VMOVI $0x1234, V0.H8
	VMOV V0.D[0], R2
	MOVD R2, 144(R0)
	VMVNI $0x00ff, V1.H4
	VORR $0x0001, V1.H4
	VBIC $0x0002, V1.H4
	VMVN V1.B8, V2.B8
	SMOV V0.B[0], R3
	MOVD R3, 152(R0)
	SMOVW V0.H[0], R4
	MOVD R4, 160(R0)
	FMOV V0.D[1], R5
	MOVD R5, 168(R0)

	// [22..25] FCVT*W + SCVTFDD/SS + FCVTZSDD/SS + FABD + FCMLE/FCMLT
	MOVD $5, R6
	SCVTF $1, R6, F0       // 2.5
	FCVTASW F0, R7         // 3
	MOVD R7, 176(R0)
	FCVTMSW F0, R8         // 2
	MOVD R8, 184(R0)
	FCVTNSW F0, R9         // 2
	MOVD R9, 192(R0)
	FCVTPSW F0, R10        // 3
	MOVD R10, 200(R0)
	FCVTAUW F0, R11
	FCVTMUW F0, R11
	FCVTNUW F0, R11
	FCVTPUW F0, R11
	MOVD $-3, R12
	SCVTF R12, F1          // -3.0
	FABD F0, F1, F2        // |-3.0 - 2.5| = 5.5
	FCVTZS F2, R13         // 5
	MOVD R13, 208(R0)
	FCMLE $0, F1, F3       // -3 <= 0 -> all 1s
	FMOVD F3, R14
	MOVD R14, 216(R0)
	FCMLT $0, F0, F4       // 2.5 < 0 -> 0
	FMOVD F4, R15
	MOVD R15, 224(R0)

	// [29..31] VSABD, VSABA, VSADDLV
	VMOVI $10, V3.S4
	VMOVI $3, V4.S4
	VSABD V4.S4, V3.S4, V5.S4   // each lane = 7
	VMOV V5.D[0], R2
	MOVD R2, 232(R0)
	VSABA V4.S4, V3.S4, V5.S4   // each lane = 14
	VMOV V5.D[0], R3
	MOVD R3, 240(R0)
	VSADDLV V5.S4, V6           // 4 * 14 = 56
	VMOV V6.D[0], R4
	MOVD R4, 248(R0)
	RET

TEXT ·arm64M6AllForms(SB),NOSPLIT,$0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1

	ADRP target, R2
	MOVP 0(R1), (R2, R3)
	MOVP (R2, R3), 0(R0)
	MOVPD 0(R1), R2, R3
	MOVPD R2, R3, 0(R0)
	MOVPW 0(R1), (R2, R3)
	MOVPW (R2, R3), 0(R0)
	MOVPS 0(R1), (R2, R3)
	MOVPSW 0(R1), (R2, R3)
	MOVPQ 0(R1), (V0, V1)
	MOVPQ (V0, V1), 0(R0)
	VLDNP 0(R1), V0, V1
	VSTNP 0(R0), V0, V1
	STTR R2, 0(R0)

	// Scalar & vector FP variants
	FCVTZSDD F0, F1
	FCVTZSSS F0, F1
	FCVTZUDD F0, F1
	SCVTFDD F0, F1
	SCVTFSS F0, F1
	UCVTFDD F0, F1
	UCVTFSS F0, F1
	FCVTXN F0, F1
	VFCVTAS V0.S4, V1.S4
	VFCVTAU V0.S4, V1.S4
	VFCVTMS V0.D2, V1.D2
	VFCVTMU V0.S2, V1.S2
	VFCVTNS V0.D2, V1.D2
	VFCVTNU V0.S4, V1.S4
	VFCVTPS V0.D2, V1.D2
	VFCVTPU V0.S2, V1.S2
	VFCVTXN V0.D2, V1.S2
	VFCVTXN2 V0.D2, V1.S4
	FCVTZS V0.D2, V1.D2
	FCVTZS $4, V0.D2, V1.D2
	FCVTZU V0.S4, V1.S4
	FCVTZU $4, V0.S4, V1.S4
	SCVTF V0.S4, V1.S4
	SCVTF $4, V0.D2, V1.D2
	UCVTF V0.S4, V1.S4
	UCVTF $4, V0.S4, V1.S4
	VFABD V0.S4, V1.S4, V2.S4
	FACGE F0, F1, F2
	VFACGE V0.S4, V1.S4, V2.S4
	FACGT F0, F1, F2
	VFACGT V0.S4, V1.S4, V2.S4
	FABS V0.S2, V1.S2
	FNEG V0.D2, V1.D2
	FSQRT V0.S4, V1.S4
	FRINTA V0.S4, V1.S4
	FRINTI V0.S2, V1.S2
	FRINTM V0.S2, V1.S2
	FRINTN V0.D2, V1.D2
	FRINTP V0.S2, V1.S2
	FRINTX V0.S4, V1.S4
	FRINTZ V0.D2, V1.D2
	FADD V0.S4, V1.S4, V2.S4
	FSUB V0.S4, V1.S4, V2.S4
	FDIV V0.S4, V1.S4, V2.S4
	FMAX V0.S4, V1.S4, V2.S4
	FMIN V0.D2, V1.D2, V2.D2
	FMAXNM V0.S4, V1.S4, V2.S4
	FMINNM V0.D2, V1.D2, V2.D2
	FMLA V0.S[1], F1, F2
	FMLS V0.D[0], F1, F2
	FMLA V0.S4, V1.S4, V2.S4
	FMLS V0.S4, V1.S4, V2.S4
	FMULS V0.S[3], F1, F2
	FMULD V0.D[0], F1, F2
	FADDP V0.S2, F1
	FMAXP V0.D2, F1
	FMINP V0.D2, F1
	FMAXNMP V0.D2, F1
	FMINNMP V0.S2, F1
	FMAXV V0.S4, F1
	FMINV V0.S4, F1
	FMAXNMV V0.S4, F1
	FMINNMV V0.S4, F1
	FRECPE F0, F1
	VFRECPE V0.S4, V1.S4
	FRECPX F0, F1
	FRSQRTE F0, F1
	VFRSQRTE V0.D2, V1.D2
	FRECPS F0, F1, F2
	VFRECPS V0.S4, V1.S4, V2.S4
	FRSQRTS F0, F1, F2
	VFRSQRTS V0.D2, V1.D2, V2.D2

	// NEON narrowing/widening/ABA/ABD/shift/saturating/estimate ops
	VADDHN V0.D2, V1.D2, V2.S2
	VADDHN2 V0.S4, V1.S4, V2.H8
	VSUBHN V0.H8, V1.H8, V2.B8
	VSUBHN2 V0.D2, V1.D2, V2.S4
	VRADDHN V0.H8, V1.H8, V2.B8
	VRADDHN2 V0.H8, V1.H8, V2.B16
	VRSUBHN V0.D2, V1.D2, V2.S2
	VRSUBHN2 V0.S4, V1.S4, V2.H8
	VUABD V0.H8, V1.H8, V2.H8
	VUABA V0.S2, V1.S2, V2.S2
	VSABDL V0.S2, V1.S2, V2.D2
	VSABDL2 V0.B16, V1.B16, V2.H8
	VUABDL V0.S2, V1.S2, V2.D2
	VUABDL2 V0.S4, V1.S4, V2.D2
	VSABAL V0.B8, V1.B8, V2.H8
	VSABAL2 V0.H8, V1.H8, V2.S4
	VUABAL V0.H4, V1.H4, V2.S4
	VUABAL2 V0.H8, V1.H8, V2.S4
	VSADDL V0.H4, V1.H4, V2.S4
	VSADDL2 V0.S4, V1.S4, V2.D2
	VUADDL V0.H4, V1.H4, V2.S4
	VUADDL2 V0.B16, V1.B16, V2.H8
	VSSUBL V0.B8, V1.B8, V2.H8
	VSSUBL2 V0.B16, V1.B16, V2.H8
	VUSUBL V0.S2, V1.S2, V2.D2
	VUSUBL2 V0.H8, V1.H8, V2.S4
	VSADDW V0.H4, V1.S4, V2.S4
	VSADDW2 V0.H8, V1.S4, V2.S4
	VUADDW V0.H4, V1.S4, V2.S4
	VUADDW2 V0.H8, V1.S4, V2.S4
	VSSUBW V0.S2, V1.D2, V2.D2
	VSSUBW2 V0.S4, V1.D2, V2.D2
	VUSUBW V0.H4, V1.S4, V2.S4
	VUSUBW2 V0.B16, V1.H8, V2.H8
	VSHLL $8, V0.B8, V1.H8
	VSHLL2 $32, V0.S4, V1.D2
	VSHSUB V0.S2, V1.S2, V2.S2
	VUHSUB V0.B8, V1.B8, V2.B8
	VSADDLP V0.H8, V1.S4
	VUADDLP V0.B16, V1.H8
	VSADALP V0.B8, V1.H4
	VUADALP V0.B8, V1.H4
	VSQDMLAL2 V0.H8, V1.H8, V2.S4
	VSQDMLAL2 V0.H[1], V1.H8, V2.S4
	VSQDMLSL2 V0.H8, V1.H8, V2.S4
	VSQDMLSL2 V0.H[1], V1.H8, V2.S4
	VSQDMULL2 V0.H8, V1.H8, V2.S4
	VSQDMULL2 V0.S[0], V1.S4, V2.D2
	VSRSHL V0.S2, V1.S2, V2.S2
	VURSHL V0, V1, V2
	VSQRSHL V0, V1, V2
	VUQRSHL V0, V1, V2
	VURSHR $56, V0, V1
	VSSRA $14, V0.S4, V1.S4
	VSRSRA $8, V0.H4, V1.H4
	VURSRA $4, V0, V1
	VSQSHLU $10, V0, V1
	VRSHRN $16, V0.D2, V1.S2
	VRSHRN2 $16, V0.D2, V1.S4
	VSQSHRN $12, V0.S4, V1.H4
	VSQSHRN2 $5, V0.H8, V1.B16
	VUQSHRN $5, V0, V1
	VUQSHRN2 $1, V0.S4, V1.H8
	VSQRSHRN $2, V0.S4, V1.H4
	VSQRSHRN2 $15, V0.S4, V1.H8
	VUQRSHRN $16, V0.D2, V1.S2
	VUQRSHRN2 $5, V0.D2, V1.S4
	VSQSHRUN $11, V0.D2, V1.S2
	VSQSHRUN2 $14, V0.D2, V1.S4
	VSQRSHRUN $3, V0, V1
	VSQRSHRUN2 $17, V0.D2, V1.S4
	VSUQADD V0, V1
	VUSQADD V0, V1
	VURECPE V0.S4, V1.S4
	VURSQRTE V0.S2, V1.S2
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse arm64 M6 failed: %v", err)
	}
	triple := "aarch64-unknown-linux-gnu"
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		triple = "arm64-apple-darwin"
	}
	ptr2 := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
	}}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"arm64M6Exec":     {Name: "arm64M6Exec", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
			"arm64M6AllForms": {Name: "arm64M6AllForms", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
		},
	})
	if err != nil {
		t.Fatalf("Translate arm64 M6 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "aarch64-unknown-linux-gnu")
	verifyLLVMWithTargetLLC(t, ll, "arm64-apple-darwin")

	if runtime.GOARCH != "arm64" {
		return
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
extern void arm64M6Exec(uint64_t *out, uint64_t *data);
int main(void) {
    uint64_t data[2] = {0x000000028000cdefULL, 0x1122334455667788ULL};
    uint64_t out[36] = {0};
    arm64M6Exec(out, data);
    uint64_t want[32] = {
        data[0],                       // [0] LDTR/STTR
        0x000000008000cdefULL,         // [1] LDTRW
        0xffffffff8000cdefULL,         // [2] LDTRSW
        0x000000000000cdefULL,         // [3] LDTRH
        0xffffffffffffcdefULL,         // [4] LDTRSH
        0x00000000ffffcdefULL,         // [5] LDTRSHW
        0x00000000000000efULL,         // [6] LDTRBW
        0xffffffffffffffefULL,         // [7] LDTRSB
        0x00000000ffffffefULL,         // [8] LDTRSBW
        0xffffffff8000cdefULL,         // [9] LDURSW
        0x000000008000cdefULL,         // [10] STTRW
        0x000000000000cdefULL,         // [11] STTRHW
        0x00000000000000efULL,         // [12] STTRBW
        data[1],                       // [13] STNP swapped[0]
        data[0],                       // [14] STNP swapped[1]
        0xffffffff8000cdefULL,         // [15] LDPSW[0]
        0x0000000000000002ULL,         // [16] LDPSW[1]
        0x0000000000000002ULL,         // [17] STNPW(LDNPW[1])
        0x1234123412341234ULL,         // [18] VMOVI $0x1234, V0.H8
        0x0000000000000034ULL,         // [19] SMOV V0.B[0]
        0x0000000000001234ULL,         // [20] SMOVW V0.H[0]
        0x1234123412341234ULL,         // [21] FMOV V0.D[1]
        3ULL,                          // [22] FCVTASW(2.5)
        2ULL,                          // [23] FCVTMSW(2.5)
        2ULL,                          // [24] FCVTNSW(2.5)
        3ULL,                          // [25] FCVTPSW(2.5)
        5ULL,                          // [26] FABD(-3, 2.5)=5.5 -> 5
        0xffffffffffffffffULL,         // [27] FCMLE(-3, 0)
        0ULL,                          // [28] FCMLT(2.5, 0)
        0x0000000700000007ULL,         // [29] VSABD(10, 3) = 7
        0x0000000e0000000eULL,         // [30] VSABA = 14
        56ULL,                         // [31] VSADDLV = 56
    };
    for (int i = 0; i < 32; i++) {
        if (out[i] != want[i]) {
            fprintf(stderr, "mismatch at [%d]: got=0x%llx want=0x%llx\n", i, (unsigned long long)out[i], (unsigned long long)want[i]);
            return i + 1;
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "arm64_m6_diff", triple, ll, mainC, nil)
}

// TestM6_X86CompleteTailAndX87 verifies all M6 x86/386 completions:
//   - All 93 newly added 386 x87 instructions (arith, moves, BCD, compares, FCMOV, constants, env, math)
//   - BCD/legacy/stack ops (AAA/AAS/AAM/AAD/DAA/DAS/ARPL/BOUNDW/BOUNDL/INTO/WAIT/PUSHAW/POPAW/LEAVEL/W)
//   - MOVW TASK + 8 unsuffixed AVX-512 aliases (VCVT*USI, VFPCLASSPS/PD)
//   - Live amd64 runtime differential checks on amd64 hosts.
func TestM6_X86CompleteTailAndX87(t *testing.T) {
	src386 := `
TEXT ·x86M6Full387(SB),NOSPLIT,$0-4
	MOVL buf+0(FP), BX
	FINIT
	FLDPI
	FLDL2E
	FLDL2T
	FLDLG2
	FLDLN2
	FADDD F0, F1
	FADDD 0(BX), F0
	FADDF 0(BX), F0
	FADDL 0(BX), F0
	FADDW 0(BX), F0
	FSUBD F0, F1
	FSUBD 0(BX), F0
	FSUBDP F0, F1
	FSUBF 0(BX), F0
	FSUBL 0(BX), F0
	FSUBW 0(BX), F0
	FSUBRD F0, F1
	FSUBRD 0(BX), F0
	FSUBRDP F0, F1
	FSUBRF 0(BX), F0
	FSUBRL 0(BX), F0
	FSUBRW 0(BX), F0
	FMULF 0(BX), F0
	FMULL 0(BX), F0
	FMULW 0(BX), F0
	FDIVDP F0, F1
	FDIVF 0(BX), F0
	FDIVL 0(BX), F0
	FDIVW 0(BX), F0
	FDIVRD F0, F1
	FDIVRD 0(BX), F0
	FDIVRDP F0, F1
	FDIVRF 0(BX), F0
	FDIVRL 0(BX), F0
	FDIVRW 0(BX), F0
	FMOVF 0(BX), F0
	FMOVF F0, 0(BX)
	FMOVFP F0, 0(BX)
	FMOVL 0(BX), F0
	FMOVL F0, 0(BX)
	FMOVLP F0, 0(BX)
	FMOVW 0(BX), F0
	FMOVW F0, 0(BX)
	FMOVWP F0, 0(BX)
	FMOVB 0(BX), F0
	FMOVBP F0, 0(BX)
	FMOVX 0(BX), F0
	FMOVXP F0, 0(BX)
	FBLD 0(BX)
	FBSTP 0(BX)
	FCOMD F0, F1
	FCOMD 0(BX), F0
	FCOMDP F0, F1
	FCOMDP 0(BX), F0
	FCOMDPP F0, F1
	FCOMF 0(BX), F0
	FCOMFP 0(BX), F0
	FCOML 0(BX), F0
	FCOMLP 0(BX), F0
	FCOMW 0(BX), F0
	FCOMWP 0(BX), F0
	FCOMI F0, F1
	FCOMIP F0, F1
	FUCOM F0, F1
	FUCOMP F0, F1
	FUCOMPP F0, F1
	FUCOMIP F0, F1
	FCMOVB F1, F0
	FCMOVBE F1, F0
	FCMOVCC F1, F0
	FCMOVCS F1, F0
	FCMOVE F1, F0
	FCMOVEQ F1, F0
	FCMOVHI F1, F0
	FCMOVLS F1, F0
	FCMOVNB F1, F0
	FCMOVNBE F1, F0
	FCMOVNE F1, F0
	FCMOVNU F1, F0
	FCMOVU F1, F0
	FCMOVUN F1, F0
	FFREE F7
	FINCSTP
	FDECSTP
	WAIT
	AAA
	AAS
	AAM
	AAD
	DAA
	DAS
	LEAVEL
	LEAVEW
	RET
`
	f386, err := Parse(ArchAMD64, src386)
	if err != nil {
		t.Fatalf("Parse 386 M6 failed: %v", err)
	}
	sig386 := map[string]FuncSig{
		"x86M6Full387": {
			Name: "x86M6Full387",
			Args: []LLVMType{Ptr},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
			}},
		},
	}
	for _, mode := range []X87Mode{X87Software, X87Hardware} {
		ll386, err := Translate(f386, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			X87Mode:      mode,
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         sig386,
		})
		if err != nil {
			t.Fatalf("Translate 386 M6 (%v) failed: %v", mode, err)
		}
		verifyLLVMWithTargetLLC(t, ll386, "i386-unknown-linux-gnu")
	}

	// AMD64 M6 verification + runtime differential execution
	srcAMD64 := `
TEXT ·amd64M6Exec(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), DI
	MOVQ in+8(FP), SI

	// [0..2] Unsuffixed AVX-512 aliases: VCVTUSI2SD / VCVTSD2USI / VFPCLASSPD / VFPCLASSPS
	MOVQ $42, CX
	VCVTUSI2SD CX, X0, X1
	VCVTSD2USI X1, DX
	MOVQ DX, 0(DI)
	VCVTTSD2USI X1, R8
	MOVQ R8, 8(DI)
	VCVTUSI2SS CX, X0, X2
	VCVTSS2USI X2, R9
	VCVTTSS2USI X2, R10
	MOVQ R10, 16(DI)
	VFPCLASSPD $0x02, X1, K1
	VFPCLASSPS $0x02, X2, K2
	WAIT
	RET
`
	f64, err := Parse(ArchAMD64, srcAMD64)
	if err != nil {
		t.Fatalf("Parse amd64 M6 failed: %v", err)
	}
	ptr2 := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
	}}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	if runtime.GOARCH != "amd64" {
		triple = "x86_64-unknown-linux-gnu"
	}
	ll64, err := Translate(f64, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"amd64M6Exec": {Name: "amd64M6Exec", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
		},
	})
	if err != nil {
		t.Fatalf("Translate amd64 M6 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll64, "x86_64-unknown-linux-gnu", "-mcpu=haswell", "-mattr=+aes,+ssse3,+sse4.1,+sse4.2,+pclmul,+avx,+avx2,+sha,+popcnt,+adx")

	if runtime.GOARCH != "amd64" {
		return
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern void amd64M6Exec(uint64_t *out, uint64_t *in);
int main(void) {
    uint64_t in[2] = {0, 0};
    uint64_t out[12] = {0};
    amd64M6Exec(out, in);
    uint64_t want[3] = {42, 42, 42};
    for (int i = 0; i < 3; i++) {
        if (out[i] != want[i]) {
            fprintf(stderr, "mismatch at [%d]: got=0x%llx want=0x%llx\n", i, (unsigned long long)out[i], (unsigned long long)want[i]);
            return i + 1;
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "amd64_m6_diff", triple, ll64, mainC, nil)
}

func TestM6_ARM32DWordAndErrorPaths(t *testing.T) {
	armSrc := "TEXT ·armM6(SB),NOSPLIT,$0-0\n\tDWORD $0x12345678\n\tRET\n"
	af, err := Parse(ArchARM, armSrc)
	if err != nil {
		t.Fatalf("Parse arm M6 failed: %v", err)
	}
	ll, err := Translate(af, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"armM6": {Name: "armM6", Ret: Void}},
	})
	if err != nil {
		t.Fatalf("Translate arm M6 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "armv7-unknown-linux-gnueabihf")

	// Error paths across M6 arm64 & x86/386 lowerers
	badARM64 := []string{
		"ADRP target",
		"MOVP (R1)",
		"VLDNP 0(R1)",
		"LDTR R1, R2",
		"STTR $1, R2",
		"VMVNI R1, V0.B16",
		"VMVN $1, V0.B8",
		"SMOV $1, R1",
		"FCVTASW F0, $1",
		"FCVTZSDD F0, $1",
		"FCVTXN F0, $1",
		"VFCVTAS V0.S4, $1",
		"VFCVTXN V0.D2, $1",
		"FADDP V0.S2, $1",
		"FCMLE $0, F0, $1",
		"FMLA V0.S4, V1.S4, $1",
		"FABS V0.S2, $1",
		"FRECPE F0, $1",
		"FABD F0, F1, $1",
		"VADDHN V0.D2, V1.D2, $1",
		"VSABD V0.S4, V1.S4, $1",
		"VSADDL V0.H4, V1.H4, $1",
		"VSHLL R1, V0.B8, V1.H8",
		"VSHSUB V0.S2, V1.S2, $1",
		"VSADDLP V0.H8, $1",
		"VSADDLV V0.S4, $1",
		"VSQDMLAL2 V0.H8, V1.H8, $1",
		"VSRSHL V0.S2, V1.S2, $1",
		"VURSHR R1, V0, V1",
		"VSQSHLU R1, V0, V1",
		"VRSHRN R1, V0.D2, V1.S2",
		"VSUQADD V0, $1",
		"VURECPE V0.S4, $1",
		"LDNP 0(R1), R2",
		"STNP 0(R1), R2",
	}
	for _, ins := range badARM64 {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n\t" + ins + "\n\tRET\n"
		f, perr := Parse(ArchARM64, src)
		if perr != nil {
			continue
		}
		if _, err := Translate(f, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Errorf("expected error for invalid arm64 M6 instruction %q", ins)
		}
	}

	bad386 := []string{
		"FADDD F0",
		"FLDPI F0",
		"FFREE AX",
		"FINCSTP F0",
		"FDECSTP F0",
		"FXAM F0",
		"FCMOVB AX, BX",
		"FMOVF AX, BX",
		"FMOVL AX, BX",
		"FMOVX AX, BX",
		"FBLD AX",
		"FLDENV AX",
		"F2XM1 F0",
		"ARPL AX",
		"BOUNDW AX, BX",
		"PUSHAW AX",
		"POPAW AX",
	}
	for _, ins := range bad386 {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n\t" + ins + "\n\tRET\n"
		f, perr := Parse(ArchAMD64, src)
		if perr != nil {
			continue
		}
		if _, err := Translate(f, Options{
			TargetTriple: "i386-unknown-linux-gnu",
			Goarch:       "386",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Errorf("expected error for invalid 386 M6 instruction %q", ins)
		}
	}
}
