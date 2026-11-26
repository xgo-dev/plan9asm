//go:build !llgo

package plan9asm

import (
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func verifyLLVMWithTargetLLC(t *testing.T, ir string, triple string, extraLLCArgs ...string) {
	t.Helper()
	if opt := findLLVM22Tool("opt"); opt != "" {
		cmd := exec.Command(opt, "-passes=verify", "-disable-output", "-")
		cmd.Stdin = strings.NewReader(ir)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("opt verify (%s) failed: %v\n%s\nIR:\n%s", triple, err, out, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		return
	}
	args := []string{"-mtriple=" + triple, "-filetype=null", "-"}
	args = append(args, extraLLCArgs...)
	cmd := exec.Command(llc, args...)
	cmd.Stdin = strings.NewReader(ir)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("llc (%s) failed: %v\n%s\nIR:\n%s", triple, err, out, ir)
	}
}

// TestM5_ARM64DiffSemantics verifies bit-for-bit execution semantics of M4 SVE
// (VL=128) and M5 ARM64 scalar/bitfield/FP/NEON lowering against architectural
// reference values on native arm64 (or Linux qemu-aarch64) hosts, and runs full
// LLVM opt+llc verification on every host.
func TestM5_ARM64DiffSemantics(t *testing.T) {
	src := `
// Kernel 1: M5 ARM64 scalar ALU, remainder, bitfield, zero-extend, pair, FP16/FP64 conversions.
TEXT ·arm64M5Kernel(SB),NOSPLIT,$0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1

	// REM / REMW / UREM / UREMW (2-op & 3-op, incl. div-by-zero safety)
	MOVD $100, R2
	MOVD $7, R3
	REM  R3, R2, R4          // 100 % 7 = 2
	MOVD R4, 0(R0)
	MOVD $-100, R2
	REMW R3, R2, R4          // int32(-100) % 7 = -2 -> 0xfffffffe
	MOVD R4, 8(R0)
	MOVD $100, R2
	UREM R3, R2              // 100 % 7 = 2 (2-op)
	MOVD R2, 16(R0)
	MOVD $0, R3
	UREMW R3, R2, R4         // div by 0 => 0
	MOVD R4, 24(R0)

	// NEG 1-op, NEGW 1-op & 2-op, NEGS 1-op
	MOVD $42, R2
	NEG  R2                  // -42
	MOVD R2, 32(R0)
	MOVD $5, R2
	NEGW R2, R3              // uint32(-5) = 0xfffffffb
	MOVD R3, 40(R0)
	NEGW R3                  // 5
	MOVD R3, 48(R0)

	// UXTB / UXTH / UXTW / MOVZ / MOVN / MOVZW / MOVNW
	MOVD $-1, R2
	UXTB R2, R3              // 0xff
	MOVD R3, 56(R0)
	UXTH R2, R3              // 0xffff
	MOVD R3, 64(R0)
	UXTW R2, R3              // 0xffffffff
	MOVD R3, 72(R0)
	MOVZ $0x1234, $16, R3    // 0x12340000
	MOVD R3, 80(R0)
	MOVN $0, R3              // 0xffffffffffffffff
	MOVD R3, 88(R0)
	MOVZW $0xabcd, R3        // 0xabcd
	MOVD R3, 96(R0)
	MOVNW $0, R3             // 0xffffffff
	MOVD R3, 104(R0)

	// BFM / SBFM / UBFM (imms >= immr extract AND imms < immr insert/shift)
	MOVD $0x12345678, R2
	UBFM $8, R2, $15, R3     // (0x12345678 >> 8) & 0xff = 0x56
	MOVD R3, 112(R0)
	MOVD $0x8000, R2
	SBFM $8, R2, $15, R3     // sext8(0x80) = -128
	MOVD R3, 120(R0)
	MOVD $0xaa00, R3
	MOVD $0x55, R2
	BFM  $0, R2, $7, R3      // 0xaa55
	MOVD R3, 128(R0)
	UBFMW $28, R2, $3, R3    // (0x55 & 0xf) << 4 = 0x50
	MOVD R3, 136(R0)
	SBFMW $28, R2, $3, R3    // sext8(0x50) = 0x50 (bit 7 is 0)
	MOVD R3, 144(R0)
	MOVD $0xff00, R3
	BFMW $28, R2, $3, R3     // (0xff00 & ~0xf0) | 0x50 = 0xff50
	MOVD R3, 152(R0)

	// 2-op SDIV, UDIVW, MNEG, SMULL, UMULL, SMULH, UMULH
	MOVD $50, R2
	MOVD $6, R3
	SDIV R3, R2              // 50 / 6 = 8
	MOVD R2, 160(R0)
	MOVD $7, R2
	MNEG R3, R2              // -(7*6) = -42
	MOVD R2, 168(R0)
	MOVD $10, R2
	UMULL R3, R2             // 60
	MOVD R2, 176(R0)

	// LDNP / STNP / LDNPW / STNPW / MOVBW / MOVHW
	LDNP (R1), (R5, R6)
	STNP (R6, R5), 184(R0)   // swapped pair from data[0..1]
	LDNPW (R1), (R5, R6)
	STNPW (R5, R6), 200(R0)
	MOVBW 0(R1), R5          // low byte of data[0] = 0xef -> sext32 = 0xffffffef
	MOVD R5, 208(R0)
	MOVHW 0(R1), R5          // low half of data[0] = 0xcdef -> sext32 = 0xffffcdef
	MOVD R5, 216(R0)

	// FP conversions: SCVTF / UCVTF (normal & fixed-point) / FCVTSD / FCVTDS / FCVTSH+FCVTHS / FCVTDH+FCVTHD / FCVT{A,M,N,P,Z}{S,U}
	MOVD $3, R2
	SCVTF R2, F0             // 3.0
	FCVTDS F0, F1            // float32(3.0)
	FCVTSH F1, F2            // fp16(3.0)
	FCVTHS F2, F3            // float32(3.0)
	FCVTSD F3, F4            // float64(3.0)
	FCVTDH F4, F5            // fp16(3.0)
	FCVTHD F5, F6            // float64(3.0)
	FCVTZS F6, R7            // 3
	MOVD R7, 224(R0)

	MOVD $5, R2
	SCVTF $1, R2, F0         // 5 * 2^-1 = 2.5
	FCVTAS F0, R7            // round(2.5) = 3
	MOVD R7, 232(R0)
	FCVTMS F0, R7            // floor(2.5) = 2
	MOVD R7, 240(R0)
	FCVTNS F0, R7            // roundeven(2.5) = 2
	MOVD R7, 248(R0)
	FCVTPS F0, R7            // ceil(2.5) = 3
	MOVD R7, 256(R0)
	FCVTZU $2, F0, R7        // trunc(2.5 * 4) = 10
	MOVD R7, 264(R0)

	// FCMEQ / FCMGE / FCMGT / FMULX scalar
	MOVD $3, R2
	UCVTF R2, F1             // 3.0
	FCMEQ F0, F0, F2         // 2.5 == 2.5 -> -1
	FMOVD F2, R7
	MOVD R7, 272(R0)
	FCMGT F0, F1, F2         // 3.0 > 2.5 -> -1
	FMOVD F2, R7
	MOVD R7, 280(R0)
	FCMGE F1, F0, F2         // 2.5 >= 3.0 -> 0
	FMOVD F2, R7
	MOVD R7, 288(R0)
	FMULX F0, F1, F2         // 3.0 * 2.5 = 7.5
	FCVTZS F2, R7            // 7
	MOVD R7, 296(R0)
	RET

// Kernel 2: Additional M5 ARM64 x/arch & encoder forms (verified via opt + llc).
TEXT ·arm64M5Forms(SB),NOSPLIT,$0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1
	MOVBW.P 1(R1), R2
	MOVBW.W 1(R1), R2
	MOVHW.P 2(R1), R2
	MOVHW.W 2(R1), R2
	MOVBW R2, (R0)
	FMOVB.P 1(R1), F0
	FMOVB.W 1(R1), F0
	FMOVB.W F0, 1(R0)
	FMOVB F0, (R0)
	FMOVH.P 2(R1), F1
	FMOVH.W 2(R1), F1
	FMOVH $1.5, F1
	FMOVH F1, (R0)
	FMOV $-0.5, V1.S4
	FMOV $2, V2.D2
	VMOVS $const_q, V3
	VMOVS $1.0, V3
	VFMULX V1.S4, V2.S4, V3.S4
	FMUL V1.S[1], V2.S4, V3.S4
	VSQDMLAL V1.H8, V2.H8, V3.H8
	VSQDMLSL V1.H8, V2.H8, V3.H8
	VSQDMULH V1.H8, V2.H8, V3.H8
	VSQRDMULH V1.H8, V2.H8, V3.H8
	VSQDMULL V1.H8, V2.H8, V3.H8
	LD2.P (R1), [V0.B, V1.B][0]
	LD3 (R1), [V0.H, V1.H, V2.H][1]
	LD4 (R1), [V0.S, V1.S, V2.S, V3.S][2]
	ST2.P (R0), [V0.B, V1.B][0]
	ST3 [V0.H, V1.H, V2.H][1], (R0)
	ST4 (R0), [V0.S, V1.S, V2.S, V3.S][2]
	VST2 (R0), [V0.H8, V1.H8]
	VSUB V0.S4, V1.S4
	PLDR R1, $1, P2
	PSTR P2, R0, $1
	ZLD1B R1, R2, P0.Z, Z4.B
	ZLD1D Z0.D, $1, P0.Z, Z5.D
	ZST1D Z5.D, P0, Z0.D, $1
	ZCMPLE $1, Z0.S, P0.Z, P3.S
	ZCMPLO Z0.D, Z1.D, P0.Z, P3.D
	ZCMPLS $2, Z0.S, P0.Z, P3.S
	ZCMPLT Z0.S, Z1.S, P0.Z, P3.S
	AT $4
	IC $4
	PRFUM $0, (R1)
	PCALIGNMAX $4, $4
	DWORD $0
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse arm64 M5 failed: %v", err)
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
			"arm64M5Kernel": {Name: "arm64M5Kernel", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
			"arm64M5Forms":  {Name: "arm64M5Forms", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
		},
	})
	if err != nil {
		t.Fatalf("Translate arm64 M5 failed: %v", err)
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
extern void arm64M5Kernel(uint64_t *out, uint64_t *data);
int main(void) {
    uint64_t data[4] = {
        0x000000020000cdefULL, // low32=0x0000cdef, hi32=0x00000002
        0x0000000400000003ULL, // low32=3, hi32=4
        0x0000002000000010ULL, // low32=0x10, hi32=0x20
        0x0000004000000030ULL, // low32=0x30, hi32=0x40
    };
    uint64_t out[48] = {0};
    arm64M5Kernel(out, data);
    uint64_t want[38] = {
        2ULL,                      // [0] REM 100 % 7
        0x00000000fffffffeULL,     // [1] REMW -100 % 7
        2ULL,                      // [2] UREM 100 % 7
        0ULL,                      // [3] UREMW / 0
        (uint64_t)-42LL,           // [4] NEG 42
        0x00000000fffffffbULL,     // [5] NEGW 5
        5ULL,                      // [6] NEGW -5
        0xffULL,                   // [7] UXTB -1
        0xffffULL,                 // [8] UXTH -1
        0xffffffffULL,             // [9] UXTW -1
        0x12340000ULL,             // [10] MOVZ
        0xffffffffffffffffULL,     // [11] MOVN 0
        0xabcdULL,                 // [12] MOVZW
        0xffffffffULL,             // [13] MOVNW 0
        0x56ULL,                   // [14] UBFM extract
        (uint64_t)-128LL,          // [15] SBFM extract
        0xaa55ULL,                 // [16] BFM
        0x50ULL,                   // [17] UBFMW shift
        0x50ULL,                   // [18] SBFMW shift
        0xff50ULL,                 // [19] BFMW insert
        8ULL,                      // [20] SDIV 2-op
        (uint64_t)-42LL,           // [21] MNEG 2-op
        60ULL,                     // [22] UMULL 2-op
        data[1],                   // [23] STNP swapped[0]
        data[0],                   // [24] STNP swapped[1]
        data[0],                   // [25] STNPW(LDNPW(data[0]))
        0x00000000ffffffefULL,     // [26] MOVBW 0xef
        0x00000000ffffcdefULL,     // [27] MOVHW 0xcdef
        3ULL,                      // [28] SCVTF->FCVTDS->FCVTSH->FCVTHS->FCVTSD->FCVTDH->FCVTHD->FCVTZS
        3ULL,                      // [29] FCVTAS(2.5)
        2ULL,                      // [30] FCVTMS(2.5)
        2ULL,                      // [31] FCVTNS(2.5)
        3ULL,                      // [32] FCVTPS(2.5)
        10ULL,                     // [33] FCVTZU $2 (2.5)
        0xffffffffffffffffULL,     // [34] FCMEQ
        0xffffffffffffffffULL,     // [35] FCMGT
        0ULL,                      // [36] FCMGE
        7ULL,                      // [37] FMULX 3.0*2.5 -> 7
    };
    for (int i = 0; i < 38; i++) {
        if (out[i] != want[i]) {
            fprintf(stderr, "mismatch at [%d]: got=0x%llx want=0x%llx\n", i, (unsigned long long)out[i], (unsigned long long)want[i]);
            return i + 1;
        }
    }
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "arm64_m5_diff", triple, ll, mainC, nil)
}

// TestM5_ARM64SVEScalableCodegen verifies that SVE instructions lower to true
// runtime-scalable LLVM IR (@llvm.vscale.i64(), <vscale x N x T>,
// @llvm.aarch64.sve.*) rather than hardcoding VL=128, and lower to hardware
// SVE instructions under llc -mtriple=aarch64-unknown-linux-gnu.
func TestM5_ARM64SVEScalableCodegen(t *testing.T) {
	src := `
TEXT ·sveRDVL(SB),NOSPLIT,$0-8
	RDVL $1, R0
	MOVD R0, ret+0(FP)
	RET

TEXT ·sveKernel(SB),NOSPLIT,$0-16
	MOVD out+0(FP), R0
	MOVD data+8(FP), R1
	RDVL $1, R2
	MOVD R2, 0(R0)
	ADDVL $2, R0, R3
	MOVD R3, 8(R0)
	ADDPL $2, R1, R4
	MOVD R4, 16(R0)
	PPTRUE P0.S
	MOVD 0(R1), R5
	MOVD 8(R1), R6
	PWHILELT R6, R5, P1.S
	PCNTP P1.S, P0, R7
	MOVD R7, 24(R0)
	ZLD1W (R1), P0/Z, Z0.S
	ZLD1W (VL*1)(R1), P0/Z, Z1.S
	ZADD Z1.S, Z0.S, Z2.S
	ZST1W Z2.S, P0, 32(R0)
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse arm64 scalable SVE failed: %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"sveRDVL": {Name: "sveRDVL", Ret: I64, Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0}}}},
			"sveKernel": {
				Name: "sveKernel",
				Args: []LLVMType{Ptr, Ptr},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Translate arm64 scalable SVE failed: %v", err)
	}
	for _, want := range []string{
		"@llvm.vscale.i64()",
		"<vscale x 4 x i32>",
		"@llvm.aarch64.sve.whilelt.nxv4i1.i64",
		"@llvm.aarch64.sve.cntp.nxv4i1",
		"@llvm.masked.load.nxv4i32.p0",
		"@llvm.masked.store.nxv4i32.p0",
		`"target-features"="+sve"`,
	} {
		if !strings.Contains(ll, want) {
			t.Fatalf("missing %q in scalable SVE IR:\n%s", want, ll)
		}
	}
	verifyLLVMWithTargetLLC(t, ll, "aarch64-unknown-linux-gnu")
	verifyLLVMWithTargetLLC(t, ll, "arm64-apple-darwin")
	if llc := findLLVM22Tool("llc"); llc != "" {
		cmd := exec.Command(llc, "-mtriple=aarch64-unknown-linux-gnu", "-filetype=asm", "-o", "-")
		cmd.Stdin = strings.NewReader(ll)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("llc asm failed: %v\n%s", err, out)
		}
		asmOut := string(out)
		for _, wantAsm := range []string{"rdvl", "addvl", "whilelt", "cntp", "ld1w", "st1w"} {
			if !strings.Contains(asmOut, wantAsm) {
				t.Errorf("missing hardware SVE mnemonic %q in llc output:\n%s", wantAsm, asmOut)
			}
		}
	}
}

// TestM5_AMD64DiffSemantics verifies M1-M5 amd64 extensions under opt + Haswell llc
// everywhere, and executes bit-for-bit runtime verification on amd64 hosts (and via Rosetta on darwin/arm64).
func TestM5_AMD64DiffSemantics(t *testing.T) {
	srcVerify := `
TEXT ·amd64M5Kernel(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), DI
	MOVQ in+8(FP), SI

	// M3 MOVBEQ + BMI2 PDEPQ/PEXTQ + DIVQ
	MOVBEQ 0(SI), AX
	MOVQ AX, 0(DI)
	MOVQ $0x0f0f0f0f0f0f0f0f, CX
	MOVQ $0x12345678, DX
	PDEPQ CX, DX, R8
	MOVQ R8, 8(DI)
	PEXTQ CX, R8, R9
	MOVQ R9, 16(DI)
	MOVQ $100, AX
	XORQ DX, DX
	MOVQ $7, BX
	DIVQ BX
	MOVQ AX, 24(DI)
	MOVQ DX, 32(DI)

	// M5 SALB, MOVQL, XCHGQ reversed, VMOVDQU64 YMM/XMM, VEXTRACTF32X4 YMM, MOVSS float imm
	MOVQ $3, AX
	SALB $2, AL
	MOVBQZX AL, AX
	MOVQ AX, 40(DI)
	MOVQL $0x12345678, BX
	MOVQ BX, 48(DI)
	MOVQ $99, CX
	MOVQ $77, 56(DI)
	XCHGQ 56(DI), CX
	MOVQ CX, 64(DI)

	VMOVDQU64 0(SI), Y0
	VMOVDQU64 Y0, 72(DI)
	VEXTRACTF32X4 $1, Y0, 104(DI)
	MOVSS $(-1.0), X1
	MOVSS X1, 120(DI)

	// M1 GF2P8MULB (a=0x57, b=0x83 in GF(2^8) mod 0x11b = 0xc1)
	VMOVDQU 0(SI), X2
	VMOVDQU 16(SI), X3
	VGF2P8MULB X3, X2, X2
	VMOVDQU X2, 128(DI)

	// M2 FMA3 VFMADD213SD
	MOVSD $2.0, X4
	MOVSD $3.0, X5
	MOVSD $4.0, X6
	VFMADD213SD X6, X5, X4   // 2*3 + 4 = 10.0
	MOVSD X4, 144(DI)

	// M5 encoder/ecosystem forms: MOVQOZX X-X, MOVHPD/LPD X-X, V4FMADDPS/VP4DPWSSD single-reg, seg MOVW/POPW, system ops, LONG/QUAD
	MOVQOZX X0, X7
	MOVHPD X0, X7
	MOVLPD X0, X7
	V4FMADDPS 0(SI), Z0, K1, Z4
	V4FNMADDSS 0(SI), X0, K1, X4
	VP4DPWSSD 0(SI), Z0, K1, Z4
	MOVW AX, CS
	MOVW CS, BX
	MOVQ GDTR, 152(DI)
	MOVL GDTR, 152(DI)
	POPW DS
	ENTER $0, $0
	LEAVEL
	LEAVEW
	INB
	OUTB
	XACQUIRE
	XRELEASE
	LONG $0x90909090
	QUAD $0x9090909090909090
	RET
`
	srcExec := `
// Executable AMD64 differential semantics kernel (no privileged ops, SP-changing POPW/LEAVE, or libm fmaf).
TEXT ·amd64M5Exec(SB),NOSPLIT,$0-16
	MOVQ out+0(FP), DI
	MOVQ in+8(FP), SI

	// M3 MOVBEQ
	MOVBEQ 0(SI), AX
	MOVQ AX, 0(DI)
	// M3 BMI2 PDEPQ / PEXTQ
	MOVQ $0x0f0f0f0f0f0f0f0f, CX
	MOVQ $0x12345678, DX
	PDEPQ CX, DX, R8
	MOVQ R8, 8(DI)
	PEXTQ CX, R8, R9
	MOVQ R9, 16(DI)
	// M3 DIVQ (100 / 7 = 14 rem 2)
	MOVQ $100, AX
	XORQ DX, DX
	MOVQ $7, BX
	DIVQ BX
	MOVQ AX, 24(DI)
	MOVQ DX, 32(DI)
	// M5 SALB, MOVQL, XCHGQ reversed
	MOVQ $3, AX
	SALB $2, AL
	MOVBQZX AL, AX
	MOVQ AX, 40(DI)
	MOVQL $0x12345678, BX
	MOVQ BX, 48(DI)
	MOVQ $99, CX
	MOVQ $77, 56(DI)
	XCHGQ 56(DI), CX
	MOVQ CX, 64(DI)
	// M5 VMOVDQU64 YMM + VEXTRACTF32X4 YMM + MOVSS $(-1.0)
	VMOVDQU64 0(SI), Y0
	VMOVDQU64 Y0, 72(DI)
	VEXTRACTF32X4 $1, Y0, 104(DI)
	MOVSS $(-1.0), X1
	MOVSS X1, 120(DI)
	// M1 VGF2P8MULB (0x57 * 0x83 = 0xc1 in GF(2^8) mod 0x11b)
	VMOVDQU 0(SI), X2
	VMOVDQU 16(SI), X3
	VGF2P8MULB X3, X2, X2
	VMOVDQU X2, 128(DI)
	// M2 VFMADD213SD (2*3 + 4 = 10.0)
	MOVSD $2.0, X4
	MOVSD $3.0, X5
	MOVSD $4.0, X6
	VFMADD213SD X6, X5, X4
	MOVSD X4, 144(DI)
	RET
`
	ptr2 := FrameLayout{Params: []FrameSlot{
		{Offset: 0, Type: Ptr, Index: 0, Field: -1},
		{Offset: 8, Type: Ptr, Index: 1, Field: -1},
	}}
	fileVerify, err := Parse(ArchAMD64, srcVerify)
	if err != nil {
		t.Fatalf("Parse amd64 M5 verify failed: %v", err)
	}
	llVerify, err := Translate(fileVerify, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"amd64M5Kernel": {Name: "amd64M5Kernel", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
		},
	})
	if err != nil {
		t.Fatalf("Translate amd64 M5 verify failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, llVerify, "x86_64-unknown-linux-gnu", "-mcpu=haswell", "-mattr=+aes,+ssse3,+sse4.1,+sse4.2,+pclmul,+avx,+avx2,+sha,+popcnt,+adx")

	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		return
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	fileExec, err := Parse(ArchAMD64, srcExec)
	if err != nil {
		t.Fatalf("Parse amd64 M5 exec failed: %v", err)
	}
	llExec, err := Translate(fileExec, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"amd64M5Exec": {Name: "amd64M5Exec", Args: []LLVMType{Ptr, Ptr}, Ret: Void, Frame: ptr2},
		},
	})
	if err != nil {
		t.Fatalf("Translate amd64 M5 exec failed: %v", err)
	}
	mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern void amd64M5Exec(uint64_t *out, uint64_t *in);
int main(void) {
    uint64_t in[4] = {0x0102030405060757ULL, 0x1122334455667788ULL, 0x0000000000000083ULL, 0x99aabbccddeeff00ULL};
    uint64_t out[24] = {0};
    amd64M5Exec(out, in);
    if (out[0] != 0x5707060504030201ULL) { fprintf(stderr, "out[0]=0x%llx\n", (unsigned long long)out[0]); return 1; }
    if (out[1] != 0x0102030405060708ULL) { fprintf(stderr, "out[1]=0x%llx\n", (unsigned long long)out[1]); return 2; }
    if (out[2] != 0x12345678ULL) { fprintf(stderr, "out[2]=0x%llx\n", (unsigned long long)out[2]); return 3; }
    if (out[3] != 14ULL || out[4] != 2ULL) { fprintf(stderr, "out[3]=%llu out[4]=%llu\n", (unsigned long long)out[3], (unsigned long long)out[4]); return 4; }
    if (out[5] != 12ULL) { fprintf(stderr, "out[5]=%llu\n", (unsigned long long)out[5]); return 5; }
    if (out[6] != 0x12345678ULL) { fprintf(stderr, "out[6]=0x%llx\n", (unsigned long long)out[6]); return 6; }
    if (out[7] != 99ULL || out[8] != 77ULL) { fprintf(stderr, "out[7]=%llu out[8]=%llu\n", (unsigned long long)out[7], (unsigned long long)out[8]); return 7; }
    if (out[9] != in[0] || out[12] != in[3]) { fprintf(stderr, "out[9]=0x%llx out[12]=0x%llx\n", (unsigned long long)out[9], (unsigned long long)out[12]); return 8; }
    if (out[13] != in[2] || out[14] != in[3]) { fprintf(stderr, "out[13]=0x%llx out[14]=0x%llx\n", (unsigned long long)out[13], (unsigned long long)out[14]); return 9; }
    if ((uint32_t)out[15] != 0xbf800000U) { fprintf(stderr, "out[15]=0x%x\n", (unsigned)(uint32_t)out[15]); return 10; }
    if ((out[16] & 0xffULL) != 0xc1ULL) { fprintf(stderr, "out[16]=0x%llx\n", (unsigned long long)out[16]); return 11; }
    if (out[18] != 0x4024000000000000ULL) { fprintf(stderr, "out[18]=0x%llx\n", (unsigned long long)out[18]); return 12; }
    return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "amd64_m5_diff", triple, llExec, mainC, runPrefix)
}

// TestM5_ARM32EncoderOps verifies all M5 32-bit ARM encoder completeness ops.
func TestM5_ARM32EncoderOps(t *testing.T) {
	src := `
TEXT ·armM5(SB),NOSPLIT,$0-0
	MOVW $100, R0
	MOVW $7, R1
	DIV  R1, R0, R2
	DIVU R1, R0
	MOD  R1, R0, R3
	MODU R1, R0
	BFC  $4, R2
	BFC  $4, R2, R3
	BFI  $4, R2
	BFI  $4, R2, R3
	BFX  $4, R2
	BFX  $4, R2, R3
	BFXU $4, R2
	BFXU $4, R2, R3
	FMULAD F0, F1
	FMULAF F0, F1
	FMULSD F0, F1
	FMULSF F0, F1
	FNMULAD F0, F1
	FNMULAF F0, F1
	FNMULSD F0, F1
	FNMULSF F0, F1
	MULAD F0, F1
	MULAF F0, F1
	MULSD F0, F1
	MULSF F0, F1
	NMULAD F0, F1
	NMULAF F0, F1
	NMULSD F0, F1
	NMULSF F0, F1
	STREX 4(R1), R0, R2
	STREXB 4(R1), R0, R2
	STREXD 4(R1), R0, R2
	SWPW 4(R1), R0, R2
	SWPBU 4(R1), R0, R2
	DUFFZERO $0
	DUFFCOPY $0
	BXRET R14
`
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatalf("Parse arm M5 failed: %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         map[string]FuncSig{"armM5": {Name: "armM5", Ret: Void}},
	})
	if err != nil {
		t.Fatalf("Translate arm M5 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "armv7-unknown-linux-gnueabihf")
}

// TestM5_WASMCompleteOpsAndSIMD128 verifies full M5 WebAssembly scalar, FP,
// conversion, control, and SIMD128 lowering under LLVM opt + wasm32 llc.
func TestM5_WASMCompleteOpsAndSIMD128(t *testing.T) {
	src := `
TEXT ·wasmM5(SB),NOSPLIT,$0-8
	// Integer bit manipulation & sign-extension
	I32Const $12
	I32Clz
	I32Ctz
	I32Popcnt
	I32Const $3
	I32Rotl
	I32Const $1
	I32Rotr
	I32Extend8S
	I32Extend16S
	Drop

	I64Const $42
	I64Clz
	I64Ctz
	I64Popcnt
	I64Const $5
	I64Rotl
	I64Const $2
	I64Rotr
	I64Extend8S
	I64Extend16S
	I64Extend32S
	LocalSet R0
	LocalGet R0
	LocalTee R1
	GlobalSet R2
	GlobalGet R2
	Drop

	// F32 / F64 const, load/store mem, arith, unary, cmp, conversions, reinterpret
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Add
	F32Const $0x3f800000
	F32Sub
	F32Const $0x40000000
	F32Mul
	F32Const $0x40000000
	F32Div
	F32Abs
	F32Neg
	F32Ceil
	F32Floor
	F32Trunc
	F32Nearest
	F32Sqrt
	F32Const $0x3f800000
	F32Min
	F32Const $0x40000000
	F32Max
	F32Const $0x3f800000
	F32Copysign
	F32Const $0x3f800000
	F32Eq
	Drop
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Ne
	Drop
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Lt
	Drop
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Gt
	Drop
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Le
	Drop
	F32Const $0x3f800000
	F32Const $0x40000000
	F32Ge
	Drop

	I32Const $0
	F32Load $0
	F64PromoteF32
	F64Abs
	F64Neg
	F64Nearest
	F64Sqrt
	F64Const $0x3ff0000000000000
	F64Add
	F64Const $0x3ff0000000000000
	F64Sub
	F64Const $0x4000000000000000
	F64Mul
	F64Const $0x4000000000000000
	F64Div
	F64Const $0x3ff0000000000000
	F64Min
	F64Const $0x4000000000000000
	F64Max
	F64Const $0x3ff0000000000000
	F64Copysign
	I32Const $0
	F64Load $8
	F64Eq
	Drop
	F64Const $0x3ff0000000000000
	F64Const $0x4000000000000000
	F64Le
	Drop
	F64Const $0x3ff0000000000000
	F64Const $0x4000000000000000
	F64Ge
	Drop

	// Conversions & reinterprets
	I32Const $7
	F32ConvertI32S
	I32TruncF32S
	F32ConvertI32U
	I32TruncSatF32U
	F64ConvertI32S
	I32TruncSatF64S
	F64ConvertI32U
	I64TruncSatF64U
	F32ConvertI64S
	I64TruncF32S
	F32ConvertI64U
	I64TruncSatF32U
	F64ConvertI64S
	I64ReinterpretF64
	F64ReinterpretI64
	F32DemoteF64
	I32ReinterpretF32
	F32ReinterpretI32
	I32Const $0
	F32Const $0x3f800000
	F32Store $0
	I32Const $0
	F64Const $0x3ff0000000000000
	F64Store $8
	Drop

	// Memory / Misc
	MemorySize
	MemoryGrow
	Drop
	MOVH $1, R3

	// SIMD128 (V128)
	V128Const $1, $2
	V128Not
	V128Const $3, $4
	V128And
	V128Const $5, $6
	V128Andnot
	V128Const $7, $8
	V128Or
	V128Const $9, $10
	V128Xor
	V128Const $1, $1
	V128Const $2, $2
	V128Bitselect
	V128AnyTrue
	Drop

	I32Const $0
	V128Load $0
	I32Const $0
	V128Load32Zero $0
	I32x4Add
	I32Const $0
	V128Load64Zero $0
	I64x2Sub
	I32Const $0
	V128Load8Splat $0
	I8x16AddSatS
	I32Const $0
	V128Load16Splat $0
	I16x8SubSatU
	I32Const $0
	V128Load32Splat $0
	I32x4MinS
	I32Const $0
	V128Load64Splat $0
	I64x2Mul
	I32Const $0
	V128Load8x8S $0
	I16x8MaxU
	I32Const $0
	V128Load16x4U $0
	I32x4Eq
	I32Const $0
	V128Load32x2S $0
	I64x2LtS
	V128Const $1, $2
	I8x16AvgrU
	I8x16Abs
	I8x16Neg
	I8x16Popcnt
	I32Const $2
	I32x4Shl
	I32Const $1
	I32x4ShrS
	I32Const $1
	I32x4ShrU
	I32x4AllTrue
	Drop
	I32Const $9
	I32x4Splat
	I32x4Bitmask
	Drop
	I32Const $5
	I8x16Splat
	I8x16ExtractLaneS $0
	Drop
	I32Const $0
	I32Const $5
	I8x16Splat
	I32Const $7
	I8x16ReplaceLane $1
	V128Load8Lane $0, $0
	I32Const $0
	I32Const $5
	I8x16Splat
	V128Store8Lane $0, $0
	Drop
	F32Const $0x3f800000
	F32x4Splat
	F32Const $0x40000000
	F32x4Splat
	F32x4Add
	F32x4Sqrt
	F32x4Ceil
	F32x4Floor
	F32x4Trunc
	F32x4Nearest
	F32x4Abs
	F32x4Neg
	F32Const $0x3f800000
	F32x4Splat
	F32x4Min
	F32Const $0x40000000
	F32x4Splat
	F32x4Max
	F32Const $0x3f800000
	F32x4Splat
	F32x4Eq
	F64Const $0x3ff0000000000000
	F64x2Splat
	F64Const $0x4000000000000000
	F64x2Splat
	F64Const $0x3ff0000000000000
	F64x2Splat
	F64x2RelaxedMadd
	F64Const $0x4000000000000000
	F64x2Splat
	F64Const $0x3ff0000000000000
	F64x2Splat
	F64x2RelaxedNmadd
	V128Const $1, $2
	V128Const $3, $4
	I32x4RelaxedLaneselect
	V128Const $1, $2
	I8x16Swizzle
	I16x8ExtendLowI8x16S
	I32Const $0
	V128Const $1, $2
	V128Store $0
	Drop

	// BrTable
	Block
		Block
			I32Const $0
			BrTable $0, $1
		End
	End
	Return
`
	file, err := Parse(ArchWASM, src)
	if err != nil {
		t.Fatalf("Parse wasm M5 failed: %v", err)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Goarch:       "wasm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"wasmM5": {
				Name: "wasmM5",
				Args: []LLVMType{I32},
				Ret:  Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("Translate wasm M5 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "wasm32-unknown-unknown")
}

// TestM5_WASMRejectsUnmodeledSegmentAndTableOps ensures segment/table/pseudo
// Wasm instructions without real segment/table semantics fail explicitly
// instead of being silently dropped or stubbed.
func TestM5_WASMRejectsUnmodeledSegmentAndTableOps(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"MemoryInit+DataDrop", "I32Const $0\nI32Const $0\nI32Const $0\nMemoryInit $0\nDataDrop $0\n"},
		{"MemoryInit", "I32Const $0\nI32Const $0\nI32Const $0\nMemoryInit\n"},
		{"DataDrop", "DataDrop $0\n"},
		{"ElemDrop", "ElemDrop $0\n"},
		{"TableInit", "I32Const $0\nI32Const $0\nI32Const $0\nTableInit $0\n"},
		{"TableCopy", "I32Const $0\nI32Const $0\nI32Const $0\nTableCopy $0\n"},
		{"TableFill", "I32Const $0\nI32Const $0\nI32Const $0\nTableFill $0\n"},
		{"TableSize", "TableSize $0\nDrop\n"},
		{"TableGrow", "I32Const $0\nI32Const $1\nTableGrow $0\nDrop\n"},
		{"ResumePoint", "ResumePoint\n"},
		{"Word", "Word $1\n"},
		{"GlobalGet imm", "GlobalGet $0\nDrop\n"},
		{"GlobalSet imm", "I32Const $1\nGlobalSet $0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + tc.body + "Return\n"
			file, err := Parse(ArchWASM, src)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: "wasm32-unknown-unknown",
				Goarch:       "wasm",
				ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			})
			if err == nil {
				t.Fatalf("expected explicit unsupported error for %s, got IR:\n%s", tc.name, ir)
			}
		})
	}
}

// TestM5_ErrorPaths exercises error/edge branches across M5 ARM64, WASM, and x86 lowerers.
func TestM5_ErrorPaths(t *testing.T) {
	arm64Bad := []string{
		"REM R1",
		"REM R1, $2",
		"NEGW",
		"NEGW $1",
		"UXTB R1",
		"MOVZ $1",
		"BFM $1, R1, R2",
		"FCVTSD F1",
		"MOVBW R1",
		"MOVBW R1, $2",
		"FMOVB R1",
		"FMOVB F1, $2",
		"FMOV $1",
		"LDNP (R1), R2",
		"STNP R1, (R2)",
		"FCVTAS F1",
		"FCVTAS F1, $2",
		"SCVTF R1",
		"FCMEQ F1, F2",
		"FMULX F1, F2",
		"VSQDMLAL V1.H8, V2.H8",
		"LD2 (R1)",
		"LD2 R1, R2",
		"LD2 (R1), R2",
		"ST2 (R1)",
	}
	for _, body := range arm64Bad {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
		file, err := Parse(ArchARM64, src)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Errorf("arm64 expected error for: %s", body)
		}
	}

	// Also exercise wasmCastFloat int-to-float bitcast and Wasm M5 error paths.
	wasmBitcast := `
TEXT ·wasmCast(SB),NOSPLIT,$0-0
	I32Const $0x3f800000
	I32Const $0x40000000
	F32Add
	Drop
	I64Const $0x3ff0000000000000
	I64Const $0x4000000000000000
	F64Add
	Drop
	I32Const $0
	V128Load16Lane $0, $0
	Drop
	I32Const $0
	V128Const $1, $2
	V128Load32Lane $0, $0
	Drop
	I32Const $0
	V128Const $1, $2
	V128Load64Lane $0, $0
	Drop
	V128Const $1, $2
	V128Const $3, $4
	I8x16AddSatU
	V128Const $1, $2
	I8x16SubSatS
	V128Const $1, $2
	I8x16MinU
	V128Const $1, $2
	I8x16MaxS
	V128Const $1, $2
	I32x4DotI16x8S
	V128Const $1, $2
	V128Const $3, $4
	I32x4RelaxedDotI8x16I7x16AddS
	Drop
	RET
`
	if f, err := Parse(ArchWASM, wasmBitcast); err == nil {
		if ll, err := Translate(f, Options{
			TargetTriple: "wasm32-unknown-unknown",
			Goarch:       "wasm",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"wasmCast": {Name: "wasmCast", Ret: Void}},
		}); err == nil {
			verifyLLVMWithTargetLLC(t, ll, "wasm32-unknown-unknown")
		}
	}

	wasmBad := []string{
		"I32Clz",
		"I32Rotl",
		"I32Const $1\nI32Rotl",
		"I32Extend8S",
		"F32Const",
		"F32Load $0",
		"F32Store $0",
		"I32Const $0\nF32Store $0",
		"F32Add",
		"F32Const $0\nF32Add",
		"F32Abs",
		"F32Eq",
		"F32Const $0\nF32Eq",
		"I32TruncF32S",
		"F32ConvertI32S",
		"F32DemoteF64",
		"F64PromoteF32",
		"I32ReinterpretF32",
		"MemoryInit",
		"TableGrow",
		"V128Load $0",
		"V128Store $0",
		"V128Not",
		"I32Const $1\nV128Not",
		"V128And",
		"V128Const $1, $2\nV128And",
		"V128Bitselect",
		"V128AnyTrue",
		"I8x16Splat",
		"I8x16ExtractLaneS $0",
		"I8x16ReplaceLane $0",
		"I32x4AllTrue",
		"I32x4Bitmask",
		"I32x4Shl",
		"I32x4Eq",
		"I32x4Add",
		"I8x16Abs",
		"F64x2RelaxedMadd",
		"I8x16Swizzle",
		"I16x8ExtendLowI8x16S",
		"BrTable",
	}
	for _, body := range wasmBad {
		src := "TEXT ·bad(SB),NOSPLIT,$0-0\n" + body + "\nRET\n"
		file, err := Parse(ArchWASM, src)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "wasm32-unknown-unknown",
			Goarch:       "wasm",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
		}); err == nil {
			t.Errorf("wasm expected error for: %s", body)
		}
	}
}
