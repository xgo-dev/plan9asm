//go:build !llgo

package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func runOptO2(t *testing.T, ir string) string {
	t.Helper()
	opt := findLLVM22Tool("opt")
	if opt == "" {
		t.Fatal("LLVM 22 opt not found")
	}
	cmd := exec.Command(opt, "-O2", "-S", "-")
	cmd.Stdin = strings.NewReader(ir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("opt -O2 failed: %v\n%s\nIR:\n%s", err, out, ir)
	}
	return string(out)
}

func extractLLVMFuncBody(t *testing.T, ir, fnName string) string {
	t.Helper()
	needle := "@" + fnName + "("
	idx := strings.Index(ir, needle)
	if idx < 0 {
		t.Fatalf("function %s not found in IR:\n%s", fnName, ir)
	}
	start := strings.Index(ir[idx:], "{")
	if start < 0 {
		t.Fatalf("function %s missing body open brace", fnName)
	}
	rest := ir[idx+start:]
	end := strings.Index(rest, "\n}")
	if end < 0 {
		t.Fatalf("function %s missing body close brace", fnName)
	}
	return rest[:end+2]
}

// TestCrossArchARM64MultiplyAccumulateAndCarryFlags verifies:
//   - Plan 9 ARM64 4-operand order (Rm, Ra, Rn, Rd => Ra +/- Rm*Rn) for all 8
//     integer multiply-accumulate ops: SMADDL, UMADDL, SMSUBL, UMSUBL, MADD,
//     MSUB, MADDW, MSUBW with asymmetric inputs.
//   - Exact AArch64 AddWithCarry NZCV flag propagation (especially carry-out
//     and signed overflow with carry-in C=1 / borrow C=0) for all 6 ops:
//     ADCSW, ADCS, SBCSW, SBCS, NGCSW, NGCS consumed by subsequent CSET/ADC.
func TestCrossArchARM64MultiplyAccumulateAndCarryFlags(t *testing.T) {
	src := `
TEXT ·smaddl(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	SMADDL R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·umaddl(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	UMADDL R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·smsubl(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	SMSUBL R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·umsubl(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	UMSUBL R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·madd(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	MADD R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·msub(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	MSUB R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·maddw(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	MADDW R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

TEXT ·msubw(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	MSUBW R0, R1, R2, R3
	MOVD R3, ret+24(FP)
	RET

// Carry-in controlled by c+16(FP): CMP $1, R2 sets C=1 iff R2>=1 else C=0.
// Packs (resLow32 << 8) | (N<<3) | (Z<<2) | (V<<1) | C.
TEXT ·adcswFlags(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD cin+16(FP), R2
	CMP $1, R2
	ADCSW R1, R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+24(FP)
	RET

TEXT ·adcsFlags(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD cin+16(FP), R2
	CMP $1, R2
	ADCS R1, R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	AND $0xff, R3, R3
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+24(FP)
	RET

TEXT ·sbcswFlags(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD cin+16(FP), R2
	CMP $1, R2
	SBCSW R1, R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+24(FP)
	RET

TEXT ·sbcsFlags(SB),NOSPLIT,$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD cin+16(FP), R2
	CMP $1, R2
	SBCS R1, R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	AND $0xff, R3, R3
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+24(FP)
	RET

TEXT ·ngcswFlags(SB),NOSPLIT,$0-24
	MOVD a+0(FP), R0
	MOVD cin+8(FP), R2
	CMP $1, R2
	NGCSW R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+16(FP)
	RET

TEXT ·ngcsFlags(SB),NOSPLIT,$0-24
	MOVD a+0(FP), R0
	MOVD cin+8(FP), R2
	CMP $1, R2
	NGCS R0, R3
	CSET HS, R4
	CSET VS, R5
	CSET EQ, R6
	CSET MI, R7
	AND $0xff, R3, R3
	LSL $8, R3, R8
	ORR R4, R8, R8
	ORR R5<<1, R8, R8
	ORR R6<<2, R8, R8
	ORR R7<<3, R8, R8
	MOVD R8, ret+16(FP)
	RET

// Constant-input oracle wrappers verified on every host via opt -O2.
TEXT ·constSMADDL(SB),NOSPLIT,$0-8
	MOVD $2, R0
	MOVD $3, R1
	MOVD $5, R2
	SMADDL R0, R1, R2, R3
	MOVD R3, ret+0(FP)
	RET

TEXT ·constADCSWCarry(SB),NOSPLIT,$0-8
	MOVD $1, R2
	CMP $1, R2
	MOVW $0, R0
	MOVW $0xffffffff, R1
	ADCSW R1, R0, R3
	CSET HS, R4
	MOVD R4, ret+0(FP)
	RET
`
	file, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("Parse arm64 failed: %v", err)
	}
	sig3 := func(name string) FuncSig {
		return FuncSig{
			Name: name,
			Args: []LLVMType{I64, I64, I64},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				},
				Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0, Field: -1}},
			},
		}
	}
	sig2 := func(name string) FuncSig {
		return FuncSig{
			Name: name,
			Args: []LLVMType{I64, I64},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			},
		}
	}
	sig0 := func(name string) FuncSig {
		return FuncSig{
			Name:  name,
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
		}
	}
	triple := "aarch64-unknown-linux-gnu"
	if runtime.GOOS == "darwin" {
		triple = "arm64-apple-darwin"
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"smaddl":          sig3("smaddl"),
			"umaddl":          sig3("umaddl"),
			"smsubl":          sig3("smsubl"),
			"umsubl":          sig3("umsubl"),
			"madd":            sig3("madd"),
			"msub":            sig3("msub"),
			"maddw":           sig3("maddw"),
			"msubw":           sig3("msubw"),
			"adcswFlags":      sig3("adcswFlags"),
			"adcsFlags":       sig3("adcsFlags"),
			"sbcswFlags":      sig3("sbcswFlags"),
			"sbcsFlags":       sig3("sbcsFlags"),
			"ngcswFlags":      sig2("ngcswFlags"),
			"ngcsFlags":       sig2("ngcsFlags"),
			"constSMADDL":     sig0("constSMADDL"),
			"constADCSWCarry": sig0("constADCSWCarry"),
		},
	})
	if err != nil {
		t.Fatalf("Translate arm64 failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "aarch64-unknown-linux-gnu")
	verifyLLVMWithTargetLLC(t, ll, "arm64-apple-darwin")

	// Verify constant-folded exact answers on every host.
	optIR := runOptO2(t, ll)
	if body := extractLLVMFuncBody(t, optIR, "constSMADDL"); !strings.Contains(body, "ret i64 13") {
		t.Fatalf("constSMADDL expected ret i64 13, got:\n%s", body)
	}
	if body := extractLLVMFuncBody(t, optIR, "constADCSWCarry"); !strings.Contains(body, "ret i64 1") {
		t.Fatalf("constADCSWCarry expected ret i64 1, got:\n%s", body)
	}

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
extern uint64_t smaddl(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t umaddl(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t smsubl(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t umsubl(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t madd(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t msub(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t maddw(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t msubw(uint64_t a, uint64_t b, uint64_t c);
extern uint64_t adcswFlags(uint64_t a, uint64_t b, uint64_t cin);
extern uint64_t adcsFlags(uint64_t a, uint64_t b, uint64_t cin);
extern uint64_t sbcswFlags(uint64_t a, uint64_t b, uint64_t cin);
extern uint64_t sbcsFlags(uint64_t a, uint64_t b, uint64_t cin);
extern uint64_t ngcswFlags(uint64_t a, uint64_t cin);
extern uint64_t ngcsFlags(uint64_t a, uint64_t cin);

static int fail = 0;
static void check(const char *name, uint64_t got, uint64_t want) {
	if (got != want) {
		fprintf(stderr, "FAIL %s: got=0x%llx want=0x%llx\n", name, (unsigned long long)got, (unsigned long long)want);
		fail = 1;
	}
}

int main(void) {
	// 8 multiply-accumulate ops x 2 asymmetric input triples each = 16 checks.
	check("smaddl(2,3,5)", smaddl(2, 3, 5), 13ULL);
	check("smaddl(-3,10,7)", smaddl((uint64_t)-3LL, 10, 7), (uint64_t)-11LL);
	check("umaddl(2,3,5)", umaddl(2, 3, 5), 13ULL);
	check("umaddl(0xffffffff,10,2)", umaddl(0xffffffffULL, 10, 2), 10ULL + 0xffffffffULL * 2ULL);
	check("smsubl(2,3,5)", smsubl(2, 3, 5), (uint64_t)-7LL);
	check("smsubl(-3,10,7)", smsubl((uint64_t)-3LL, 10, 7), 31ULL);
	check("umsubl(2,3,5)", umsubl(2, 3, 5), (uint64_t)-7LL);
	check("umsubl(0xffffffff,10,2)", umsubl(0xffffffffULL, 10, 2), 10ULL - 0xffffffffULL * 2ULL);
	check("madd(2,3,5)", madd(2, 3, 5), 13ULL);
	check("madd(11,17,23)", madd(11, 17, 23), 17ULL + 11ULL * 23ULL);
	check("msub(2,3,5)", msub(2, 3, 5), (uint64_t)-7LL);
	check("msub(11,100,7)", msub(11, 100, 7), 23ULL);
	check("maddw(2,3,5)", maddw(2, 3, 5), 13ULL);
	check("maddw(11,17,23)", maddw(11, 17, 23), 270ULL);
	check("msubw(2,3,5)", msubw(2, 3, 5), 0xfffffff9ULL);
	check("msubw(11,100,7)", msubw(11, 100, 7), 23ULL);

	// Flags packed as (res<<8) | (N<<3) | (Z<<2) | (V<<1) | C
	// ADCSW: 0 + 0xffffffff + C=1 => res=0, N=0, Z=1, V=0, C=1 => 0x005
	check("adcsw(0,0xffffffff,C=1)", adcswFlags(0, 0xffffffffULL, 1), (0ULL << 8) | 0x5ULL);
	// ADCSW: 0 + 0xffffffff + C=0 => res=0xffffffff, N=1, Z=0, V=0, C=0 => 0x8
	check("adcsw(0,0xffffffff,C=0)", adcswFlags(0, 0xffffffffULL, 0), (0xffffffffULL << 8) | 0x8ULL);
	// ADCSW: 0x7fffffff + 0 + C=1 => res=0x80000000, N=1, Z=0, V=1, C=0 => 0xa
	check("adcsw(0x7fffffff,0,C=1)", adcswFlags(0x7fffffffULL, 0, 1), (0x80000000ULL << 8) | 0xaULL);
	// ADCS: 0 + ~0 + C=1 => res=0, Z=1, C=1 => 0x5
	check("adcs(0,~0,C=1)", adcsFlags(0, ~0ULL, 1), (0ULL << 8) | 0x5ULL);
	// ADCS: 0x7fffffffffffffff + 0 + C=1 => res=0x8000..00 (low8=0), N=1, V=1, C=0 => 0xa
	check("adcs(INT64_MAX,0,C=1)", adcsFlags(0x7fffffffffffffffULL, 0, 1), (0ULL << 8) | 0xaULL);
	// SBCSW: 5 - 5 - borrow(C=0) => res=0xffffffff, N=1, Z=0, V=0, C=0 => 0x8
	check("sbcsw(5,5,C=0)", sbcswFlags(5, 5, 0), (0xffffffffULL << 8) | 0x8ULL);
	// SBCSW: 5 - 5 - 0(C=1) => res=0, N=0, Z=1, V=0, C=1 => 0x5
	check("sbcsw(5,5,C=1)", sbcswFlags(5, 5, 1), (0ULL << 8) | 0x5ULL);
	// SBCSW: 0x80000000 - 0 - borrow(C=0) => res=0x7fffffff, N=0, Z=0, V=1, C=1 => 0x3
	check("sbcsw(INT32_MIN,0,C=0)", sbcswFlags(0x80000000ULL, 0, 0), (0x7fffffffULL << 8) | 0x3ULL);
	// SBCS: 5 - 5 - borrow(C=0) => res=-1 (low8=0xff), N=1, C=0 => 0x8
	check("sbcs(5,5,C=0)", sbcsFlags(5, 5, 0), (0xffULL << 8) | 0x8ULL);
	// SBCS: 5 - 5 - 0(C=1) => res=0, Z=1, C=1 => 0x5
	check("sbcs(5,5,C=1)", sbcsFlags(5, 5, 1), (0ULL << 8) | 0x5ULL);
	// NGCSW: 0 - 0 - borrow(C=0) => res=0xffffffff, N=1, C=0 => 0x8
	check("ngcsw(0,C=0)", ngcswFlags(0, 0), (0xffffffffULL << 8) | 0x8ULL);
	// NGCSW: 0 - 0 - 0(C=1) => res=0, Z=1, C=1 => 0x5
	check("ngcsw(0,C=1)", ngcswFlags(0, 1), (0ULL << 8) | 0x5ULL);
	// NGCS: 0 - 0 - borrow(C=0) => res=-1 (low8=0xff), N=1, C=0 => 0x8
	check("ngcs(0,C=0)", ngcsFlags(0, 0), (0xffULL << 8) | 0x8ULL);
	// NGCS: 0 - 0 - 0(C=1) => res=0, Z=1, C=1 => 0x5
	check("ngcs(0,C=1)", ngcsFlags(0, 1), (0ULL << 8) | 0x5ULL);

	return fail;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "arm64_cross_arch_madd_adc", triple, ll, mainC, nil)
}

// TestCrossArchARMv7ShiftCarryFlags verifies that ARMv7 SLL.S, SRL.S, SRA.S,
// and shifted-register .S operations (MOVW.S / AND.S / TST) write the exact
// architectural shifter carry-out bit to C (and preserve C when shift == 0).
func TestCrossArchARMv7ShiftCarryFlags(t *testing.T) {
	src := `
// SLL.S $1 on 0x80000000 shifts out 1 => C=1 (MOVW.CS sets R0=1)
TEXT ·sllCarry1(SB),NOSPLIT,$0-4
	MOVW $0x80000000, R1
	SLL.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SLL.S $1 on 0x40000000 shifts out 0 => C=0
TEXT ·sllCarry0(SB),NOSPLIT,$0-4
	MOVW $0x40000000, R1
	MOVW $1, R3
	CMP $1, R3
	SLL.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SRL.S $1 on 1 shifts out 1 => C=1
TEXT ·srlCarry1(SB),NOSPLIT,$0-4
	MOVW $1, R1
	SRL.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SRL.S $1 on 2 shifts out 0 => C=0
TEXT ·srlCarry0(SB),NOSPLIT,$0-4
	MOVW $2, R1
	MOVW $1, R3
	CMP $1, R3
	SRL.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SRA.S $1 on -1 shifts out 1 => C=1
TEXT ·sraCarry1(SB),NOSPLIT,$0-4
	MOVW $-1, R1
	SRA.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SRA.S $1 on -2 shifts out 0 => C=0
TEXT ·sraCarry0(SB),NOSPLIT,$0-4
	MOVW $-2, R1
	MOVW $1, R3
	CMP $1, R3
	SRA.S $1, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Shift by 0 preserves prior C=1
TEXT ·sllZeroPreservesC(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R1
	MOVW $0, R4
	SLL.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SLL.S by 32 uses bit 0 of src; by 33 sets C=0
TEXT ·sll32Bit0(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $1, R1
	MOVW $32, R4
	SLL.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·sll33Zero(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $-1, R1
	MOVW $33, R4
	SLL.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// SRL.S by 32 uses bit 31; SRA.S by 33 uses sign bit 31
TEXT ·srl32Bit31(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0x80000000, R1
	MOVW $32, R4
	SRL.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·sra33Sign(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0x80000000, R1
	MOVW $33, R4
	SRA.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Shifted-register MOVW.S and AND.S also update C from the barrel shifter.
TEXT ·movwShiftCarry1(SB),NOSPLIT,$0-4
	MOVW $0x80000000, R1
	MOVW.S R1<<1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·andShiftCarry1(SB),NOSPLIT,$0-4
	MOVW $1, R1
	MOVW $-1, R2
	AND.S R1>>1, R2, R3
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·tstRotateCarry1(SB),NOSPLIT,$0-4
	MOVW $1, R1
	MOVW $-1, R2
	TST R1@>1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mvnShiftCarry1(SB),NOSPLIT,$0-4
	MOVW $0x80000000, R1
	MVN.S R1<<1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Immediate shift edge cases matching Go cmd/internal/obj/arm/asm5.go encoding
// (imm & 31, distinct from register shifts Rs & 255):
//   - SLL.S $32 (entry C=0, R1=-1) => encoded as MOV.S R1, R2 => res=-1, C=0!
//   - SLL.S $33 (entry C=0, R1=-1) => encoded as LSL.S $1 => res=-2, C=1!
//   - SLL.S $64 (entry C=0, R1=-1) => encoded as MOV.S R1, R2 => res=-1, C=0!
//   - SRL.S $32 (entry C=0, R1=-1) => encoded as LSR.S $32 => res=0, C=1!
//   - SRL.S $33 (entry C=0, R1=-1) => encoded as LSR.S $1 => res=0x7fffffff, C=1!
//   - SRA.S $32 (entry C=0, R1=-1) => encoded as ASR.S $32 => res=-1, C=1!
//   - SRA.S $33 (entry C=1, R1=-2) => encoded as ASR.S $1 => res=-1, C=0!
TEXT ·immSll32PreservesC0(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SLL.S $32, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSll32Value(SB),NOSPLIT,$0-4
	MOVW $-1, R1
	SLL.S $32, R1, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·immSll33SetsC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SLL.S $33, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSll64PreservesC0(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SLL.S $64, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSrl32SetsC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SRL.S $32, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSrl33ValueAndC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SRL.S $33, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	ORR R2, R0, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSra32SetsC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $-1, R1
	SRA.S $32, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSra33ClearsC(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $-2, R1
	SRA.S $33, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Rotated-immediate logical ops (ARMv7 ARMExpandImm_C):
// Entry C=1 + $0x40000000 (rot=1, bit31=0) => C=0 across all 6 ops.
TEXT ·immTstRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	TST $0x40000000, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immTeqRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	TEQ $0x40000000, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immAndRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	AND.S $0x40000000, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immOrrRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	ORR.S $0x40000000, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immEorRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	EOR.S $0x40000000, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immBicRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	BIC.S $0x40000000, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Controls:
//   - TST $1 (rot=0): preserves C=1
//   - TST $0x80000000 (rot=1, bit31=1): sets C=1 from C=0
//   - TST $0x12345678 (literal pool via R11): preserves C=1
//   - AND.S $~0x40000000 (Go rewrites to BIC.S $0x40000000, rot=1, bit31=0): sets C=0 from C=1
//   - AND.S $-1 (Go rewrites to BIC.S $0, rot=0): preserves C=1
//   - BIC.S $~0x40000000 (MVN R11; BIC.S R11): preserves C=1
TEXT ·immTstUnrotPreservesC1(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	TST $1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immTstRot1SetsC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0, R2
	TST $0x80000000, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immTstPoolPreservesC1(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	TST $0x12345678, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immAndNconRot0(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	AND.S $-1073741825, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immAndNconUnrotPreservesC1(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	AND.S $-1, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immBicNconPreservesC1(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $0, R2
	BIC.S $-1073741825, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immSll0PreservesC1(SB),NOSPLIT,$0-4
	MOVW $1, R3
	CMP $1, R3
	MOVW $-1, R1
	SLL.S $0, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·immAndNconRot1SetsC1(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0, R2
	AND.S $2147483647, R2, R4
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Conditional compare (TST/TEQ/CMP/CMN), conditional carry-chain (ADC/SBC/RSC),
// and conditional VFP compare (CMPF/CMPD) must evaluate their condition predicate
// once before modifying any flag, and preserve all 4 NZCV flags when false.
// Each helper packs NZCV into bit3=N(8), bit2=Z(4), bit1=C(2), bit0=V(1).
TEXT ·condTstEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	TST.EQ $0x40000000, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condTstNeTrueClearsCAndSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	TST.NE $0x40000000, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condTeqEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	TEQ.EQ $0x40000000, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condTeqNeTrueClearsC(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	TEQ.NE $0x40000000, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condTstShiftEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVW $0, R1
	TST.EQ R1<<1, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmpEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	CMP.EQ $5, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmpNeTrueUpdatesAllNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	CMP.NE $5, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmnEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	CMN.EQ $0x7fffffff, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmnNeTrueUpdatesAllNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	CMN.NE $0x7fffffff, R2
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condAdcEqSTakenUpdatesCarryAtomically(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $0, R3
	MOVW $1, R2
	MOVW $-1, R4
	ADC.EQ.S R4, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condSbcEqSTakenUpdatesCarryAtomically(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0, R2
	TST $0, R2
	MOVW $1, R2
	SBC.EQ.S $1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condRscEqSTakenUpdatesCarryAtomically(SB),NOSPLIT,$0-4
	MOVW $0, R3
	CMP $1, R3
	MOVW $0, R2
	TST $0, R2
	MOVW $1, R2
	RSC.EQ.S $1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmpfEqFalsePreservesNZCV(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVF $2.0, F0
	MOVF $1.0, F1
	CMPF.EQ F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Plan 9 2-op CMPD/CMPF src, dst encodes VCMPE dst, src (compare Args[1] vs Args[0]).
// F0=1.0, F1=2.0 => CMPD.PL F0, F1 compares F1(2.0) vs F0(1.0) => GT => C=1 (2).
TEXT ·condCmpdPlGt(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVD $1.0, F0
	MOVD $2.0, F1
	CMPD.PL F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

// F0=2.0, F1=1.0 => CMPD.PL F0, F1 compares F1(1.0) vs F0(2.0) => LT => N flips 0->1
// and C flips 1->0 atomically under a single evaluation of PL => N=1 (8).
TEXT ·condCmpdPlLtUpdatesAtomically(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVD $2.0, F0
	MOVD $1.0, F1
	CMPD.PL F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmpdPlEq(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVD $2.0, F0
	MOVD $2.0, F1
	CMPD.PL F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·condCmpdPlNaN(SB),NOSPLIT,$0-4
	MOVW $1, R2
	CMP $0, R2
	MOVD $0.0, F0
	DIVD F0, F0
	MOVD $1.0, F1
	CMPD.PL F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·cmpfGt(SB),NOSPLIT,$0-4
	MOVF $1.0, F0
	MOVF $2.0, F1
	CMPF F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·cmpfLt(SB),NOSPLIT,$0-4
	MOVF $2.0, F0
	MOVF $1.0, F1
	CMPF F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·cmpfEq(SB),NOSPLIT,$0-4
	MOVF $2.0, F0
	MOVF $2.0, F1
	CMPF F0, F1
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

// 1-operand CMPF/CMPD compares the single operand against 0.0.
TEXT ·cmpfZeroPos(SB),NOSPLIT,$0-4
	MOVF $2.0, F0
	CMPF F0
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·cmpdZeroNeg(SB),NOSPLIT,$0-4
	MOVD $-2.0, F0
	CMPD F0
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·cmpdZeroEq(SB),NOSPLIT,$0-4
	MOVD $0.0, F0
	CMPD F0
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Positive partial-flag controls: explicitly establishing C=1 or C=0 before TST $1, R1.
TEXT ·partialTstPreservesExplicitC1(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	TST $1, R1
	CMP.CS $1, R1
	MOVW $0, R0
	MOVW.EQ $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·partialTstPreservesExplicitC0(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $2, R1
	TST $1, R1
	CMP.CS $1, R1
	MOVW $0, R0
	MOVW.EQ $1, R0
	MOVW R0, ret+0(FP)
	RET

// MOVW CPSR, Rd observes tracked NZCV flags in bits [31:28].
TEXT ·cpsrReadCarry1(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $1, R1
	MOVW CPSR, R2
	SRL $29, R2
	AND $1, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·cpsrReadCarry0(SB),NOSPLIT,$0-4
	MOVW $0, R1
	CMP $1, R1
	MOVW CPSR, R2
	SRL $29, R2
	AND $1, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·cpsrReadNZCVSubGt(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW CPSR, R2
	SRL $28, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·cpsrReadNZCVSubLt(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $5, R1
	MOVW CPSR, R2
	SRL $28, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·cpsrReadNZCVAddOv(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMN $0x7fffffff, R1
	MOVW CPSR, R2
	SRL $28, R2
	MOVW R2, ret+0(FP)
	RET

TEXT ·cpsrRoundtripCarry(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $1, R1
	MOVW CPSR, R2
	MOVW $0, R3
	CMP $1, R3
	MOVW R2, CPSR
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Multiply .S updates N/Z and preserves C/V (and MULAL is signed SMLAL while MULALU is unsigned UMLAL).
TEXT ·mulSZeroSetsZPreservesC(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MUL.S R1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulSNegSetsNPreservesC(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $-3, R2
	MOVW $5, R3
	MUL.S R2, R3, R4
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·muluSZeroSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MULU.S R1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulaSZeroSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $3, R2
	MOVW $2, R3
	MOVW $-6, R4
	MULA.S R2, R3, R4, R5
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulaSNegSetsN(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $3, R2
	MOVW $-4, R3
	MOVW $2, R4
	MULA.S R2, R3, R4, R5
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mullSZeroSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MULL.S R1, R2, (R3, R4)
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mullSNegSetsN(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $-2, R2
	MOVW $3, R3
	MULL.S R2, R3, (R4, R5)
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulluSZeroSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MULLU.S R1, R2, (R3, R4)
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulluSHiBitSetsN(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0xffffffff, R2
	MOVW $0xffffffff, R3
	MULLU.S R2, R3, (R4, R5)
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulalSSignedNeg(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $-2, R2
	MOVW $3, R3
	MOVW $0, R4
	MOVW $0, R5
	MULAL.S R2, R3, (R4, R5)
	// Signed -2 * 3 + 0 = -6 => hi(R4) = -1, lo(R5) = -6, N=1, Z=0, C=1(preserved).
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	ADD R4, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulalSZeroSetsZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $-2, R2
	MOVW $3, R3
	MOVW $0, R4
	MOVW $6, R5
	MULAL.S R2, R3, (R4, R5)
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulaluSUnsignedPos(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $-2, R2
	MOVW $3, R3
	MOVW $0, R4
	MOVW $0, R5
	MULALU.S R2, R3, (R4, R5)
	// Unsigned 0xfffffffe * 3 + 0 = 0x2fffffffa => hi(R4) = 2, N=0, Z=0, C=1(preserved).
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	ADD R4, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulEqSFalsePreservesFlags(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MUL.EQ.S R1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

TEXT ·mulNeSTrueUpdatesNZ(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R2
	MUL.NE.S R1, R2, R3
	MOVW $0, R0
	ORR.MI $8, R0
	ORR.EQ $4, R0
	ORR.CS $2, R0
	ORR.VS $1, R0
	MOVW R0, ret+0(FP)
	RET

// Unreachable dead blocks after unconditional branches/RET must not cause false
// flag-definedness rejections.
TEXT ·deadBlockAfterUncondBranch(SB),NOSPLIT,$0-4
	MOVW $1, R0
	B done
	MOVW.CS $2, R0
done:
	MOVW R0, ret+0(FP)
	RET

TEXT ·deadLabeledBlockAfterRet(SB),NOSPLIT,$0-4
	MOVW $7, R0
	MOVW R0, ret+0(FP)
	RET
dead:
	MOVW.CS $9, R0
	MOVW R0, ret+0(FP)
	RET

// Runtime-input shift function to verify non-constant armv7 backend codegen
// (explicitly establishes C=0 so shift-by-0 does not depend on caller entry C).
TEXT ·runtimeShiftCarry(SB),NOSPLIT,$0-12
	MOVW $0, R3
	CMP $1, R3
	MOVW x+0(FP), R1
	MOVW n+4(FP), R4
	SLL.S R4, R1, R2
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+8(FP)
	RET
`
	file, err := Parse(ArchARM, src)
	if err != nil {
		t.Fatalf("Parse arm failed: %v", err)
	}
	sig0 := func(name string) FuncSig {
		return FuncSig{
			Name:  name,
			Ret:   I32,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
		}
	}
	wantConst := map[string]int{
		"sllCarry1":                             1,
		"sllCarry0":                             0,
		"srlCarry1":                             1,
		"srlCarry0":                             0,
		"sraCarry1":                             1,
		"sraCarry0":                             0,
		"sllZeroPreservesC":                     1,
		"sll32Bit0":                             1,
		"sll33Zero":                             0,
		"srl32Bit31":                            1,
		"sra33Sign":                             1,
		"movwShiftCarry1":                       1,
		"andShiftCarry1":                        1,
		"tstRotateCarry1":                       1,
		"mvnShiftCarry1":                        1,
		"immSll32PreservesC0":                   0,
		"immSll32Value":                         -1,
		"immSll33SetsC1":                        1,
		"immSll64PreservesC0":                   0,
		"immSrl32SetsC1":                        1,
		"immSrl33ValueAndC1":                    0x7fffffff,
		"immSra32SetsC1":                        1,
		"immSra33ClearsC":                       0,
		"immTstRot0":                            0,
		"immTeqRot0":                            0,
		"immAndRot0":                            0,
		"immOrrRot0":                            0,
		"immEorRot0":                            0,
		"immBicRot0":                            0,
		"immTstUnrotPreservesC1":                1,
		"immTstRot1SetsC1":                      1,
		"immTstPoolPreservesC1":                 1,
		"immAndNconRot0":                        0,
		"immAndNconUnrotPreservesC1":            1,
		"immBicNconPreservesC1":                 1,
		"immSll0PreservesC1":                    1,
		"immAndNconRot1SetsC1":                  1,
		"condTstEqFalsePreservesNZCV":           2,
		"condTstNeTrueClearsCAndSetsZ":          4,
		"condTeqEqFalsePreservesNZCV":           2,
		"condTeqNeTrueClearsC":                  0,
		"condTstShiftEqFalsePreservesNZCV":      2,
		"condCmpEqFalsePreservesNZCV":           2,
		"condCmpNeTrueUpdatesAllNZCV":           8,
		"condCmnEqFalsePreservesNZCV":           2,
		"condCmnNeTrueUpdatesAllNZCV":           9,
		"condAdcEqSTakenUpdatesCarryAtomically": 2,
		"condSbcEqSTakenUpdatesCarryAtomically": 8,
		"condRscEqSTakenUpdatesCarryAtomically": 8,
		"condCmpfEqFalsePreservesNZCV":          2,
		"condCmpdPlGt":                          2,
		"condCmpdPlLtUpdatesAtomically":         8,
		"condCmpdPlEq":                          6,
		"condCmpdPlNaN":                         3,
		"cmpfGt":                                2,
		"cmpfLt":                                8,
		"cmpfEq":                                6,
		"cmpfZeroPos":                           2,
		"cmpdZeroNeg":                           8,
		"cmpdZeroEq":                            6,
		"partialTstPreservesExplicitC1":         1,
		"partialTstPreservesExplicitC0":         0,
		"cpsrReadCarry1":                        1,
		"cpsrReadCarry0":                        0,
		"cpsrReadNZCVSubGt":                     2,
		"cpsrReadNZCVSubLt":                     8,
		"cpsrReadNZCVAddOv":                     9,
		"cpsrRoundtripCarry":                    1,
		"mulSZeroSetsZPreservesC":               6,
		"mulSNegSetsNPreservesC":                10,
		"muluSZeroSetsZ":                        6,
		"mulaSZeroSetsZ":                        6,
		"mulaSNegSetsN":                         10,
		"mullSZeroSetsZ":                        6,
		"mullSNegSetsN":                         10,
		"mulluSZeroSetsZ":                       6,
		"mulluSHiBitSetsN":                      10,
		"mulalSSignedNeg":                       9, // N(8)+C(2)+hi(-1) = 9
		"mulalSZeroSetsZ":                       6,
		"mulaluSUnsignedPos":                    4, // C(2)+hi(2) = 4
		"mulEqSFalsePreservesFlags":             2,
		"mulNeSTrueUpdatesNZ":                   6,
		"deadBlockAfterUncondBranch":            1,
		"deadLabeledBlockAfterRet":              7,
	}
	sigs := map[string]FuncSig{
		"runtimeShiftCarry": {
			Name: "runtimeShiftCarry",
			Args: []LLVMType{I32, I32},
			Ret:  I32,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I32, Index: 0, Field: -1},
					{Offset: 4, Type: I32, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
	}
	for name := range wantConst {
		sigs[name] = sig0(name)
	}
	ll, err := Translate(file, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         sigs,
	})
	if err != nil {
		t.Fatalf("Translate arm failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "armv7-unknown-linux-gnueabihf")

	optIR := runOptO2(t, ll)
	for name, want := range wantConst {
		body := extractLLVMFuncBody(t, optIR, name)
		expectedRet := fmt.Sprintf("ret i32 %d", want)
		if !strings.Contains(body, expectedRet) {
			t.Errorf("ARMv7 %s: expected %q after -O2, got:\n%s", name, expectedRet, body)
		}
	}

	// Per-flag definedness enforcement: partial flag writes (N/Z only, or N/Z/C
	// without V) and conditional flag writes must NOT mark unmodified entry flags
	// as defined; reading any undefined entry flag must fail with ErrProbeNeedsContext.
	t.Run("PartialFlagDefinedness", func(t *testing.T) {
		rejectCases := []struct {
			name string
			body string
		}{
			{
				name: "TST_unrot_then_CMP_CS",
				body: "MOVW $1, R1\nTST $1, R1\nCMP.CS $1, R1\nMOVW $0, R0\nMOVW.EQ $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_MOVW_CS",
				body: "MOVW $1, R1\nTST $1, R1\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_MOVW_HI",
				body: "MOVW $1, R1\nTST $1, R1\nMOVW $0, R0\nMOVW.HI $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_MOVW_VS",
				body: "MOVW $1, R1\nTST $1, R1\nMOVW $0, R0\nMOVW.VS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_MOVW_LT",
				body: "MOVW $1, R1\nTST $1, R1\nMOVW $0, R0\nMOVW.LT $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_rot_defines_C_not_V",
				body: "MOVW $1, R1\nTST $0x40000000, R1\nMOVW $0, R0\nMOVW.VS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "conditional_CMP_EQ_does_not_define_C",
				body: "MOVW $1, R1\nTST $1, R1\nCMP.EQ $0, R1\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_ADC_reads_undef_C",
				body: "MOVW $1, R1\nTST $1, R1\nADC $0, R1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_SBC_reads_undef_C",
				body: "MOVW $1, R1\nTST $1, R1\nSBC $0, R1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_unrot_then_RSC_reads_undef_C",
				body: "MOVW $1, R1\nTST $1, R1\nRSC $0, R1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "SLL_S_imm0_does_not_define_C",
				body: "MOVW $-1, R1\nSLL.S $0, R1, R2\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "SLL_S_imm32_does_not_define_C",
				body: "MOVW $-1, R1\nSLL.S $32, R1, R2\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "SLL_S_reg_may_be_zero_does_not_define_C",
				body: "MOVW $1, R1\nMOVW $4, R4\nSLL.S R4, R1, R2\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "CFG_join_missing_C_on_one_path",
				body: "MOVW $1, R1\nTST $1, R1\nBEQ join\nCMP $0, R1\njoin:\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "TST_partial_then_MOVW_CPSR",
				body: "MOVW $1, R1\nTST $1, R1\nMOVW CPSR, R2\nMOVW R2, ret+0(FP)\nRET\n",
			},
			{
				name: "MUL_S_does_not_define_C",
				body: "MOVW $2, R1\nMOVW $3, R2\nMUL.S R1, R2, R3\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "MULA_S_does_not_define_C",
				body: "MOVW $2, R1\nMOVW $3, R2\nMOVW $1, R3\nMULA.S R1, R2, R3, R4\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "MULL_S_does_not_define_C",
				body: "MOVW $2, R1\nMOVW $3, R2\nMULL.S R1, R2, (R3, R4)\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "MULAL_S_does_not_define_C",
				body: "MOVW $2, R1\nMOVW $3, R2\nMOVW $0, R3\nMOVW $0, R4\nMULAL.S R1, R2, (R3, R4)\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
			{
				name: "branch_then_MOVW_CPSR_without_all_flags",
				body: "B next\nnext:\nMOVW CPSR, R0\nMOVW R0, ret+0(FP)\nRET\n",
			},
		}
		for _, tc := range rejectCases {
			t.Run("Reject_"+tc.name, func(t *testing.T) {
				f, err := Parse(ArchARM, "TEXT ·f(SB),NOSPLIT,$0-4\n"+tc.body)
				if err != nil {
					t.Fatalf("Parse failed: %v", err)
				}
				_, err = Translate(f, Options{
					TargetTriple: "armv7-unknown-linux-gnueabihf",
					Goarch:       "arm",
					ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
					Sigs:         map[string]FuncSig{"f": sig0("f")},
				})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("expected ErrProbeNeedsContext for %s, got: %v", tc.name, err)
				}
			})
		}

		acceptCases := []struct {
			name string
			body string
			want int
		}{
			{
				name: "TST_unrot_allows_EQ",
				body: "MOVW $0, R1\nTST $1, R1\nMOVW $0, R0\nMOVW.EQ $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
				want: 1,
			},
			{
				name: "TST_unrot_allows_MI",
				body: "MOVW $-1, R1\nTST $0x80000000, R1\nMOVW $0, R0\nMOVW.MI $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
				want: 1,
			},
			{
				name: "TST_rot_defines_C_allows_CS",
				body: "MOVW $0, R1\nTST $0x80000000, R1\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
				want: 1,
			},
			{
				name: "SRL_S_imm32_defines_C_allows_CS",
				body: "MOVW $-1, R1\nSRL.S $32, R1, R2\nMOVW $0, R0\nMOVW.CS $1, R0\nMOVW R0, ret+0(FP)\nRET\n",
				want: 1,
			},
		}
		for _, tc := range acceptCases {
			t.Run("Accept_"+tc.name, func(t *testing.T) {
				f, err := Parse(ArchARM, "TEXT ·f(SB),NOSPLIT,$0-4\n"+tc.body)
				if err != nil {
					t.Fatalf("Parse failed: %v", err)
				}
				llCase, err := Translate(f, Options{
					TargetTriple: "armv7-unknown-linux-gnueabihf",
					Goarch:       "arm",
					ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
					Sigs:         map[string]FuncSig{"f": sig0("f")},
				})
				if err != nil {
					t.Fatalf("Translate(%s) unexpected error: %v", tc.name, err)
				}
				optCase := runOptO2(t, llCase)
				body := extractLLVMFuncBody(t, optCase, "f")
				if wantRet := fmt.Sprintf("ret i32 %d", tc.want); !strings.Contains(body, wantRet) {
					t.Fatalf("Accept_%s: expected %q after -O2, got:\n%s", tc.name, wantRet, body)
				}
			})
		}
	})

	// Cross-CALL flag handling: general calls clobber hardware flags and do not
	// propagate LLVM flag slots back to the caller, so consuming flags across a
	// general CALL must be rejected with ErrProbeNeedsContext. Verified Linux/ARM
	// __kuser_cmpxchg trampolines (MOVW $0xffff0fc0, R15) lower to atomic cmpxchg
	// defining C only.
	t.Run("CrossCallFlags", func(t *testing.T) {
		rejectCallCases := []struct {
			name string
			src  string
			sigs map[string]FuncSig
		}{
			{
				name: "callee_sets_C_caller_reads_CS",
				src: `
TEXT ·setC(SB),NOSPLIT,$0-0
	MOVW $1, R1
	CMP $0, R1
	RET

TEXT ·caller(SB),NOSPLIT,$0-4
	BL ·setC(SB)
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET
`,
				sigs: map[string]FuncSig{
					"setC":   {Name: "setC", Ret: Void},
					"caller": sig0("caller"),
				},
			},
			{
				name: "caller_sets_C_call_clobbers_C",
				src: `
TEXT ·noop(SB),NOSPLIT,$0-0
	RET

TEXT ·caller(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	BL ·noop(SB)
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET
`,
				sigs: map[string]FuncSig{
					"noop":   {Name: "noop", Ret: Void},
					"caller": sig0("caller"),
				},
			},
			{
				name: "conditional_call_clobbers_C",
				src: `
TEXT ·noop(SB),NOSPLIT,$0-0
	RET

TEXT ·caller(SB),NOSPLIT,$0-4
	MOVW $1, R1
	CMP $0, R1
	BL.NE ·noop(SB)
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET
`,
				sigs: map[string]FuncSig{
					"noop":   {Name: "noop", Ret: Void},
					"caller": sig0("caller"),
				},
			},
			{
				name: "call_then_MOVW_CPSR",
				src: `
TEXT ·setC(SB),NOSPLIT,$0-0
	MOVW $1, R1
	CMP $0, R1
	RET

TEXT ·caller(SB),NOSPLIT,$0-4
	BL ·setC(SB)
	MOVW CPSR, R0
	MOVW R0, ret+0(FP)
	RET
`,
				sigs: map[string]FuncSig{
					"setC":   {Name: "setC", Ret: Void},
					"caller": sig0("caller"),
				},
			},
			{
				name: "kuser_cas_defines_only_C_not_Z",
				src: `
TEXT cas<>(SB),NOSPLIT,$0
	MOVW $0xffff0fc0, R15

TEXT ·caller(SB),NOSPLIT,$0-4
	BL cas<>(SB)
	MOVW $0, R0
	MOVW.EQ $1, R0
	MOVW R0, ret+0(FP)
	RET
`,
				sigs: map[string]FuncSig{
					"cas<>":  {Name: "cas<>", Ret: Void},
					"caller": sig0("caller"),
				},
			},
		}
		for _, tc := range rejectCallCases {
			t.Run("Reject_"+tc.name, func(t *testing.T) {
				f, err := Parse(ArchARM, tc.src)
				if err != nil {
					t.Fatalf("Parse failed: %v", err)
				}
				_, err = Translate(f, Options{
					TargetTriple: "armv7-unknown-linux-gnueabihf",
					Goarch:       "arm",
					ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
					Sigs:         tc.sigs,
				})
				if !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("expected ErrProbeNeedsContext for %s, got: %v", tc.name, err)
				}
			})
		}

		// Positive control: re-establishing flags after BL is accepted.
		t.Run("Accept_reestablish_flags_after_call", func(t *testing.T) {
			f, err := Parse(ArchARM, `
TEXT ·setC(SB),NOSPLIT,$0-0
	RET

TEXT ·caller(SB),NOSPLIT,$0-4
	BL ·setC(SB)
	MOVW $1, R1
	CMP $0, R1
	MOVW $0, R0
	MOVW.CS $1, R0
	MOVW R0, ret+0(FP)
	RET
`)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			llCall, err := Translate(f, Options{
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Goarch:       "arm",
				ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
				Sigs: map[string]FuncSig{
					"setC":   {Name: "setC", Ret: Void},
					"caller": sig0("caller"),
				},
			})
			if err != nil {
				t.Fatalf("Translate failed: %v", err)
			}
			if strings.Contains(llCall, "mrs $0, apsr") {
				t.Fatalf("unexpected mrs $0, apsr in:\n%s", llCall)
			}
			verifyLLVMWithTargetLLC(t, llCall, "armv7-unknown-linux-gnueabihf")
			optCall := runOptO2(t, llCall)
			body := extractLLVMFuncBody(t, optCall, "caller")
			if !strings.Contains(body, "ret i32 1") {
				t.Fatalf("expected ret i32 1 after -O2, got:\n%s", body)
			}
		})

		// Positive control: verified Linux/ARM kuser __kuser_cmpxchg lowers to cmpxchg and defines C.
		t.Run("Accept_kuser_cas_cmpxchg_sets_C", func(t *testing.T) {
			f, err := Parse(ArchARM, `
TEXT cas<>(SB),NOSPLIT,$0
	MOVW $0xffff0fc0, R15

TEXT ·armcas(SB),NOSPLIT,$0-16
	MOVW valptr+0(FP), R2
	MOVW old+4(FP), R0
	MOVW new+8(FP), R1
	BL cas<>(SB)
	BCC ret0
	MOVW $1, R0
	MOVW R0, ret+12(FP)
	RET
ret0:
	MOVW $0, R0
	MOVW R0, ret+12(FP)
	RET
`)
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			llCAS, err := Translate(f, Options{
				TargetTriple: "armv7-unknown-linux-gnueabihf",
				Goarch:       "arm",
				ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
				Sigs: map[string]FuncSig{
					"cas<>": {Name: "cas<>", Ret: Void},
					"armcas": {
						Name: "armcas",
						Args: []LLVMType{Ptr, I32, I32},
						Ret:  I32,
						Frame: FrameLayout{
							Params: []FrameSlot{
								{Offset: 0, Type: Ptr, Index: 0, Field: -1},
								{Offset: 4, Type: I32, Index: 1, Field: -1},
								{Offset: 8, Type: I32, Index: 2, Field: -1},
							},
							Results: []FrameSlot{{Offset: 12, Type: I32, Index: 0, Field: -1}},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("Translate kuser CAS failed: %v", err)
			}
			if !strings.Contains(llCAS, "cmpxchg ptr") {
				t.Fatalf("expected atomic cmpxchg lowering for kuser CAS, got:\n%s", llCAS)
			}
			if strings.Contains(llCAS, "mrs $0, apsr") {
				t.Fatalf("unexpected mrs $0, apsr in kuser CAS IR:\n%s", llCAS)
			}
			verifyLLVMWithTargetLLC(t, llCAS, "armv7-unknown-linux-gnueabihf")
		})
	})
}

// TestCrossArchX86DivTrapsAndResults verifies 386 and amd64 DIV/IDIV across
// all widths (B/W/L/Q):
//   - Normal quotients and remainders match architecture.
//   - Divide-by-zero, signed wide INT_MIN/-1, and quotient overflow into the
//     narrow destination width trap with architectural #DE (never silently
//     substituting divisor=1 or truncating overflowing quotients), even when
//     the quotient/remainder is dead/overwritten and under LLVM -O2.
func TestCrossArchX86DivTrapsAndResults(t *testing.T) {
	src386 := `
TEXT ·divbOk(SB),NOSPLIT,$0-4
	MOVL $43, AX
	MOVL $5, BX
	DIVB BL
	MOVBLZX AL, CX
	MOVBLZX AH, DX
	SHLL $8, DX
	ORL DX, CX
	MOVL CX, ret+0(FP)
	RET

TEXT ·divbOverflow(SB),NOSPLIT,$0-4
	MOVL $256, AX
	MOVL $1, BX
	DIVB BL
	MOVBLZX AL, AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·divbZero(SB),NOSPLIT,$0-4
	MOVL $7, AX
	MOVL $0, BX
	DIVB BL
	MOVBLZX AL, AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·divbOverflowDead(SB),NOSPLIT,$0-4
	MOVL $256, AX
	MOVL $1, BX
	DIVB BL
	MOVL $99, ret+0(FP)
	RET

TEXT ·idivbOverflow(SB),NOSPLIT,$0-4
	MOVL $128, AX
	MOVL $1, BX
	IDIVB BL
	MOVBLSX AL, AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·idivbWideMinNeg1(SB),NOSPLIT,$0-4
	MOVL $0x8000, AX
	MOVL $0xff, BX
	IDIVB BL
	MOVBLSX AL, AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·divwOverflow(SB),NOSPLIT,$0-4
	MOVL $1, DX
	MOVL $0, AX
	MOVL $1, BX
	DIVW BX
	MOVWLZX AX, AX
	MOVL AX, ret+0(FP)
	RET

TEXT ·divlOverflow(SB),NOSPLIT,$0-4
	MOVL $1, DX
	MOVL $0, AX
	MOVL $1, BX
	DIVL BX
	MOVL AX, ret+0(FP)
	RET

TEXT ·divlRuntime(SB),NOSPLIT,$0-16
	MOVL hi+0(FP), DX
	MOVL lo+4(FP), AX
	MOVL d+8(FP), BX
	DIVL BX
	MOVL AX, ret+12(FP)
	RET
`
	file386, err := Parse(ArchAMD64, src386)
	if err != nil {
		t.Fatalf("Parse 386 div failed: %v", err)
	}
	sig32 := func(name string) FuncSig {
		return FuncSig{
			Name:  name,
			Ret:   I32,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
		}
	}
	ll386, err := Translate(file386, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"divbOk":           sig32("divbOk"),
			"divbOverflow":     sig32("divbOverflow"),
			"divbZero":         sig32("divbZero"),
			"divbOverflowDead": sig32("divbOverflowDead"),
			"idivbOverflow":    sig32("idivbOverflow"),
			"idivbWideMinNeg1": sig32("idivbWideMinNeg1"),
			"divwOverflow":     sig32("divwOverflow"),
			"divlOverflow":     sig32("divlOverflow"),
			"divlRuntime": {
				Name: "divlRuntime",
				Args: []LLVMType{I32, I32, I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1},
						{Offset: 4, Type: I32, Index: 1, Field: -1},
						{Offset: 8, Type: I32, Index: 2, Field: -1},
					},
					Results: []FrameSlot{{Offset: 12, Type: I32, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Translate 386 div failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll386, "i386-unknown-linux-gnu")
	verifyLLVMWithTargetLLC(t, ll386, "i686-pc-windows-msvc")
	verifyLLVMWithTargetLLC(t, ll386, "i686-pc-windows-gnu")

	opt386 := runOptO2(t, ll386)
	// Verify Windows 32-bit MSVC & MinGW assembly contain real #DE divl and
	// ZERO __chkstk / ___chkstk_ms references.
	llcTool := findLLVM22Tool("llc")
	if llcTool == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	assertNoWindowsChkstk := func(ir, triple string) {
		t.Helper()
		cmd := exec.Command(llcTool, "-mtriple="+triple, "-O2", "-o", "-", "-")
		cmd.Stdin = strings.NewReader(ir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("llc (%s) asm emission failed: %v\n%s", triple, err, out)
		}
		asmText := string(out)
		if strings.Contains(asmText, "__chkstk") {
			t.Fatalf("llc (%s) emitted unexpected __chkstk reference:\n%s", triple, asmText)
		}
		if !strings.Contains(asmText, "divl") {
			t.Fatalf("llc (%s) missing #DE divl instruction:\n%s", triple, asmText)
		}
	}
	assertNoWindowsChkstk(opt386, "i686-pc-windows-msvc")
	assertNoWindowsChkstk(opt386, "i686-pc-windows-gnu")

	// 43 / 5 = 8 rem 3 => (3<<8) | 8 = 776
	if body := extractLLVMFuncBody(t, opt386, "divbOk"); !strings.Contains(body, "ret i32 776") {
		t.Errorf("386 divbOk expected ret i32 776, got:\n%s", body)
	}
	for _, trapFn := range []string{"divbOverflow", "divbZero", "divbOverflowDead", "idivbOverflow", "idivbWideMinNeg1", "divwOverflow", "divlOverflow"} {
		body := extractLLVMFuncBody(t, opt386, trapFn)
		if !strings.Contains(body, "divl %eax") || !strings.Contains(body, "unreachable") {
			t.Errorf("386 %s expected #DE inline asm trap + unreachable after -O2, got:\n%s", trapFn, body)
		}
		if strings.Contains(body, "ret i32") {
			t.Errorf("386 %s must not return normally after #DE trap:\n%s", trapFn, body)
		}
	}

	// amd64: DIVB, IDIVB, DIVW, IDIVW, DIVL, IDIVL, DIVQ, IDIVQ
	src64 := `
TEXT ·divbZero64(SB),NOSPLIT,$0-8
	MOVQ $7, AX
	MOVQ $0, BX
	DIVB BL
	MOVBQZX AL, AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·divbOvf64(SB),NOSPLIT,$0-8
	MOVQ $256, AX
	MOVQ $1, BX
	DIVB BL
	MOVBQZX AL, AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·divqOk64(SB),NOSPLIT,$0-8
	MOVQ $0, DX
	MOVQ $100, AX
	MOVQ $7, BX
	DIVQ BX
	SHLQ $8, DX
	ORQ DX, AX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·divqOvf64(SB),NOSPLIT,$0-8
	MOVQ $1, DX
	MOVQ $0, AX
	MOVQ $1, BX
	DIVQ BX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·idivqMinNeg1(SB),NOSPLIT,$0-8
	MOVQ $-1, DX
	MOVQ $-9223372036854775808, AX
	MOVQ $-1, BX
	IDIVQ BX
	MOVQ AX, ret+0(FP)
	RET

TEXT ·divbRuntime64(SB),NOSPLIT,$0-24
	MOVQ a+0(FP), AX
	MOVQ b+8(FP), BX
	DIVB BL
	MOVBQZX AL, AX
	MOVQ AX, ret+16(FP)
	RET
`
	file64, err := Parse(ArchAMD64, src64)
	if err != nil {
		t.Fatalf("Parse amd64 div failed: %v", err)
	}
	sig64 := func(name string) FuncSig {
		return FuncSig{
			Name:  name,
			Ret:   I64,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
		}
	}
	sigs64 := map[string]FuncSig{
		"divbZero64":   sig64("divbZero64"),
		"divbOvf64":    sig64("divbOvf64"),
		"divqOk64":     sig64("divqOk64"),
		"divqOvf64":    sig64("divqOvf64"),
		"idivqMinNeg1": sig64("idivqMinNeg1"),
		"divbRuntime64": {
			Name: "divbRuntime64",
			Args: []LLVMType{I64, I64},
			Ret:  I64,
			Frame: FrameLayout{
				Params: []FrameSlot{
					{Offset: 0, Type: I64, Index: 0, Field: -1},
					{Offset: 8, Type: I64, Index: 1, Field: -1},
				},
				Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
			},
		},
	}
	ll64, err := Translate(file64, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         sigs64,
	})
	if err != nil {
		t.Fatalf("Translate amd64 div failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll64, "x86_64-unknown-linux-gnu")
	verifyLLVMWithTargetLLC(t, ll64, "x86_64-pc-windows-msvc")
	verifyLLVMWithTargetLLC(t, ll64, "x86_64-pc-windows-gnu")

	// Also verify non-x86 and omitted (empty) target-triple lowering emit
	// portable @llvm.trap() without x86 inline asm so modules translated via
	// the public Translate API without TargetTriple compile cleanly on non-x86
	// hosts (e.g. Apple Silicon arm64) as well as x86_64.
	for _, tc := range []struct {
		name   string
		triple string
	}{
		{name: "arm64", triple: "arm64-apple-darwin"},
		{name: "empty", triple: ""},
	} {
		llPortable, err := Translate(file64, Options{
			TargetTriple: tc.triple,
			Goarch:       "amd64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         sigs64,
		})
		if err != nil {
			t.Fatalf("Translate amd64 div for %s triple failed: %v", tc.name, err)
		}
		if !strings.Contains(llPortable, "@llvm.trap()") || strings.Contains(llPortable, "divl %eax") || strings.Contains(llPortable, "xorl %eax") {
			t.Fatalf("%s triple div trap expected portable @llvm.trap() without x86 inline asm:\n%s", tc.name, llPortable)
		}
		verifyLLVMWithTargetLLC(t, llPortable, "arm64-apple-darwin")
		verifyLLVMWithTargetLLC(t, llPortable, "x86_64-unknown-linux-gnu")
		if tc.triple == "" {
			// Compile with llc using the default host target (no -mtriple),
			// reproducing callers that pass empty TargetTriple on arm64 hosts.
			tmpObj := filepath.Join(t.TempDir(), "empty_triple_div.o")
			cmd := exec.Command(llcTool, "-filetype=obj", "-o", tmpObj, "-")
			cmd.Stdin = strings.NewReader(llPortable)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("llc default-host compile of empty-triple amd64 div IR failed: %v\n%s", err, out)
			}
		}
	}

	opt64 := runOptO2(t, ll64)
	assertNoWindowsChkstk(opt64, "x86_64-pc-windows-msvc")
	assertNoWindowsChkstk(opt64, "x86_64-pc-windows-gnu")

	// 100 / 7 = 14 rem 2 => (2<<8) | 14 = 526
	if body := extractLLVMFuncBody(t, opt64, "divqOk64"); !strings.Contains(body, "ret i64 526") {
		t.Errorf("amd64 divqOk64 expected ret i64 526, got:\n%s", body)
	}
	for _, trapFn := range []string{"divbZero64", "divbOvf64", "divqOvf64", "idivqMinNeg1"} {
		body := extractLLVMFuncBody(t, opt64, trapFn)
		if !strings.Contains(body, "divl %eax") || !strings.Contains(body, "unreachable") {
			t.Errorf("amd64 %s expected #DE inline asm trap + unreachable after -O2, got:\n%s", trapFn, body)
		}
		if strings.Contains(body, "ret i64") {
			t.Errorf("amd64 %s must not return normally after #DE trap:\n%s", trapFn, body)
		}
	}

	// On Windows/amd64, verify real object compilation & linking succeeds with
	// zero __chkstk / ___chkstk_ms link errors.
	if runtime.GOOS == "windows" && runtime.GOARCH == "amd64" {
		llc, clang, ok := findLlcAndClang(t)
		if !ok {
			t.Skip("llc/clang not found")
		}
		winTriple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
		winC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern uint64_t divbRuntime64(uint64_t a, uint64_t b);
int main(void) {
	uint64_t got = divbRuntime64(42, 2);
	if (got != 21) {
		fprintf(stderr, "FAIL windows divb: got=%llu want=21\n", (unsigned long long)got);
		return 1;
	}
	return 0;
}
`
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "windows_div_link", winTriple, ll64, winC, nil)
	}

	// On native Linux/amd64, fork-test actual SIGFPE (#DE) delivery!
	if runtime.GOOS == "linux" && runtime.GOARCH == "amd64" {
		llc, clang, ok := findLlcAndClang(t)
		if !ok {
			t.Skip("llc/clang not found")
		}
		mainC := `
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>
extern uint64_t divbRuntime64(uint64_t a, uint64_t b);
static int expect_sigfpe(const char *name, uint64_t a, uint64_t b) {
	pid_t pid = fork();
	if (pid == 0) {
		volatile uint64_t r = divbRuntime64(a, b);
		(void)r;
		_exit(0);
	}
	int st = 0;
	waitpid(pid, &st, 0);
	if (!WIFSIGNALED(st) || WTERMSIG(st) != SIGFPE) {
		fprintf(stderr, "FAIL %s: expected SIGFPE, got status=0x%x\n", name, st);
		return 1;
	}
	return 0;
}
int main(void) {
	if (divbRuntime64(42, 2) != 21) {
		fprintf(stderr, "FAIL normal divb: got=%llu\n", (unsigned long long)divbRuntime64(42, 2));
		return 1;
	}
	int fail = 0;
	fail |= expect_sigfpe("divb_zero", 7, 0);
	fail |= expect_sigfpe("divb_overflow", 256, 1);
	return fail;
}
`
		compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "amd64_div_sigfpe", "x86_64-unknown-linux-gnu", ll64, mainC, nil)
	}
}

// TestCrossArchWasmNonSaturatingTruncTraps verifies all 8 non-saturating Wasm
// float-to-int truncations (i32/i64.trunc_f32/f64_s/u):
//   - Traps on NaN, +/-Inf, and out-of-range inputs survive LLVM -O2 EVEN WHEN
//     the truncated result is immediately Drop'ped.
//   - Exact IEEE-754 boundary values (e.g. -0.5 for unsigned, -2147483648.9 for
//     i32.trunc_f64_s, -2^63 for i64.trunc_f64_s) succeed without trapping.
//   - When wasm-ld and node are available, executes compiled Wasm bytecode in
//     Node.js to verify real WebAssembly traps and boundary return values.
func TestCrossArchWasmNonSaturatingTruncTraps(t *testing.T) {
	src := `
// Dropped NaN trunc must still trap after -O2 for all 8 ops!
TEXT ·dropI32F32SNaN(SB),NOSPLIT,$0-4
	F32Const $0x7fc00000
	I32TruncF32S
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI32F32UNaN(SB),NOSPLIT,$0-4
	F32Const $0x7fc00000
	I32TruncF32U
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI32F64SNaN(SB),NOSPLIT,$0-4
	F64Const $0x7ff8000000000000
	I32TruncF64S
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI32F64UNaN(SB),NOSPLIT,$0-4
	F64Const $0x7ff8000000000000
	I32TruncF64U
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI64F32SNaN(SB),NOSPLIT,$0-4
	F32Const $0x7fc00000
	I64TruncF32S
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI64F32UNaN(SB),NOSPLIT,$0-4
	F32Const $0x7fc00000
	I64TruncF32U
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI64F64SNaN(SB),NOSPLIT,$0-4
	F64Const $0x7ff8000000000000
	I64TruncF64S
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

TEXT ·dropI64F64UNaN(SB),NOSPLIT,$0-4
	F64Const $0x7ff8000000000000
	I64TruncF64U
	Drop
	I32Const $42
	I32Store ret+0(FP)
	RET

// Runtime-input functions for all 8 ops + dropped variant for Node execution.
TEXT ·rtI32F32S(SB),NOSPLIT,$0-8
	F32Load x+0(FP)
	I32TruncF32S
	I32Store ret+4(FP)
	RET

TEXT ·rtI32F32U(SB),NOSPLIT,$0-8
	F32Load x+0(FP)
	I32TruncF32U
	I32Store ret+4(FP)
	RET

TEXT ·rtI32F64S(SB),NOSPLIT,$0-12
	F64Load x+0(FP)
	I32TruncF64S
	I32Store ret+8(FP)
	RET

TEXT ·rtI32F64U(SB),NOSPLIT,$0-12
	F64Load x+0(FP)
	I32TruncF64U
	I32Store ret+8(FP)
	RET

TEXT ·rtI64F32S(SB),NOSPLIT,$0-12
	F32Load x+0(FP)
	I64TruncF32S
	I64Store ret+4(FP)
	RET

TEXT ·rtI64F32U(SB),NOSPLIT,$0-12
	F32Load x+0(FP)
	I64TruncF32U
	I64Store ret+4(FP)
	RET

TEXT ·rtI64F64S(SB),NOSPLIT,$0-16
	F64Load x+0(FP)
	I64TruncF64S
	I64Store ret+8(FP)
	RET

TEXT ·rtI64F64U(SB),NOSPLIT,$0-16
	F64Load x+0(FP)
	I64TruncF64U
	I64Store ret+8(FP)
	RET

TEXT ·rtDropI32F64S(SB),NOSPLIT,$0-12
	F64Load x+0(FP)
	I32TruncF64S
	Drop
	I32Const $77
	I32Store ret+8(FP)
	RET
`
	file, err := Parse(ArchWASM, src)
	if err != nil {
		t.Fatalf("Parse wasm trunc failed: %v", err)
	}
	dropFns := []string{
		"dropI32F32SNaN", "dropI32F32UNaN", "dropI32F64SNaN", "dropI32F64UNaN",
		"dropI64F32SNaN", "dropI64F32UNaN", "dropI64F64SNaN", "dropI64F64UNaN",
	}
	sigs := map[string]FuncSig{
		"rtI32F32S":     {Name: "rtI32F32S", Args: []LLVMType{"float"}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "float", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}}},
		"rtI32F32U":     {Name: "rtI32F32U", Args: []LLVMType{"float"}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "float", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}}}},
		"rtI32F64S":     {Name: "rtI32F64S", Args: []LLVMType{"double"}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}}},
		"rtI32F64U":     {Name: "rtI32F64U", Args: []LLVMType{"double"}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}}},
		"rtI64F32S":     {Name: "rtI64F32S", Args: []LLVMType{"float"}, Ret: I64, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "float", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 4, Type: I64, Index: 0, Field: -1}}}},
		"rtI64F32U":     {Name: "rtI64F32U", Args: []LLVMType{"float"}, Ret: I64, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "float", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 4, Type: I64, Index: 0, Field: -1}}}},
		"rtI64F64S":     {Name: "rtI64F64S", Args: []LLVMType{"double"}, Ret: I64, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}}},
		"rtI64F64U":     {Name: "rtI64F64U", Args: []LLVMType{"double"}, Ret: I64, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}}}},
		"rtDropI32F64S": {Name: "rtDropI32F64S", Args: []LLVMType{"double"}, Ret: I32, Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: "double", Index: 0, Field: -1}}, Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}}}},
	}
	for _, name := range dropFns {
		sigs[name] = FuncSig{
			Name:  name,
			Ret:   I32,
			Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
		}
	}
	ll, err := Translate(file, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Goarch:       "wasm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         sigs,
	})
	if err != nil {
		t.Fatalf("Translate wasm trunc failed: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ll, "wasm32-unknown-unknown")

	optIR := runOptO2(t, ll)
	t.Run("IRAndOptO2", func(t *testing.T) {
		for _, name := range dropFns {
			body := extractLLVMFuncBody(t, optIR, name)
			if !strings.Contains(body, "@llvm.trap()") || !strings.Contains(body, "unreachable") {
				t.Errorf("wasm %s dropped NaN trap was eliminated by -O2:\n%s", name, body)
			}
			if strings.Contains(body, "ret i32 42") {
				t.Errorf("wasm %s must not return 42 after dropped NaN trap:\n%s", name, body)
			}
		}
	})

	t.Run("NodeWasmExec", func(t *testing.T) {
		requireExec := os.Getenv("PLAN9ASM_REQUIRE_WASM_EXEC") == "1" || os.Getenv("PLAN9ASM_REQUIRE_AMD64_DIFF") == "1"
		wasmLD := findLLVM22Tool("wasm-ld")
		nodeBin, _ := exec.LookPath("node")
		llc := findLLVM22Tool("llc")
		if wasmLD == "" || nodeBin == "" || llc == "" {
			msg := fmt.Sprintf("Wasm execution prerequisites missing (wasm-ld-22=%q node=%q llc-22=%q)", wasmLD, nodeBin, llc)
			if requireExec {
				t.Fatal("PLAN9ASM_REQUIRE_WASM_EXEC=1: " + msg)
			}
			t.Skip(msg)
		}
		tmpDir := t.TempDir()
		llPath := filepath.Join(tmpDir, "trunc.ll")
		objPath := filepath.Join(tmpDir, "trunc.o")
		wasmPath := filepath.Join(tmpDir, "trunc.wasm")
		if err := os.WriteFile(llPath, []byte(optIR), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(llc, "-mtriple=wasm32-unknown-unknown", "-O2", "-filetype=obj", "-o", objPath, llPath).CombinedOutput(); err != nil {
			t.Fatalf("llc wasm32 obj failed: %v\n%s", err, out)
		}
		if out, err := exec.Command(wasmLD, "--no-entry", "--export-all", "-o", wasmPath, objPath).CombinedOutput(); err != nil {
			t.Fatalf("wasm-ld failed: %v\n%s", err, out)
		}
		js := fmt.Sprintf(`
const fs = require("fs");
const assert = require("assert");
const bytes = fs.readFileSync(%q);
const mod = new WebAssembly.Module(bytes);
const e = new WebAssembly.Instance(mod).exports;
let executed = 0;

function expectEq(name, got, want) {
  assert.strictEqual(got, want, name + ": got=" + got + " want=" + want);
  executed++;
}

function expectTrap(name, fn) {
  let trapped = false;
  try { fn(); } catch (err) {
    assert(err instanceof WebAssembly.RuntimeError, name + ": unexpected error " + err);
    trapped = true;
  }
  assert(trapped, name + ": expected WebAssembly trap, but returned normally");
  executed++;
}

// All 8 dropped NaN functions must trap even after -O2!
for (const name of %q.split(",")) {
  expectTrap(name, () => e[name]());
}

// Dropped runtime f64->i32s: valid returns 77, NaN/overflow traps!
expectEq("rtDropI32F64S(1.5)", e.rtDropI32F64S(1.5), 77);
expectEq("rtDropI32F64S(-2^31-0.9)", e.rtDropI32F64S(-2147483648.9), 77);
expectTrap("rtDropI32F64S(NaN)", () => e.rtDropI32F64S(NaN));
expectTrap("rtDropI32F64S(2^31)", () => e.rtDropI32F64S(2147483648.0));
expectTrap("rtDropI32F64S(-2^31-1)", () => e.rtDropI32F64S(-2147483649.0));

// i32.trunc_f32_s
expectEq("i32f32s(-2^31)", e.rtI32F32S(-2147483648.0), -2147483648);
expectEq("i32f32s(max)", e.rtI32F32S(2147483520.0), 2147483520);
expectTrap("i32f32s(NaN)", () => e.rtI32F32S(NaN));
expectTrap("i32f32s(+2^31)", () => e.rtI32F32S(2147483648.0));
expectTrap("i32f32s(-Inf)", () => e.rtI32F32S(-Infinity));

// i32.trunc_f32_u
expectEq("i32f32u(-0.5)", e.rtI32F32U(-0.5) >>> 0, 0);
expectEq("i32f32u(max)", e.rtI32F32U(4294967040.0) >>> 0, 4294967040);
expectTrap("i32f32u(-1)", () => e.rtI32F32U(-1.0));
expectTrap("i32f32u(2^32)", () => e.rtI32F32U(4294967296.0));
expectTrap("i32f32u(NaN)", () => e.rtI32F32U(NaN));

// i32.trunc_f64_s
expectEq("i32f64s(-2^31-0.9)", e.rtI32F64S(-2147483648.9), -2147483648);
expectEq("i32f64s(max)", e.rtI32F64S(2147483647.9), 2147483647);
expectTrap("i32f64s(-2^31-1)", () => e.rtI32F64S(-2147483649.0));
expectTrap("i32f64s(+2^31)", () => e.rtI32F64S(2147483648.0));
expectTrap("i32f64s(NaN)", () => e.rtI32F64S(NaN));

// i32.trunc_f64_u
expectEq("i32f64u(-0.999999)", e.rtI32F64U(-0.999999) >>> 0, 0);
expectEq("i32f64u(max)", e.rtI32F64U(4294967295.9) >>> 0, 4294967295);
expectTrap("i32f64u(-1)", () => e.rtI32F64U(-1.0));
expectTrap("i32f64u(2^32)", () => e.rtI32F64U(4294967296.0));

// i64.trunc_f32_s & u
expectEq("i64f32s(-2^63)", e.rtI64F32S(-9223372036854775808.0), -9223372036854775808n);
expectTrap("i64f32s(+2^63)", () => e.rtI64F32S(9223372036854775808.0));
expectTrap("i64f32s(NaN)", () => e.rtI64F32S(NaN));
expectEq("i64f32u(-0.5)", e.rtI64F32U(-0.5), 0n);
expectTrap("i64f32u(-1)", () => e.rtI64F32U(-1.0));
expectTrap("i64f32u(2^64)", () => e.rtI64F32U(18446744073709551616.0));

// i64.trunc_f64_s & u
expectEq("i64f64s(-2^63)", e.rtI64F64S(-9223372036854775808.0), -9223372036854775808n);
expectTrap("i64f64s(+2^63)", () => e.rtI64F64S(9223372036854775808.0));
expectTrap("i64f64s(NaN)", () => e.rtI64F64S(NaN));
expectEq("i64f64u(-0.999999)", e.rtI64F64U(-0.999999), 0n);
expectTrap("i64f64u(-1)", () => e.rtI64F64U(-1.0));
expectTrap("i64f64u(2^64)", () => e.rtI64F64U(18446744073709551616.0));

console.log("wasm_trunc_executed_cases=" + executed);
`, wasmPath, strings.Join(dropFns, ","))
		out, err := exec.Command(nodeBin, "-e", js).CombinedOutput()
		if err != nil {
			t.Fatalf("node wasm32 trunc execution failed: %v\n%s", err, out)
		}
		const wantCases = 44
		wantMarker := fmt.Sprintf("wasm_trunc_executed_cases=%d", wantCases)
		if !strings.Contains(string(out), wantMarker) {
			t.Fatalf("expected %q in Node output, got:\n%s", wantMarker, out)
		}
		t.Log(wantMarker)
	})
}

// TestFindLLVM22ToolRejectsNon22WasmLD ensures the LLVM 22 toolchain lookup
// rejects non-22 wasm-ld binaries on PATH (e.g. LLD 23.1.4) while accepting
// genuine LLD 22.x binaries.
func TestFindLLVM22ToolRejectsNon22WasmLD(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell shim test runs on Unix hosts")
	}
	writeShim := func(dir, name, version string) string {
		p := filepath.Join(dir, name)
		script := "#!/bin/sh\necho " + version + "\n"
		if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	t.Run("RejectLLD23", func(t *testing.T) {
		dir := t.TempDir()
		writeShim(dir, "wasm-ld", "'Homebrew LLD 23.1.4'")
		t.Setenv("LLVM_CONFIG", "")
		t.Setenv("PATH", dir)
		if got := findLLVM22Tool("wasm-ld"); got != "" {
			t.Fatalf("findLLVM22Tool(wasm-ld) accepted non-22 binary: %q", got)
		}
	})
	t.Run("AcceptLLD22", func(t *testing.T) {
		dir := t.TempDir()
		want := writeShim(dir, "wasm-ld", "'Ubuntu LLD 22.1.8'")
		t.Setenv("LLVM_CONFIG", "")
		t.Setenv("PATH", dir)
		if got := findLLVM22Tool("wasm-ld"); got != want {
			t.Fatalf("findLLVM22Tool(wasm-ld) = %q, want %q", got, want)
		}
	})
	t.Run("LLVMConfig22FallsBackToPathLLD22", func(t *testing.T) {
		llvmBin := t.TempDir()
		pathBin := t.TempDir()
		llvmConfig := filepath.Join(llvmBin, "llvm-config")
		cfgScript := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n--version) echo 22.1.8 ;;\n--bindir) echo %q ;;\nesac\n", llvmBin)
		if err := os.WriteFile(llvmConfig, []byte(cfgScript), 0o755); err != nil {
			t.Fatal(err)
		}
		want := writeShim(pathBin, "wasm-ld", "'Homebrew LLD 22.1.8'")
		t.Setenv("LLVM_CONFIG", llvmConfig)
		t.Setenv("PATH", pathBin)
		if got := findLLVM22Tool("wasm-ld"); got != want {
			t.Fatalf("findLLVM22Tool(wasm-ld) with separate LLVM_CONFIG bindir = %q, want %q", got, want)
		}
	})
	t.Run("LLVMConfig22StillRejectsPathLLD23", func(t *testing.T) {
		llvmBin := t.TempDir()
		pathBin := t.TempDir()
		llvmConfig := filepath.Join(llvmBin, "llvm-config")
		cfgScript := fmt.Sprintf("#!/bin/sh\ncase \"$1\" in\n--version) echo 22.1.8 ;;\n--bindir) echo %q ;;\nesac\n", llvmBin)
		if err := os.WriteFile(llvmConfig, []byte(cfgScript), 0o755); err != nil {
			t.Fatal(err)
		}
		writeShim(pathBin, "wasm-ld", "'Homebrew LLD 23.1.4'")
		t.Setenv("LLVM_CONFIG", llvmConfig)
		t.Setenv("PATH", pathBin)
		if got := findLLVM22Tool("wasm-ld"); got != "" {
			t.Fatalf("findLLVM22Tool(wasm-ld) with LLVM_CONFIG=22 accepted LLD 23 on PATH: %q", got)
		}
	})
	t.Run("InvalidLLVMConfigRejectsPathLLD22", func(t *testing.T) {
		pathBin := t.TempDir()
		writeShim(pathBin, "wasm-ld", "'Ubuntu LLD 22.1.8'")
		t.Setenv("LLVM_CONFIG", "/nonexistent/llvm-config")
		t.Setenv("PATH", pathBin)
		if got := findLLVM22Tool("wasm-ld"); got != "" {
			t.Fatalf("findLLVM22Tool(wasm-ld) with invalid LLVM_CONFIG accepted PATH binary: %q", got)
		}
	})
}

// BenchmarkAMD64PureInt1024ADDQ tracks ABI0 validation allocations on a
// 1,024-instruction pure-integer amd64 function (straight-line and branched),
// ensuring lazy x87ByTop avoids allocating the 8-way x87/MMX partition table
// when x87/MMX is unused.
func BenchmarkAMD64PureInt1024ADDQ(b *testing.B) {
	makeBench := func(branched bool) (*File, map[string]FuncSig) {
		var sb strings.Builder
		sb.WriteString("TEXT ·add1024(SB),NOSPLIT,$0-16\n")
		sb.WriteString("\tMOVQ x+0(FP), AX\n")
		for i := 0; i < 1024; i++ {
			sb.WriteString("\tADDQ $1, AX\n")
			if branched {
				fmt.Fprintf(&sb, "\tJNZ L%d\nL%d:\n", i, i)
			}
		}
		sb.WriteString("\tMOVQ AX, ret+8(FP)\n")
		sb.WriteString("\tRET\n")
		file, err := Parse(ArchAMD64, sb.String())
		if err != nil {
			b.Fatal(err)
		}
		sigs := map[string]FuncSig{
			"add1024": {
				Name: "add1024",
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		}
		return file, sigs
	}
	resolve := func(s string) string { return strings.TrimPrefix(s, "·") }
	b.Run("StraightLine", func(b *testing.B) {
		file, sigs := makeBench(false)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateAMD64PhysicalFrameLeases(file, resolve, sigs); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("Branched1024", func(b *testing.B) {
		file, sigs := makeBench(true)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := validateAMD64PhysicalFrameLeases(file, resolve, sigs); err != nil {
				b.Fatal(err)
			}
		}
	})
}
