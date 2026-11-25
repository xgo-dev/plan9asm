package plan9asm

import (
	"strings"
	"testing"
)

func TestM8_CharLiteralImmediates(t *testing.T) {
	amd64Src := `
TEXT ·m8CharAMD64(SB), NOSPLIT, $0-8
	MOVQ $'a', AX
	ADDQ $'\n', AX
	ADDQ $'\x7f', AX
	ADDQ $',', AX
	ADDQ $('z'-'a'), AX
	MOVQ AX, ret+0(FP)
	RET
`
	arm64Src := `
TEXT ·m8CharARM64(SB), NOSPLIT, $0-8
	MOVD $'a', R0
	ADD  $'\n', R0, R0
	ADD  $'\x7f', R0, R0
	ADD  $',', R0, R0
	ADD  $('z'-'a'), R0, R0
	MOVD R0, ret+0(FP)
	RET
`
	armSrc := `
TEXT ·m8CharARM(SB), NOSPLIT, $0-4
	MOVW $'a', R0
	ADD  $',', R0, R0
	ADD  $('z'-'a'), R0, R0
	MOVW R0, ret+0(FP)
	RET
`
	fX86, err := Parse(ArchAMD64, amd64Src)
	if err != nil {
		t.Fatalf("parse amd64 char literals: %v", err)
	}
	fA64, err := Parse(ArchARM64, arm64Src)
	if err != nil {
		t.Fatalf("parse arm64 char literals: %v", err)
	}
	fARM, err := Parse(ArchARM, armSrc)
	if err != nil {
		t.Fatalf("parse arm char literals: %v", err)
	}

	hostTriple := hostLLVMTriple()
	x86Triple := "x86_64-unknown-linux-gnu"
	a64Triple := "aarch64-unknown-linux-gnu"
	if hostTriple != "" {
		x86Triple = hostTriple
		a64Triple = hostTriple
	}

	irX86, err := Translate(fX86, Options{
		TargetTriple: x86Triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8CharAMD64": {
				Name:  "m8CharAMD64",
				Ret:   I64,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate amd64 char literals: %v", err)
	}
	irA64, err := Translate(fA64, Options{
		TargetTriple: a64Triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8CharARM64": {
				Name:  "m8CharARM64",
				Ret:   I64,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate arm64 char literals: %v", err)
	}
	irARM, err := Translate(fARM, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8CharARM": {
				Name:  "m8CharARM",
				Ret:   I32,
				Frame: FrameLayout{Results: []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}}},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate arm char literals: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irARM, "armv7-unknown-linux-gnueabihf")

	if hostTriple != "" {
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern uint64_t m8CharAMD64(void);
extern uint64_t m8CharARM64(void);
int main(void) {
	// 'a'(97) + '\n'(10) + '\x7f'(127) + ','(44) + ('z'-'a')(25) = 303
	uint64_t x = m8CharAMD64();
	uint64_t a = m8CharARM64();
	if (x != 303ULL || a != 303ULL) {
		fprintf(stderr, "char imm mismatch: x86=%llu arm64=%llu want=303\n", (unsigned long long)x, (unsigned long long)a);
		return 1;
	}
	printf("M8_CHAR_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{irX86, irA64}, mainC, "M8_CHAR_OK")
	}
}

func TestM8_OpFPAndSymOffset(t *testing.T) {
	// 1. amd64 JMP sym+8(SB) and CALL sym+8(SB) IR & llc verification.
	symOffSrc := `
TEXT ·m8SymCallJmp(SB), NOSPLIT, $0-8
	CALL extfn+8(SB)
	JMP  extfn+16(SB)
`
	fSym, err := Parse(ArchAMD64, symOffSrc)
	if err != nil {
		t.Fatalf("parse sym+off: %v", err)
	}
	irSym, err := Translate(fSym, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8SymCallJmp": {Name: "m8SymCallJmp", Ret: I64},
		},
	})
	if err != nil {
		t.Fatalf("translate sym+off: %v", err)
	}
	if !strings.Contains(irSym, "getelementptr i8, ptr @extfn, i64 8") ||
		!strings.Contains(irSym, "getelementptr i8, ptr @extfn, i64 16") {
		t.Fatalf("expected non-zero symbol offsets in IR, got:\n%s", irSym)
	}
	verifyLLVMWithTargetLLC(t, irSym, "x86_64-unknown-linux-gnu")

	// 2. amd64 remaining OpFP gaps: VMOVDQU (X/Y), VMOVDQU64 (Z), BTSQ/BTRQ,
	//    XCHGQ/XADDQ/CMPXCHGQ/ORW/ANDW on OpFP.
	amd64FPSrc := `
TEXT ·m8AMD64VecFP(SB), NOSPLIT, $0-128
	VMOVDQU64 a+0(FP), Z0
	VMOVDQU64 Z0, ret+64(FP)
	VMOVDQU   a+0(FP), Y1
	VMOVDQU   Y1, ret+64(FP)
	VMOVDQU   a+0(FP), X2
	VMOVDQU   X2, ret+64(FP)
	RET

TEXT ·m8AMD64BitAtomicFP(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), AX
	MOVQ AX, ret+16(FP)
	BTSQ $5, ret+16(FP)
	BTRQ $1, ret+16(FP)
	MOVQ $10, BX
	XADDQ BX, ret+16(FP)
	// BX now holds old ret; ret += 10
	MOVQ ret+16(FP), AX
	MOVQ b+8(FP), CX
	CMPXCHGQ CX, ret+16(FP)
	// ret is now b; swap with DX=0x42
	MOVQ $0x42, DX
	XCHGQ ret+16(FP), DX
	// DX holds b; ret holds 0x42; ORW $0x100, ret -> 0x142
	ORW $0x100, ret+16(FP)
	ANDW $0x1ff, ret+16(FP)
	// Return (ret << 32) | (DX & 0xffffffff)
	MOVQ ret+16(FP), R8
	SHLQ $32, R8
	ANDQ $0xffffffff, DX
	ORQ  DX, R8
	MOVQ R8, ret+16(FP)
	RET
`
	fAMD64FP, err := Parse(ArchAMD64, amd64FPSrc)
	if err != nil {
		t.Fatalf("parse amd64 OpFP: %v", err)
	}
	hostTriple := hostLLVMTriple()
	x86Triple := "x86_64-unknown-linux-gnu"
	if hostTriple != "" {
		x86Triple = hostTriple
	}
	zArgs := make([]LLVMType, 8)
	zParams := make([]FrameSlot, 8)
	zResults := make([]FrameSlot, 8)
	for i := 0; i < 8; i++ {
		zArgs[i] = I64
		zParams[i] = FrameSlot{Offset: int64(i * 8), Type: I64, Index: i, Field: -1}
		zResults[i] = FrameSlot{Offset: int64(64 + i*8), Type: I64, Index: i, Field: -1}
	}
	irAMD64FP, err := Translate(fAMD64FP, Options{
		TargetTriple: x86Triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8AMD64VecFP": {
				Name:  "m8AMD64VecFP",
				Args:  zArgs,
				Ret:   LLVMType("{ i64, i64, i64, i64, i64, i64, i64, i64 }"),
				Frame: FrameLayout{Params: zParams, Results: zResults},
			},
			"m8AMD64BitAtomicFP": {
				Name: "m8AMD64BitAtomicFP",
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
		},
	})
	if err != nil {
		t.Fatalf("translate amd64 OpFP: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irAMD64FP, "x86_64-unknown-linux-gnu")

	// 3. arm64 remaining OpFP gaps: FMOVQ, LDP, LDPW, STPW (both split and packed slots).
	arm64FPSrc := `
TEXT ·m8ARM64FMOVQFP(SB), NOSPLIT, $0-32
	FMOVQ a+0(FP), F0
	FMOVQ F0, ret+16(FP)
	RET

TEXT ·m8ARM64LDPFP(SB), NOSPLIT, $0-32
	LDP a+0(FP), (R1, R2)
	ADD $1, R1, R1
	ADD $2, R2, R2
	STP (R1, R2), ret+16(FP)
	RET

TEXT ·m8ARM64LDPWSTPW(SB), NOSPLIT, $0-16
	LDPW a+0(FP), (R1, R2)
	ADD  $10, R1, R1
	ADD  $20, R2, R2
	STPW (R1, R2), ret+8(FP)
	RET

TEXT ·m8ARM64LDPWPacked(SB), NOSPLIT, $0-16
	LDPW a+0(FP), (R1, R2)
	ADD  $1, R1, R1
	ADD  $2, R2, R2
	STPW (R1, R2), ret+8(FP)
	RET
`
	fARM64FP, err := Parse(ArchARM64, arm64FPSrc)
	if err != nil {
		t.Fatalf("parse arm64 OpFP: %v", err)
	}
	a64Triple := "aarch64-unknown-linux-gnu"
	if hostTriple != "" {
		a64Triple = hostTriple
	}
	irARM64FP, err := Translate(fARM64FP, Options{
		TargetTriple: a64Triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8ARM64FMOVQFP": {
				Name: "m8ARM64FMOVQFP",
				Args: []LLVMType{I64, I64},
				Ret:  LLVMType("{ i64, i64 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: I64, Index: 0, Field: -1},
						{Offset: 24, Type: I64, Index: 1, Field: -1},
					},
				},
			},
			"m8ARM64LDPFP": {
				Name: "m8ARM64LDPFP",
				Args: []LLVMType{I64, I64},
				Ret:  LLVMType("{ i64, i64 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I64, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 16, Type: I64, Index: 0, Field: -1},
						{Offset: 24, Type: I64, Index: 1, Field: -1},
					},
				},
			},
			"m8ARM64LDPWSTPW": {
				Name: "m8ARM64LDPWSTPW",
				Args: []LLVMType{I32, I32},
				Ret:  LLVMType("{ i32, i32 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: I32, Index: 0, Field: -1},
						{Offset: 4, Type: I32, Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 8, Type: I32, Index: 0, Field: -1},
						{Offset: 12, Type: I32, Index: 1, Field: -1},
					},
				},
			},
			"m8ARM64LDPWPacked": {
				Name: "m8ARM64LDPWPacked",
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate arm64 OpFP: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irARM64FP, "aarch64-unknown-linux-gnu")

	if hostTriple != "" {
		irAMD64Host := irAMD64FP + `
define void @m8AMD64VecFPOut(ptr %in, ptr %out) {
entry:
  %p0 = getelementptr i64, ptr %in, i64 0
  %p1 = getelementptr i64, ptr %in, i64 1
  %p2 = getelementptr i64, ptr %in, i64 2
  %p3 = getelementptr i64, ptr %in, i64 3
  %p4 = getelementptr i64, ptr %in, i64 4
  %p5 = getelementptr i64, ptr %in, i64 5
  %p6 = getelementptr i64, ptr %in, i64 6
  %p7 = getelementptr i64, ptr %in, i64 7
  %v0 = load i64, ptr %p0
  %v1 = load i64, ptr %p1
  %v2 = load i64, ptr %p2
  %v3 = load i64, ptr %p3
  %v4 = load i64, ptr %p4
  %v5 = load i64, ptr %p5
  %v6 = load i64, ptr %p6
  %v7 = load i64, ptr %p7
  %r = call { i64, i64, i64, i64, i64, i64, i64, i64 } @m8AMD64VecFP(i64 %v0, i64 %v1, i64 %v2, i64 %v3, i64 %v4, i64 %v5, i64 %v6, i64 %v7)
  %r0 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 0
  %r1 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 1
  %r2 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 2
  %r3 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 3
  %r4 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 4
  %r5 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 5
  %r6 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 6
  %r7 = extractvalue { i64, i64, i64, i64, i64, i64, i64, i64 } %r, 7
  %o0 = getelementptr i64, ptr %out, i64 0
  %o1 = getelementptr i64, ptr %out, i64 1
  %o2 = getelementptr i64, ptr %out, i64 2
  %o3 = getelementptr i64, ptr %out, i64 3
  %o4 = getelementptr i64, ptr %out, i64 4
  %o5 = getelementptr i64, ptr %out, i64 5
  %o6 = getelementptr i64, ptr %out, i64 6
  %o7 = getelementptr i64, ptr %out, i64 7
  store i64 %r0, ptr %o0
  store i64 %r1, ptr %o1
  store i64 %r2, ptr %o2
  store i64 %r3, ptr %o3
  store i64 %r4, ptr %o4
  store i64 %r5, ptr %o5
  store i64 %r6, ptr %o6
  store i64 %r7, ptr %o7
  ret void
}
`
		irARM64Host := irARM64FP + `
define void @m8ARM64FMOVQFPOut(i64 %a, i64 %b, ptr %out) {
entry:
  %r = call { i64, i64 } @m8ARM64FMOVQFP(i64 %a, i64 %b)
  %v0 = extractvalue { i64, i64 } %r, 0
  %v1 = extractvalue { i64, i64 } %r, 1
  store i64 %v0, ptr %out
  %p1 = getelementptr i64, ptr %out, i64 1
  store i64 %v1, ptr %p1
  ret void
}
define void @m8ARM64LDPFPOut(i64 %a, i64 %b, ptr %out) {
entry:
  %r = call { i64, i64 } @m8ARM64LDPFP(i64 %a, i64 %b)
  %v0 = extractvalue { i64, i64 } %r, 0
  %v1 = extractvalue { i64, i64 } %r, 1
  store i64 %v0, ptr %out
  %p1 = getelementptr i64, ptr %out, i64 1
  store i64 %v1, ptr %p1
  ret void
}
define void @m8ARM64LDPWSTPWOut(i32 %a, i32 %b, ptr %out) {
entry:
  %r = call { i32, i32 } @m8ARM64LDPWSTPW(i32 %a, i32 %b)
  %v0 = extractvalue { i32, i32 } %r, 0
  %v1 = extractvalue { i32, i32 } %r, 1
  store i32 %v0, ptr %out
  %p1 = getelementptr i32, ptr %out, i64 1
  store i32 %v1, ptr %p1
  ret void
}
`
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern void m8AMD64VecFPOut(uint64_t *in, uint64_t *out);
extern uint64_t m8AMD64BitAtomicFP(uint64_t a, uint64_t b);
extern void m8ARM64FMOVQFPOut(uint64_t a, uint64_t b, uint64_t *out);
extern void m8ARM64LDPFPOut(uint64_t a, uint64_t b, uint64_t *out);
extern void m8ARM64LDPWSTPWOut(uint32_t a, uint32_t b, uint32_t *out);
extern uint64_t m8ARM64LDPWPacked(uint64_t packed);

int main(void) {
	uint64_t zin[8] = {11, 22, 33, 44, 55, 66, 77, 88};
	uint64_t zout[8] = {0};
	m8AMD64VecFPOut(zin, zout);
	for (int i = 0; i < 8; i++) {
		if (zout[i] != zin[i]) {
			fprintf(stderr, "VMOVDQU64 OpFP mismatch at %d: got=%llu want=%llu\n", i, (unsigned long long)zout[i], (unsigned long long)zin[i]);
			return 1;
		}
	}
	// a = 0x3 -> BTS 5 => 0x23 -> BTR 1 => 0x21 -> XADD 10 => 0x2b -> CMPXCHG b=0x1234 -> XCHG 0x42 -> ORW 0x100 => 0x142
	uint64_t r = m8AMD64BitAtomicFP(0x3ULL, 0x1234ULL);
	uint64_t want = (0x142ULL << 32) | 0x1234ULL;
	if (r != want) {
		fprintf(stderr, "m8AMD64BitAtomicFP mismatch: got=0x%llx want=0x%llx\n", (unsigned long long)r, (unsigned long long)want);
		return 2;
	}
	uint64_t fmovOut[2] = {0, 0};
	m8ARM64FMOVQFPOut(0x1122334455667788ULL, 0x99aabbccddeeff00ULL, fmovOut);
	if (fmovOut[0] != 0x1122334455667788ULL || fmovOut[1] != 0x99aabbccddeeff00ULL) {
		fprintf(stderr, "FMOVQ OpFP mismatch\n");
		return 3;
	}
	uint64_t ldpOut[2] = {0, 0};
	m8ARM64LDPFPOut(100, 200, ldpOut);
	if (ldpOut[0] != 101 || ldpOut[1] != 202) {
		fprintf(stderr, "LDP OpFP mismatch: %llu %llu\n", (unsigned long long)ldpOut[0], (unsigned long long)ldpOut[1]);
		return 4;
	}
	uint32_t ldpwOut[2] = {0, 0};
	m8ARM64LDPWSTPWOut(7, 9, ldpwOut);
	if (ldpwOut[0] != 17 || ldpwOut[1] != 29) {
		fprintf(stderr, "LDPW/STPW split OpFP mismatch: %u %u\n", ldpwOut[0], ldpwOut[1]);
		return 5;
	}
	uint64_t pk = m8ARM64LDPWPacked((0x00000010ULL << 32) | 0x00000005ULL);
	if (pk != ((0x00000012ULL << 32) | 0x00000006ULL)) {
		fprintf(stderr, "LDPW/STPW packed OpFP mismatch: 0x%llx\n", (unsigned long long)pk);
		return 6;
	}
	printf("M8_OPFP_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{irAMD64Host, irARM64Host}, mainC, "M8_OPFP_OK")
	}
}

func TestM8_ARM64PrePostWritebackDiffSemantics(t *testing.T) {
	src := `
// Walk a uint64 buffer with MOVD.W load/store, MOVD.P store, LDP.W, STP.W,
// MOVW.W, LDPW.W, STPW.W, and FMOVD.W; return final R1 - initial R1.
TEXT ·m8ARM64PrePost(SB), NOSPLIT, $0-24
	MOVD buf+0(FP), R1
	MOVD R1, R10
	// 1. MOVD.P store: writes 0x1111 to buf[0], then R1 += 8 (&buf[1])
	MOVD $0x1111, R2
	MOVD.P R2, 8(R1)
	// 2. MOVD.W store: R1 += 8 (&buf[2]), then writes 0x2222 to buf[2]
	MOVD $0x2222, R3
	MOVD.W R3, 8(R1)
	// 3. MOVD.W load: R1 += 8 (&buf[3]), loads buf[3] (preloaded 0x3333) into R4
	MOVD.W 8(R1), R4
	// 4. STP.W: R1 += 16 (&buf[5]), stores (R4+1, R4+2) at buf[5], buf[6]
	ADD  $1, R4, R5
	ADD  $2, R4, R6
	STP.W (R5, R6), 16(R1)
	// 5. LDP.W: R1 += -16 (&buf[3]), loads (buf[3], buf[4]) into (R7, R8)
	LDP.W -16(R1), (R7, R8)
	// 6. MOVW.W + STPW.W + LDPW.W on buf[7] (which holds two u32s):
	//    R1 is at &buf[3]; advance by +32 to &buf[7] via LDPW.W
	LDPW.W 32(R1), (R2, R3)
	ADD  $10, R2, R2
	ADD  $20, R3, R3
	//    Store updated pair to buf[8] via STPW.W +8
	STPW.W (R2, R3), 8(R1)
	// 7. FMOVD.W: R1 += 8 (&buf[9]), load double and store to &buf[10] via FMOVD.W +8
	FMOVD.W 8(R1), F0
	FMOVD.W F0, 8(R1)
	// Return (R1 - initial R1) and R7 + R8
	SUB  R10, R1, R0
	MOVD R0, ret0+8(FP)
	ADD  R7, R8, R9
	MOVD R9, ret1+16(FP)
	RET
`
	f, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("parse arm64 .W/.P: %v", err)
	}
	hostTriple := hostLLVMTriple()
	triple := "aarch64-unknown-linux-gnu"
	if hostTriple != "" {
		triple = hostTriple
	}
	ir, err := Translate(f, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8ARM64PrePost": {
				Name: "m8ARM64PrePost",
				Args: []LLVMType{Ptr},
				Ret:  LLVMType("{ i64, i64 }"),
				Frame: FrameLayout{
					Params: []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
					Results: []FrameSlot{
						{Offset: 8, Type: I64, Index: 0, Field: -1},
						{Offset: 16, Type: I64, Index: 1, Field: -1},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate arm64 .W/.P: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir, "aarch64-unknown-linux-gnu")

	if hostTriple != "" {
		hostIR := ir + `
define void @m8ARM64PrePostOut(ptr %buf, ptr %out) {
entry:
  %r = call { i64, i64 } @m8ARM64PrePost(ptr %buf)
  %v0 = extractvalue { i64, i64 } %r, 0
  %v1 = extractvalue { i64, i64 } %r, 1
  store i64 %v0, ptr %out
  %p1 = getelementptr i64, ptr %out, i64 1
  store i64 %v1, ptr %p1
  ret void
}
`
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern void m8ARM64PrePostOut(uint64_t *buf, uint64_t *out);

int main(void) {
	uint64_t buf[12] = {0};
	buf[1] = 0xaaaaULL; // must stay untouched (skipped by MOVD.W +8 from &buf[1] to &buf[2])
	buf[3] = 0x3333ULL;
	buf[4] = 0x4444ULL;
	buf[7] = (0x00000002ULL << 32) | 0x00000001ULL;
	buf[9] = 0x400921fb54442d18ULL; // pi bits
	uint64_t out[2] = {0, 0};
	m8ARM64PrePostOut(buf, out);
	// Final R1 is &buf[10] => delta = 80 bytes
	if (out[0] != 80ULL || out[1] != (0x3333ULL + 0x4444ULL)) {
		fprintf(stderr, "arm64 .W/.P ret mismatch: delta=%llu sum=0x%llx\n", (unsigned long long)out[0], (unsigned long long)out[1]);
		return 1;
	}
	if (buf[0] != 0x1111ULL || buf[1] != 0xaaaaULL || buf[2] != 0x2222ULL ||
		buf[5] != 0x3334ULL || buf[6] != 0x3335ULL ||
		buf[8] != ((0x00000016ULL << 32) | 0x0000000bULL) ||
		buf[10] != 0x400921fb54442d18ULL) {
		fprintf(stderr, "arm64 .W/.P buf mismatch: b0=%llx b1=%llx b2=%llx b5=%llx b6=%llx b8=%llx b10=%llx\n",
			(unsigned long long)buf[0], (unsigned long long)buf[1], (unsigned long long)buf[2],
			(unsigned long long)buf[5], (unsigned long long)buf[6], (unsigned long long)buf[8], (unsigned long long)buf[10]);
		return 2;
	}
	printf("M8_ARM64_WB_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{hostIR}, mainC, "M8_ARM64_WB_OK")
	}
}

func TestM8_ARM32AddrModesWritebackAndSubOff(t *testing.T) {
	armSrc := `
TEXT ·m8ARMModes(SB), NOSPLIT, $0-8
	MOVW p+0(FP), R1
	// .U: negative offset (-4), no writeback
	MOVW.U 4(R1), R2
	// .W: pre-increment (+4), writes R1
	MOVW.W 4(R1), R3
	// .W.U: pre-decrement (-4), writes R1
	MOVW.W.U 4(R1), R4
	// .P.U: post-decrement (-4), writes R1 after load
	MOVW.P.U 4(R1), R5
	// Stores with .W.U and .P.U
	MOVW.W.U R2, 4(R1)
	MOVW.P.U R3, 4(R1)
	// Narrow + VFP with .W/.U
	MOVB.W.U 1(R1), R6
	MOVF.W   4(R1), F0
	MOVD.P.U 8(R1), F1
	ADD R2, R3, R0
	ADD R4, R0, R0
	ADD R5, R0, R0
	ADD R6, R0, R0
	ADD R1, R0, R0
	MOVW R0, ret+4(FP)
	RET
`
	f, err := Parse(ArchARM, armSrc)
	if err != nil {
		t.Fatalf("parse arm .W/.U: %v", err)
	}
	ir, err := Translate(f, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8ARMModes": {
				Name: "m8ARMModes",
				Args: []LLVMType{I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate arm .W/.U: %v", err)
	}
	// Verify negative offsets (-4, -1, -8) and R1 writeback stores are emitted!
	for _, want := range []string{"add i32 ", ", -4", ", -1", ", -8", "store i32 %", ", ptr %reg_R1"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("expected %q in ARM .W/.U IR, got:\n%s", want, ir)
		}
	}
	verifyLLVMWithTargetLLC(t, ir, "armv7-unknown-linux-gnueabihf")
}

func TestM8_X86LockAtomicsDiffSemantics(t *testing.T) {
	// Test ALL lockable x86 RMW ops emit true atomicrmw/cmpxchg seq_cst AND
	// produce bit-for-bit accurate memory + flag semantics on host execution!
	src := `
// buf[0..11] are 64-bit slots used to verify each LOCK op + its flags.
TEXT ·m8LockAtomics(SB), NOSPLIT, $0-16
	MOVQ buf+0(FP), DI
	XORQ R12, R12

	// 0: LOCK; ADDQ $10, 0(DI) (wrap from -5 to +5 => CF=1)
	LOCK; ADDQ $10, 0(DI)
	SETCS AL
	MOVBQZX AL, AX
	ORQ AX, R12

	// 1: LOCK; SUBQ $10, 8(DI) (3 - 10 => -7, CF=1)
	LOCK; SUBQ $10, 8(DI)
	SETCS AL
	MOVBQZX AL, AX
	SHLQ $1, AX
	ORQ AX, R12

	// 2: LOCK; XORQ $0xff, 16(DI)
	LOCK; XORQ $0xff, 16(DI)

	// 3: LOCK; ORW $0x0f00, 24(DI) and LOCK; ANDW $0x0ff0, 24(DI)
	LOCK; ORW $0x0f00, 24(DI)
	LOCK; ANDW $0x0ff0, 24(DI)

	// 4: LOCK; INCQ 32(DI) and LOCK; DECQ 40(DI) (1 -> 0 => ZF=1)
	LOCK; INCQ 32(DI)
	LOCK; DECQ 40(DI)
	SETEQ AL
	MOVBQZX AL, AX
	SHLQ $2, AX
	ORQ AX, R12

	// 5: LOCK; BTSQ CX, 48(DI) with CX=67 -> sets bit 3 of buf[7] (unbounded bit-string!),
	//    then LOCK; BTRQ $3, 56(DI) -> clears bit 3 of buf[7] (old bit=1 => CF=1),
	//    then LOCK; BTCQ $0, 48(DI) -> flips bit 0 of buf[6].
	MOVQ $67, CX
	LOCK; BTSQ CX, 48(DI)
	LOCK; BTRQ $3, 56(DI)
	SETCS AL
	MOVBQZX AL, AX
	SHLQ $3, AX
	ORQ AX, R12
	LOCK; BTCQ $0, 48(DI)

	// 6: LOCK; NEGQ 64(DI) (42 -> -42, CF=1); save CF via SETCS (preserves all flags!)
	LOCK; NEGQ 64(DI)
	SETCS R8B

	// 7: LOCK; NOTQ 72(DI) (0x0f0f -> ~0x0f0f; must preserve CF=1 from NEGQ!)
	LOCK; NOTQ 72(DI)

	// 8: LOCK; ADCQ $5, 80(DI) with CF=1 preserved from NEGQ:
	//    0xfffffffffffffffe + 5 + 1 = 4, CF=1; save CF via SETCS (preserves all flags!)
	LOCK; ADCQ $5, 80(DI)
	SETCS R9B

	// 9: LOCK; SBBQ $3, 88(DI) with CF=1 directly from ADCQ:
	//    10 - 3 - 1 = 6, CF=0; save CF via SETCS
	LOCK; SBBQ $3, 88(DI)
	SETCS R10B

	MOVBQZX R8B, AX
	SHLQ $4, AX
	ORQ AX, R12
	MOVBQZX R9B, AX
	SHLQ $5, AX
	ORQ AX, R12
	MOVBQZX R10B, AX
	SHLQ $6, AX
	ORQ AX, R12

	// 10: Narrow B/W/L variants on buf[12]..buf[13] (including reg bit-index for W and L)
	LOCK; ADDB $1, 96(DI)
	LOCK; SUBW $2, 98(DI)
	LOCK; XORL $3, 100(DI)
	MOVQ $4, CX
	LOCK; BTSW CX, 104(DI)
	MOVQ $1, CX
	LOCK; BTRL CX, 108(DI)

	MOVQ R12, ret+8(FP)
	RET
`
	f, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("parse x86 LOCK atomics: %v", err)
	}
	hostTriple := hostLLVMTriple()
	triple := "x86_64-unknown-linux-gnu"
	if hostTriple != "" {
		triple = hostTriple
	}
	ir, err := Translate(f, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8LockAtomics": {
				Name: "m8LockAtomics",
				Args: []LLVMType{Ptr},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate x86 LOCK atomics: %v", err)
	}
	for _, want := range []string{
		"atomicrmw add ptr",
		"atomicrmw sub ptr",
		"atomicrmw xor ptr",
		"atomicrmw or ptr",
		"atomicrmw and ptr",
		"cmpxchg ptr",
		"seq_cst seq_cst",
	} {
		if !strings.Contains(ir, want) {
			t.Fatalf("expected atomic IR %q for LOCK RMW, got:\n%s", want, ir)
		}
	}
	verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")

	if hostTriple != "" {
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern uint64_t m8LockAtomics(uint64_t *buf);

int main(void) {
	uint64_t buf[14] = {0};
	buf[0]  = (uint64_t)(-5LL);      // +10 => 5, CF=1 (bit0)
	buf[1]  = 3ULL;                  // -10 => -7, CF=1 (bit1)
	buf[2]  = 0x1234ULL;             // ^0xff => 0x12cb
	buf[3]  = 0x00abULL;             // |0x0f00 => 0x0fab, &0x0ff0 => 0x0fa0
	buf[4]  = 99ULL;                 // INC => 100
	buf[5]  = 1ULL;                  // DEC => 0, ZF=1 (bit2)
	buf[6]  = 0x10ULL;               // BTC 0 => 0x11
	buf[7]  = 0ULL;                  // BTS bit 67 from buf[6] => bit 3 of buf[7]=8, then BTR 3 => 0, CF=1 (bit3)
	buf[8]  = 42ULL;                 // NEG => -42, CF=1 (bit4)
	buf[9]  = 0x0f0fULL;             // NOT => ~0x0f0f (CF preserved = 1)
	buf[10] = 0xfffffffffffffffeULL; // ADC 5 + CF(1) => 4, CF=1 (bit5)
	buf[11] = 10ULL;                 // SBB 3 + CF(1) => 6, CF=0 (bit6=0)
	// buf[12]: byte0=10 -> 11; u16@2=10 -> 8; u32@4=5 -> 6
	((uint8_t*)&buf[12])[0] = 10;
	((uint16_t*)&buf[12])[1] = 10;
	((uint32_t*)&buf[12])[1] = 5;
	// buf[13]: u16@0=0 -> 0x10; u32@4=0x7 -> 0x5
	((uint16_t*)&buf[13])[0] = 0;
	((uint32_t*)&buf[13])[1] = 7;

	uint64_t flags = m8LockAtomics(buf);
	uint64_t wantFlags = 0x3fULL; // bits 0..5 set, bit 6 clear
	if (flags != wantFlags) {
		fprintf(stderr, "LOCK flags mismatch: got=0x%llx want=0x%llx\n", (unsigned long long)flags, (unsigned long long)wantFlags);
		return 1;
	}
	if (buf[0] != 5ULL || buf[1] != (uint64_t)(-7LL) || buf[2] != 0x12cbULL ||
		buf[3] != 0x0fa0ULL || buf[4] != 100ULL || buf[5] != 0ULL ||
		buf[6] != 0x11ULL || buf[7] != 0ULL || buf[8] != (uint64_t)(-42LL) ||
		buf[9] != ~0x0f0fULL || buf[10] != 4ULL || buf[11] != 6ULL) {
		fprintf(stderr, "LOCK qword mismatch\n");
		return 2;
	}
	if (((uint8_t*)&buf[12])[0] != 11 || ((uint16_t*)&buf[12])[1] != 8 || ((uint32_t*)&buf[12])[1] != 6 ||
		((uint16_t*)&buf[13])[0] != 0x10 || ((uint32_t*)&buf[13])[1] != 5) {
		fprintf(stderr, "LOCK narrow mismatch\n");
		return 3;
	}
	printf("M8_LOCK_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{ir}, mainC, "M8_LOCK_OK")
	}
}

func TestM8_AMD64DirectionFlagStringOpsDiffSemantics(t *testing.T) {
	src := `
// Backward overlapping memmove using STD; REP; MOVSB, then CLD; REP; MOVSB forward.
TEXT ·m8BackwardMovsb(SB), NOSPLIT, $0-24
	MOVQ dst+0(FP), DI
	MOVQ src+8(FP), SI
	MOVQ n+16(FP), CX
	STD
	REP; MOVSB
	CLD
	RET

// Backward REP; STOSW from high address downward.
TEXT ·m8BackwardStosw(SB), NOSPLIT, $0-24
	MOVQ dst+0(FP), DI
	MOVQ val+8(FP), AX
	MOVQ n+16(FP), CX
	STD
	REP; STOSW
	CLD
	RET

// Backward REPN; SCASB to find last occurrence of a byte (returns remaining CX).
TEXT ·m8BackwardScasb(SB), NOSPLIT, $0-32
	MOVQ endptr+0(FP), DI
	MOVQ needle+8(FP), AX
	MOVQ n+16(FP), CX
	STD
	REPN; SCASB
	CLD
	MOVQ CX, ret+24(FP)
	RET
`
	f, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("parse amd64 STD/CLD: %v", err)
	}
	hostTriple := hostLLVMTriple()
	triple := "x86_64-unknown-linux-gnu"
	if hostTriple != "" {
		triple = hostTriple
	}
	ir, err := Translate(f, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m8BackwardMovsb": {
				Name: "m8BackwardMovsb",
				Args: []LLVMType{Ptr, Ptr, I64},
				Ret:  Void,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: Ptr, Index: 1, Field: -1},
						{Offset: 16, Type: I64, Index: 2, Field: -1},
					},
				},
			},
			"m8BackwardStosw": {
				Name: "m8BackwardStosw",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  Void,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
						{Offset: 16, Type: I64, Index: 2, Field: -1},
					},
				},
			},
			"m8BackwardScasb": {
				Name: "m8BackwardScasb",
				Args: []LLVMType{Ptr, I64, I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
						{Offset: 16, Type: I64, Index: 2, Field: -1},
					},
					Results: []FrameSlot{{Offset: 24, Type: I64, Index: 0, Field: -1}},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("translate amd64 STD/CLD: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")

	if hostTriple != "" {
		mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern void m8BackwardMovsb(void *dst, void *src, uint64_t n);
extern void m8BackwardStosw(void *dst, uint64_t val, uint64_t n);
extern uint64_t m8BackwardScasb(void *endptr, uint64_t needle, uint64_t n);

int main(void) {
	// Overlapping right-shift by 2: "ABCDEFGH" -> copy 6 bytes from buf+5 to buf+7 backward => "ABABCDEF"
	char buf[9] = "ABCDEFGH";
	m8BackwardMovsb(buf + 7, buf + 5, 6);
	if (memcmp(buf, "ABABCDEF", 8) != 0) {
		fprintf(stderr, "STD REP MOVSB mismatch: got=%.8s want=ABABCDEF\n", buf);
		return 1;
	}
	// Backward STOSW: fill words[4], words[3], words[2], words[1] with 0xbeef
	uint16_t words[6] = {0x1111, 0, 0, 0, 0, 0x9999};
	m8BackwardStosw(&words[4], 0xbeef, 4);
	if (words[0] != 0x1111 || words[1] != 0xbeef || words[4] != 0xbeef || words[5] != 0x9999) {
		fprintf(stderr, "STD REP STOSW mismatch: %x %x %x %x\n", words[0], words[1], words[4], words[5]);
		return 2;
	}
	// Backward SCASB on "ab,cd,ef" (len 8, end at index 7): finds ',' at index 5 after 3 steps => rem CX = 5
	const char *s = "ab,cd,ef";
	uint64_t rem = m8BackwardScasb((void*)(s + 7), ',', 8);
	if (rem != 5ULL) {
		fprintf(stderr, "STD REPN SCASB mismatch: got=%llu want=5\n", (unsigned long long)rem);
		return 3;
	}
	printf("M8_DF_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{ir}, mainC, "M8_DF_OK")
	}
}

func TestM8_EdgeBranchesAndErrorPaths(t *testing.T) {
	// Exercise legitimate fallback paths, single-slot OpFP truncation/padding,
	// and error diagnostics introduced in M8 across amd64 and arm64.
	x86Sig := func(name string) map[string]FuncSig {
		return map[string]FuncSig{
			name: {
				Name: name,
				Args: []LLVMType{I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I64, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 8, Type: I64, Index: 0, Field: -1}},
				},
			},
		}
	}

	// 1. Valid fallback & single-slot cases on amd64:
	//    - LOCK before non-memory/non-RMW ops falls through to regular lowering
	//    - VMOVDQU store into single 8-byte FP slot writes available slot cleanly
	x86Valid := `
TEXT ·m8X86ValidEdges(SB), NOSPLIT, $0-16
	LOCK; NOP
	LOCK; ADDQ $1, AX
	LOCK; INCQ AX
	LOCK; BTSQ $1, AX
	LOCK; NEGQ AX
	VMOVDQU X0, ret+8(FP)
	RET
`
	f, err := Parse(ArchAMD64, x86Valid)
	if err != nil {
		t.Fatalf("parse x86 valid edges: %v", err)
	}
	ir, err := Translate(f, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         x86Sig("m8X86ValidEdges"),
	})
	if err != nil {
		t.Fatalf("translate x86 valid edges: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")

	// 2. amd64 error diagnostics for invalid OpFP / segment-relative LOCK targets.
	x86ErrCases := []string{
		"VMOVDQU X0, bad+999(FP)",
		"BTSQ $1, bad+999(FP)",
		"LOCK; ADDQ $1, bad+999(FP)",
		"LOCK; ADDQ $1, 0(FS)",
		"LOCK; INCQ 0(FS)",
		"LOCK; BTSQ $1, 0(FS)",
		"LOCK; NEGQ 0(FS)",
		"LOCK; ADCQ $1, 0(FS)",
	}
	for _, body := range x86ErrCases {
		src := "TEXT ·m8Err(SB), NOSPLIT, $0-16\n\t" + body + "\n\tRET\n"
		pf, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatalf("parse %q: %v", body, err)
		}
		if _, err := Translate(pf, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         x86Sig("m8Err"),
		}); err == nil {
			t.Fatalf("expected translation error for %q", body)
		}
	}
	// Exercise loadFPVec error propagation via an unsupported aggregate FP param type.
	badFPSig := map[string]FuncSig{
		"m8BadVecFP": {
			Name:  "m8BadVecFP",
			Args:  []LLVMType{LLVMType("[2 x i64]")},
			Ret:   Void,
			Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: LLVMType("[2 x i64]"), Index: 0, Field: -1}}},
		},
	}
	for _, body := range []string{
		"VMOVDQU64 a+0(FP), Z0",
		"VMOVDQU a+0(FP), Y0",
		"VMOVDQU a+0(FP), X0",
	} {
		src := "TEXT ·m8BadVecFP(SB), NOSPLIT, $0-16\n\t" + body + "\n\tRET\n"
		pf, err := Parse(ArchAMD64, src)
		if err != nil {
			t.Fatalf("parse %q: %v", body, err)
		}
		if _, err := Translate(pf, Options{
			TargetTriple: "x86_64-unknown-linux-gnu",
			Goarch:       "amd64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         badFPSig,
		}); err == nil {
			t.Fatalf("expected translation error for %q", body)
		}
	}

	// 3. arm64 single-slot FMOVQ OpFP load/store + error diagnostics.
	a64Single := `
TEXT ·m8A64Single(SB), NOSPLIT, $0-16
	FMOVQ a+0(FP), F0
	FMOVQ F0, ret+8(FP)
	LDP   a+0(FP), (R1, R2)
	RET
`
	fA64, err := Parse(ArchARM64, a64Single)
	if err != nil {
		t.Fatalf("parse arm64 single: %v", err)
	}
	irA64, err := Translate(fA64, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs:         x86Sig("m8A64Single"),
	})
	if err != nil {
		t.Fatalf("translate arm64 single: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irA64, "aarch64-unknown-linux-gnu")

	a64ErrCases := []string{
		"FMOVQ a+0(FP), R1",
		"FMOVQ bad+999(FP), F0",
		"FMOVQ R1, ret+8(FP)",
		"FMOVQ F0, bad+999(FP)",
		"LDPW bad+999(FP), (R1, R2)",
		"STPW (R1, R2), bad+999(FP)",
	}
	for _, body := range a64ErrCases {
		src := "TEXT ·m8A64Err(SB), NOSPLIT, $0-16\n\t" + body + "\n\tRET\n"
		pf, err := Parse(ArchARM64, src)
		if err != nil {
			t.Fatalf("parse %q: %v", body, err)
		}
		if _, err := Translate(pf, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
			Sigs:         x86Sig("m8A64Err"),
		}); err == nil {
			t.Fatalf("expected translation error for %q", body)
		}
	}
}
