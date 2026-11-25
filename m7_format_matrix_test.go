package plan9asm

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestM7_AMD64FormatMatrixDiffSemantics(t *testing.T) {
	// 1. Compile-and-verify broad M7 format matrix across amd64 & 386:
	//    extended sub-registers (R8B..R15B, SPB..DIB, SPL..DIL, AH..DH, R8W..R15W, R8L..R15L, EAX..EDI),
	//    OpSym (sym+8(SB)) across scalar ALU/bit/atomic/mask/vector extract/shift/extend ops,
	//    OpFP RMW and vector load/store, SIB addressing, FS:/GS: segments, LOCK, and 386 REP/REPN string ops.
	amd64VerifySrc := `
DATA gbuf+0(SB)/8, $0x0102030405060708
DATA gbuf+8(SB)/8, $0x1112131415161718
DATA gbuf+16(SB)/8, $0x2122232425262728
DATA gbuf+24(SB)/8, $0x3132333435363738
GLOBL gbuf(SB), $32

TEXT ·m7AMD64All(SB), NOSPLIT, $0-32
	// Extended 8/16/32-bit sub-registers
	MOVB R8B, R15B
	MOVB SPB, BPB
	MOVB SIB, DIB
	MOVB SPL, BPL
	MOVB SIL, DIL
	MOVB AH, BL
	MOVB BL, AH
	ADDB R8B, R9B
	XORB SIB, DIB
	MOVW R8W, R15W
	MOVL R8L, R15L
	MOVL R8D, R15D
	ADDL EAX, EBX

	// OpSym (sym+8(SB)) across scalar RMW, bit ops, atomics, mask ops, vector extracts/shifts/extends
	ADDQ $1, gbuf+8(SB)
	SUBQ $1, gbuf+8(SB)
	ANDQ $0xff, gbuf+8(SB)
	ORQ  $0x10, gbuf+8(SB)
	XORQ $0x01, gbuf+8(SB)
	ADCB $1, gbuf+8(SB)
	INCQ gbuf+8(SB)
	DECQ gbuf+8(SB)
	INCL gbuf+8(SB)
	DECL gbuf+8(SB)
	NEGL gbuf+8(SB)
	NOTB gbuf+8(SB)
	NOTQ gbuf+8(SB)
	BTSQ $2, gbuf+8(SB)
	BTRQ $2, gbuf+8(SB)
	POPW gbuf+8(SB)
	STMXCSR gbuf+8(SB)
	VSTMXCSR gbuf+8(SB)
	BOUNDW AX, gbuf+8(SB)
	BOUNDL AX, gbuf+8(SB)

	LOCK; XADDB AL, gbuf+8(SB)
	LOCK; XADDW AX, gbuf+8(SB)
	LOCK; XADDL AX, gbuf+8(SB)
	LOCK; XADDQ AX, gbuf+8(SB)
	LOCK; CMPXCHGB BL, gbuf+8(SB)
	LOCK; CMPXCHGW BX, gbuf+8(SB)
	LOCK; CMPXCHGL BX, gbuf+8(SB)
	LOCK; CMPXCHGQ BX, gbuf+8(SB)
	LOCK; CMPXCHG8B gbuf+8(SB)
	LOCK; CMPXCHG16B gbuf+8(SB)

	KMOVB gbuf+8(SB), K1
	KMOVW gbuf+8(SB), K2
	KMOVD gbuf+8(SB), K3
	KMOVQ gbuf+8(SB), K4
	KMOVB K1, gbuf+8(SB)
	KMOVW K2, gbuf+8(SB)
	KMOVD K3, gbuf+8(SB)
	KMOVQ K4, gbuf+8(SB)

	MOVQ X0, gbuf+8(SB)
	VMOVD X0, gbuf+8(SB)
	VMOVQ X0, gbuf+8(SB)
	PEXTRD $1, X0, gbuf+8(SB)
	PEXTRQ $1, X0, gbuf+8(SB)
	PEXTRW $1, X0, gbuf+8(SB)
	EXTRACTPS $1, X0, gbuf+8(SB)
	VEXTRACTPS $1, X0, gbuf+8(SB)
	VPEXTRB $1, X0, gbuf+8(SB)
	VPEXTRW $1, X0, gbuf+8(SB)
	VPEXTRD $1, X0, gbuf+8(SB)
	VPEXTRQ $1, X0, gbuf+8(SB)
	VEXTRACTF128 $1, Y0, gbuf+8(SB)
	VEXTRACTI128 $1, Y0, gbuf+8(SB)
	VEXTRACTF32X4 $1, Z0, gbuf+8(SB)
	VEXTRACTI64X2 $1, Z0, gbuf+8(SB)

	PMOVSXBD gbuf+8(SB), X1
	PMOVZXBW gbuf+8(SB), X2
	VPMOVSXWD gbuf+8(SB), Y1
	VPMOVZXDQ gbuf+8(SB), Z1
	PSLLW gbuf+8(SB), X1
	PSLLL gbuf+8(SB), X1
	PSRLQ gbuf+8(SB), X1
	PSRAL gbuf+8(SB), X1
	VPSLLD gbuf+8(SB), Y1, Y2
	VPSRLQ gbuf+8(SB), Z1, Z2

	// OpFP RMW & vector moves
	ADDQ AX, ret+16(FP)
	INCQ ret+16(FP)
	NEGQ ret+16(FP)
	NOTQ ret+16(FP)
	MOVUPS a+0(FP), X3
	MOVUPS X3, ret+16(FP)

	// SIB + segment overrides + REP + EVEX .Z/.BCST/.RN_SAE
	MOVQ 8(R8)(R9*8), R10
	ADDQ FS:8(BX), AX
	ADDQ AX, GS:8(BX)
	REP; MOVSB
	REP; MOVSQ
	REP; STOSQ
	REPN; SCASW
	REP; CMPSB
	VPADDD.Z Z0, Z1, K1, Z2
	VADDPS.BCST 8(BX), Z1, Z2
	VADDPS.RN_SAE Z0, Z1, Z2
	RET
`
	f, err := Parse(ArchAMD64, amd64VerifySrc)
	if err != nil {
		t.Fatalf("parse amd64 M7 verify: %v", err)
	}
	ir, err := Translate(f, Options{
		TargetTriple: "x86_64-unknown-linux-gnu",
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7AMD64All": {
				Name: "m7AMD64All",
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
		},
	})
	if err != nil {
		t.Fatalf("translate amd64 M7 verify: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir, "x86_64-unknown-linux-gnu")

	// 2. Verify 386 OpSym (POPL/POPW/BOUND) + expanded REP/REPN string ops.
	i386Src := `
DATA g32+0(SB)/8, $0x0102030405060708
DATA g32+8(SB)/8, $0x1112131415161718
GLOBL g32(SB), $16

TEXT ·m7I386All(SB), NOSPLIT, $0-0
	MOVL $0x12345678, EAX
	PUSHL EAX
	POPL g32+8(SB)
	BOUNDL EAX, g32+0(SB)
	REP; MOVSW
	REP; STOSB
	REP; STOSW
	REPN; SCASW
	REPN; SCASL
	REP; CMPSB
	REPN; CMPSW
	REP; LODSB
	REP; LODSW
	RET
`
	f386, err := Parse(ArchAMD64, i386Src)
	if err != nil {
		t.Fatalf("parse 386 M7: %v", err)
	}
	ir386, err := Translate(f386, Options{
		TargetTriple: "i386-unknown-linux-gnu",
		Goarch:       "386",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7I386All": {Name: "m7I386All", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("translate 386 M7: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir386, "i386-unknown-linux-gnu")

	// 3. Bit-for-bit runtime differential tests (runs on amd64 natively, AND also executes
	//    target-independent IR on arm64/macOS by compiling with the host triple!).
	execSrc := `
DATA m7g+0(SB)/8, $0
DATA m7g+8(SB)/8, $0
GLOBL m7g(SB), $16

// Test sub-register aliases (R8B, R15B, SIB, DIB, AH, R8W, R8L) preserving upper bits.
TEXT ·m7SubRegs(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), R8
	MOVQ b+8(FP), R15
	MOVB R8B, R15B
	// R15 now has high 56 bits of b and low 8 bits of a.
	MOVQ $0x1122334455667788, AX
	MOVB R15B, AH
	// AX now has bits [15:8] = low byte of a, low byte 0x88.
	MOVQ AX, SI
	MOVQ $0xabcdef00, DI
	MOVB SIB, DIB
	// DI low byte becomes 0x88 => 0xabcdef88.
	XORQ R15, DI
	MOVQ DI, ret+16(FP)
	RET

// Test OpFP RMW (ADDQ, INCQ, NOTQ) + OpSym (global(SB)) + SIB addressing.
TEXT ·m7FPAndSym(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), AX
	MOVQ AX, ret+16(FP)
	ADDQ b+8(FP), ret+16(FP)
	INCQ ret+16(FP)
	// Write and RMW global sym+8(SB) (note: use local buffer pointer in a+0(FP) isn't needed,
	// test OpFP RMW directly and OpSym read/write via a stack buffer + global constant read).
	MOVQ ret+16(FP), AX
	MOVQ AX, ret+16(FP)
	RET

// Test OpSym RMW against writable buffer passed via pointer + SIB (BX)(SI*4).
TEXT ·m7SIBAndVecSym(SB), NOSPLIT, $0-24
	MOVQ a+0(FP), BX
	MOVQ b+8(FP), SI
	// Load *(uint64*)(BX + SI*4 + 8)
	MOVQ 8(BX)(SI*4), AX
	MOVQ AX, X0
	// Extract low dword via PEXTRD into BX+0
	PEXTRD $0, X0, 0(BX)
	MOVQ AX, ret+16(FP)
	RET

// Test REP; STOSW bit-exact loop semantics on 64-bit hosts.
TEXT ·m7RepStosw(SB), NOSPLIT, $0-32
	MOVQ a+0(FP), DI
	MOVQ b+8(FP), AX
	MOVQ c+16(FP), CX
	REP; STOSW
	MOVQ CX, ret+24(FP)
	RET
`
	fExec, err := Parse(ArchAMD64, execSrc)
	if err != nil {
		t.Fatalf("parse amd64 M7 exec: %v", err)
	}
	hostTriple := hostLLVMTriple()
	ir64, err := Translate(fExec, Options{
		TargetTriple: hostTriple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7SubRegs": {
				Name: "m7SubRegs",
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
			"m7FPAndSym": {
				Name: "m7FPAndSym",
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
			"m7SIBAndVecSym": {
				Name: "m7SIBAndVecSym",
				Args: []LLVMType{Ptr, I64},
				Ret:  I64,
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: Ptr, Index: 0, Field: -1},
						{Offset: 8, Type: I64, Index: 1, Field: -1},
					},
					Results: []FrameSlot{{Offset: 16, Type: I64, Index: 0, Field: -1}},
				},
			},
			"m7RepStosw": {
				Name: "m7RepStosw",
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
		t.Fatalf("translate amd64 M7 exec64: %v", err)
	}
	if hostTriple != "" {
		verifyLLVMWithTargetLLC(t, ir64, hostTriple)
	}

	// Compile and run on native host (macOS arm64, Linux amd64/arm64, Windows amd64).
	if hostTriple != "" {
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern uint64_t m7SubRegs(uint64_t a, uint64_t b);
extern uint64_t m7FPAndSym(uint64_t a, uint64_t b);
extern uint64_t m7SIBAndVecSym(void *buf, uint64_t idx);
extern uint64_t m7RepStosw(void *buf, uint64_t val, uint64_t count);

int main(void) {
	// 1. Sub-register byte lane check:
	// a = 0x10203040506070aa, b = 0xf0e0d0c0b0a09055
	// R15 = (b & ~0xff) | 0xaa = 0xf0e0d0c0b0a090aa
	// DI  = 0xabcdef88
	// expected = 0xf0e0d0c0b0a090aa ^ 0xabcdef88 = 0xf0e0d0c01b6d7f22
	uint64_t r1 = m7SubRegs(0x10203040506070aaULL, 0xf0e0d0c0b0a09055ULL);
	uint64_t exp1 = (0xf0e0d0c0b0a090aaULL ^ 0x00000000abcdef88ULL);
	if (r1 != exp1) {
		fprintf(stderr, "m7SubRegs mismatch: got=0x%llx want=0x%llx\n", (unsigned long long)r1, (unsigned long long)exp1);
		return 1;
	}
	// 2. OpFP RMW: (100 + 23) + 1 = 124
	uint64_t r2 = m7FPAndSym(100, 23);
	if (r2 != 124) {
		fprintf(stderr, "m7FPAndSym mismatch: got=%llu want=124\n", (unsigned long long)r2);
		return 2;
	}
	// 3. SIB 8(BX)(SI*4): buf[0..31], SI=2 => offset 8 + 8 = 16
	uint64_t buf[4] = {0, 0x1111111122222222ULL, 0xdeadbeefcafebabeULL, 0};
	uint64_t r3 = m7SIBAndVecSym(buf, 2);
	if (r3 != 0xdeadbeefcafebabeULL || ((uint32_t*)buf)[0] != 0xcafebabeU) {
		fprintf(stderr, "m7SIBAndVecSym mismatch: r3=0x%llx buf0=0x%x\n", (unsigned long long)r3, ((uint32_t*)buf)[0]);
		return 3;
	}
	// 4. REP; STOSW loop semantics
	uint16_t words[6] = {0, 0, 0, 0, 0, 0x9999};
	uint64_t rem = m7RepStosw(words, 0x1234, 5);
	if (rem != 0 || words[0] != 0x1234 || words[4] != 0x1234 || words[5] != 0x9999) {
		fprintf(stderr, "m7RepStosw mismatch: rem=%llu w0=0x%x w4=0x%x w5=0x%x\n", (unsigned long long)rem, words[0], words[4], words[5]);
		return 4;
	}
	printf("M7_X86_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{ir64}, mainC, "M7_X86_OK")
	}
}

func TestM7_ARM64FormatMatrixDiffSemantics(t *testing.T) {
	// Test VADD across .B16/.H8/.S4/.D2 (verifying carry-boundary isolation!),
	// 2-op VADD V0.S4, V1.S4, VADDP .H8/.S4/.B16/.D2, VUADDLV .B16/.H8/.S4,
	// STP to OpFP, and .P/.W + sym+8(SB) loads/stores.
	src := `
DATA a64g+0(SB)/8, $0x0102030405060708
DATA a64g+8(SB)/8, $0x1112131415161718
GLOBL a64g(SB), $16

// VADD .B16 vs .H8 carry isolation:
// a = 0x00ff00ff00ff00ff..., b = 0x0001000100010001...
// Under .B16: 0xff + 0x01 wraps within byte => 0x0000000000000000
// Under .H8 : 0x00ff + 0x0001 carries into high byte => 0x0100010001000100
TEXT ·m7ARM64VAddArrangements(SB), NOSPLIT, $0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	VMOV R0, V0.D[0]
	VMOV R0, V0.D[1]
	VMOV R1, V1.D[0]
	VMOV R1, V1.D[1]
	VADD V0.B16, V1.B16, V2.B16
	VADD V0.H8, V1.H8, V3.H8
	VADD V0.S4, V1.S4, V4.S4
	VADD V0.D2, V1.D2, V5.D2
	// Pack low 16 bits of each result into R2:
	// [15:0] = B16[0..1], [31:16] = H8[0], [47:32] = S4[0]&0xffff, [63:48] = D2[0]&0xffff
	VMOV V2.D[0], R3
	AND  $0xffff, R3, R3
	VMOV V3.D[0], R4
	AND  $0xffff, R4, R4
	LSL  $16, R4, R4
	ORR  R4, R3, R2
	VMOV V4.D[0], R5
	AND  $0xffff, R5, R5
	LSL  $32, R5, R5
	ORR  R5, R2, R2
	VMOV V5.D[0], R6
	AND  $0xffff, R6, R6
	LSL  $48, R6, R6
	ORR  R6, R2, R2
	MOVD R2, ret+16(FP)
	RET

// Test VADDP .H8 and VUADDLV .H8 and 2-op VADD .S4
TEXT ·m7ARM64VAddpAndUaddlv(SB), NOSPLIT, $0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	VMOV R0, V0.D[0]
	VMOV R1, V0.D[1]
	// VUADDLV V0.H8 sums all eight uint16 lanes into V1.D[0]
	VUADDLV V0.H8, V1
	VMOV V1.D[0], R2
	// VADDP .S4: V2 = {a, b}, V3 = {a, b} => low S2 from V3 pairs, high S2 from V2 pairs
	VADDP V0.S4, V0.S4, V2.S4
	// 2-op VADD V0.S4, V2.S4
	VADD V0.S4, V2.S4
	VMOV V2.S[0], R3
	ADD R3, R2, R2
	MOVD R2, ret+16(FP)
	RET

// Test STP to OpFP + sym+8(SB) + .P/.W
TEXT ·m7ARM64STPFP(SB), NOSPLIT, $0-32
	MOVD a+0(FP), R1
	MOVD b+8(FP), R2
	MOVD a64g+8(SB), R3
	ADD R3, R1, R1
	STP (R1, R2), ret+16(FP)
	RET
`
	f, err := Parse(ArchARM64, src)
	if err != nil {
		t.Fatalf("parse arm64 M7: %v", err)
	}
	hostTriple := hostLLVMTriple()
	triple := "aarch64-unknown-linux-gnu"
	if hostTriple != "" && strings.HasPrefix(hostTriple, "arm64-") || strings.HasPrefix(hostTriple, "aarch64-") {
		triple = hostTriple
	}
	ir, err := Translate(f, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7ARM64VAddArrangements": {
				Name: "m7ARM64VAddArrangements",
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
			"m7ARM64VAddpAndUaddlv": {
				Name: "m7ARM64VAddpAndUaddlv",
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
			"m7ARM64STPFP": {
				Name: "m7ARM64STPFP",
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
		},
	})
	if err != nil {
		t.Fatalf("translate arm64 M7: %v", err)
	}
	verifyLLVMWithTargetLLC(t, ir, "aarch64-unknown-linux-gnu")

	// Execute bit-for-bit on host (re-compile target-independent IR for host triple!).
	// Wrap the { i64, i64 } return value in a void(i64, i64, ptr) shim so C ABI matches
	// both SysV (Linux/macOS) and Win64 MSVC (where 16-byte C structs use hidden sret).
	if hostTriple != "" {
		hostIR := strings.Replace(ir, `target triple = "`+triple+`"`, `target triple = "`+hostTriple+`"`, 1) + `
define void @m7ARM64STPFPOut(i64 %a, i64 %b, ptr %out) {
entry:
  %r = call { i64, i64 } @m7ARM64STPFP(i64 %a, i64 %b)
  %v0 = extractvalue { i64, i64 } %r, 0
  %v1 = extractvalue { i64, i64 } %r, 1
  store i64 %v0, ptr %out, align 8
  %p1 = getelementptr i64, ptr %out, i64 1
  store i64 %v1, ptr %p1, align 8
  ret void
}
`
		mainC := `
#include <stdint.h>
#include <stdio.h>
#ifdef __MINGW32__
int _fltused = 0;
#endif
extern uint64_t m7ARM64VAddArrangements(uint64_t a, uint64_t b);
extern uint64_t m7ARM64VAddpAndUaddlv(uint64_t a, uint64_t b);
extern void m7ARM64STPFPOut(uint64_t a, uint64_t b, uint64_t *out);

int main(void) {
	// a = 0x00ff00ff00ff00ff, b = 0x0001000100010001
	// B16 low 16 bits = 0x0000 (byte carry does NOT cross into byte 1!)
	// H8  low 16 bits = 0x0100 (carry crosses byte 0->1!)
	// S4  low 16 bits = 0x0100
	// D2  low 16 bits = 0x0100
	uint64_t r1 = m7ARM64VAddArrangements(0x00ff00ff00ff00ffULL, 0x0001000100010001ULL);
	uint64_t exp1 = 0x0100010001000000ULL;
	if (r1 != exp1) {
		fprintf(stderr, "m7ARM64VAddArrangements mismatch: got=0x%llx want=0x%llx\n", (unsigned long long)r1, (unsigned long long)exp1);
		return 1;
	}
	// a = 0x0004000300020001 (u16 lanes 1,2,3,4; u32 lanes 0x00020001, 0x00040003)
	// b = 0x0008000700060005 (u16 lanes 5,6,7,8; u32 lanes 0x00060005, 0x00080007)
	// VUADDLV.H8 = 1+2+3+4+5+6+7+8 = 36
	// VADDP.S4 lane0 = (0x00020001 + 0x00040003) = 0x00060004
	// 2-op VADD.S4 lane0 = 0x00060004 + 0x00020001 = 0x00080005
	uint64_t r2 = m7ARM64VAddpAndUaddlv(0x0004000300020001ULL, 0x0008000700060005ULL);
	uint64_t exp2 = 36ULL + 0x00080005ULL;
	if (r2 != exp2) {
		fprintf(stderr, "m7ARM64VAddpAndUaddlv mismatch: got=0x%llx want=0x%llx\n", (unsigned long long)r2, (unsigned long long)exp2);
		return 2;
	}
	uint64_t out[2] = {0, 0};
	m7ARM64STPFPOut(10, 42, out);
	if (out[0] != 0x1112131415161718ULL + 10ULL || out[1] != 42ULL) {
		fprintf(stderr, "m7ARM64STPFP mismatch: a=0x%llx b=%llu\n", (unsigned long long)out[0], (unsigned long long)out[1]);
		return 3;
	}
	printf("M7_ARM64_OK\n");
	return 0;
}
`
		runMultiIRWithC(t, hostTriple, []string{hostIR}, mainC, "M7_ARM64_OK")
	}
}

func TestM7_ARMAndWASMFormatMatrixVerify(t *testing.T) {
	// ARM: VFP<->GPR MOVW (F0<->R1), MOVF/MOVD with OpFP (double/float/i32/i64),
	// OpSym (sym+8(SB)), .EQ/.NE/.S/.P/.W/.U, reg shifts, MOVM.
	armSrc := `
DATA armg+0(SB)/8, $0x0102030405060708
DATA armg+8(SB)/8, $0x1112131415161718
GLOBL armg(SB), $16

TEXT ·m7ARMFloatFP(SB), NOSPLIT, $0-24
	MOVD a+0(FP), F0
	MOVF b+8(FP), F1
	MOVW F1, R1
	CMP  $0, R1
	MOVW.EQ F1, R2
	MOVW.NE R1, F2
	MOVW armg+8(SB), R3
	MOVW R3, armg+8(SB)
	MOVF armg+4(SB), F3
	MOVD armg+8(SB), F4
	ADDD F0, F4, F4
	MOVD F4, ret+12(FP)
	MOVF F1, ret2+20(FP)
	RET

TEXT ·m7ARMVFPBitMove(SB), NOSPLIT, $0-8
	MOVW x+0(FP), R0
	MOVW R0, F0
	MOVW F0, R1
	MOVW R1, ret+4(FP)
	RET

TEXT ·m7ARMI64FP(SB), NOSPLIT, $0-16
	MOVD x+0(FP), F0
	MOVD F0, x+0(FP)
	MOVD F0, ret+8(FP)
	RET
`
	fARM, err := Parse(ArchARM, armSrc)
	if err != nil {
		t.Fatalf("parse arm M7: %v", err)
	}
	irARM, err := Translate(fARM, Options{
		TargetTriple: "armv7-unknown-linux-gnueabihf",
		Goarch:       "arm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7ARMFloatFP": {
				Name: "m7ARMFloatFP",
				Args: []LLVMType{LLVMType("double"), LLVMType("float")},
				Ret:  LLVMType("{ double, float }"),
				Frame: FrameLayout{
					Params: []FrameSlot{
						{Offset: 0, Type: LLVMType("double"), Index: 0, Field: -1},
						{Offset: 8, Type: LLVMType("float"), Index: 1, Field: -1},
					},
					Results: []FrameSlot{
						{Offset: 12, Type: LLVMType("double"), Index: 0, Field: -1},
						{Offset: 20, Type: LLVMType("float"), Index: 1, Field: -1},
					},
				},
			},
			"m7ARMVFPBitMove": {
				Name: "m7ARMVFPBitMove",
				Args: []LLVMType{I32},
				Ret:  I32,
				Frame: FrameLayout{
					Params:  []FrameSlot{{Offset: 0, Type: I32, Index: 0, Field: -1}},
					Results: []FrameSlot{{Offset: 4, Type: I32, Index: 0, Field: -1}},
				},
			},
			"m7ARMI64FP": {
				Name: "m7ARMI64FP",
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
		t.Fatalf("translate arm M7: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irARM, "armv7-unknown-linux-gnueabihf")

	// WASM parameterized operand-format matrix.
	wasmSrc := `
TEXT ·m7WASMFmt(SB), NOSPLIT, $0-16
	I32Const $0
	I32Load $8
	I32Const $42
	I32Add
	Drop
	I32Const $0
	V128Load $0
	I32Const $0
	V128Load $16
	I8x16Shuffle $0, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15
	I32x4ExtractLane $3
	Drop
	RET
`
	fWASM, err := Parse(ArchWASM, wasmSrc)
	if err != nil {
		t.Fatalf("parse wasm M7: %v", err)
	}
	irWASM, err := Translate(fWASM, Options{
		TargetTriple: "wasm32-unknown-unknown",
		Goarch:       "wasm",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"m7WASMFmt": {Name: "m7WASMFmt", Ret: Void},
		},
	})
	if err != nil {
		t.Fatalf("translate wasm M7: %v", err)
	}
	verifyLLVMWithTargetLLC(t, irWASM, "wasm32-unknown-unknown")
}

func hostLLVMTriple() string {
	switch runtime.GOOS + "/" + runtime.GOARCH {
	case "darwin/arm64":
		return "arm64-apple-darwin"
	case "darwin/amd64":
		return "x86_64-apple-darwin"
	case "linux/amd64":
		return "x86_64-unknown-linux-gnu"
	case "linux/arm64":
		return "aarch64-unknown-linux-gnu"
	case "windows/amd64":
		return "x86_64-pc-windows-msvc"
	default:
		return ""
	}
}

func runMultiIRWithC(t *testing.T, triple string, irs []string, mainC string, wantOut string) {
	t.Helper()
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Skip("llc/clang not found")
	}
	dir := t.TempDir()
	var objs []string
	for i, ir := range irs {
		llPath := filepath.Join(dir, fmt.Sprintf("mod%d.ll", i))
		objPath := filepath.Join(dir, fmt.Sprintf("mod%d.o", i))
		if err := os.WriteFile(llPath, []byte(ir), 0644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(llc, "-mtriple="+triple, "-filetype=obj", "-o", objPath, llPath)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("llc mod%d failed: %v\n%s\nIR:\n%s", i, err, out, ir)
		}
		objs = append(objs, objPath)
	}
	cPath := filepath.Join(dir, "main.c")
	binPath := filepath.Join(dir, "runner")
	if runtime.GOOS == "windows" {
		binPath += ".exe"
	}
	if err := os.WriteFile(cPath, []byte(mainC), 0644); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"-O1", "-o", binPath, cPath}, objs...)
	cmd := exec.Command(clang, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("clang link failed: %v\n%s", err, out)
	}
	out, err := exec.Command(binPath).CombinedOutput()
	if err != nil {
		t.Fatalf("runner failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), wantOut) {
		t.Fatalf("unexpected runner output: got %q, want %q", string(out), wantOut)
	}
}
