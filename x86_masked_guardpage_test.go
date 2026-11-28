//go:build unix && !llgo

package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

// TestX86MaskedMemoryGuardPage executes LLVM-compiled x86 EVEX masked loads,
// stores, compress, expand, extract, scalar moves, and masked ALU memory-source
// instructions directly against PROT_NONE guard pages. Masked-off lanes MUST
// NOT read or write memory; touching them triggers SIGSEGV/SIGBUS.
func TestX86MaskedMemoryGuardPage(t *testing.T) {
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	llc, clang := requireLlcAndClang(t)

	src := `
// 1. VMOVDQU32 Z0, K1, (AX): masked store of 32-bit lanes
TEXT ·maskedStore32(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ val+16(FP), CX
	KMOVW BX, K1
	VPBROADCASTD CX, Z0
	VMOVDQU32 Z0, K1, (AX)
	RET

// 2. VMOVDQU32 (AX), K1, Z0 (merge) and VMOVDQU32.Z (AX), K1, Z0 (zero)
TEXT ·maskedLoad32Merge(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ out+16(FP), DX
	KMOVW BX, K1
	MOVL $0x11111111, CX
	VPBROADCASTD CX, Z0
	VMOVDQU32 (AX), K1, Z0
	VMOVDQU32 Z0, (DX)
	RET

TEXT ·maskedLoad32Zero(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ out+16(FP), DX
	KMOVW BX, K1
	MOVL $0x22222222, CX
	VPBROADCASTD CX, Z0
	VMOVDQU32.Z (AX), K1, Z0
	VMOVDQU32 Z0, (DX)
	RET

// 3. Sibling widths: VMOVDQU8, VMOVDQU16, VMOVDQU64, VMOVUPS, VMOVUPD
TEXT ·maskedStore8(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ val+16(FP), CX
	KMOVQ BX, K1
	VPBROADCASTB CX, Z0
	VMOVDQU8 Z0, K1, (AX)
	RET

TEXT ·maskedStore64(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ val+16(FP), CX
	KMOVB BX, K1
	VPBROADCASTQ CX, Z0
	VMOVDQU64 Z0, K1, (AX)
	RET

TEXT ·maskedStorePS(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ val+16(FP), CX
	KMOVW BX, K1
	VPBROADCASTD CX, Z0
	VMOVUPS Z0, K1, (AX)
	RET

// 4. VPCOMPRESSD Z0, K1, (AX): contiguous masked store of active lanes only
TEXT ·maskedCompress32(SB),NOSPLIT,$0-24
	MOVQ src+0(FP), SI
	MOVQ dst+8(FP), AX
	MOVQ mask+16(FP), BX
	KMOVW BX, K1
	VMOVDQU32 (SI), Z0
	VPCOMPRESSD Z0, K1, (AX)
	RET

// 5. VPEXPANDD (AX), K1, Z0: contiguous masked load of popcount(K1) lanes only
TEXT ·maskedExpand32(SB),NOSPLIT,$0-24
	MOVQ src+0(FP), AX
	MOVQ out+8(FP), DX
	MOVQ mask+16(FP), BX
	KMOVW BX, K1
	VPEXPANDD.Z (AX), K1, Z0
	VMOVDQU32 Z0, (DX)
	RET

// 6. VEXTRACTI32X4 $0, Z0, K1, (AX): masked sub-vector store
TEXT ·maskedExtract32x4(SB),NOSPLIT,$0-24
	MOVQ src+0(FP), SI
	MOVQ dst+8(FP), AX
	MOVQ mask+16(FP), BX
	KMOVB BX, K1
	VMOVDQU32 (SI), Z0
	VEXTRACTI32X4 $0, Z0, K1, (AX)
	RET

// 7. VPADDD (AX), Z1, K1, Z2: masked ALU memory-source read
TEXT ·maskedAddMem32(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ out+16(FP), DX
	KMOVW BX, K1
	MOVL $100, CX
	VPBROADCASTD CX, Z1
	MOVL $777, CX
	VPBROADCASTD CX, Z2
	VPADDD (AX), Z1, K1, Z2
	VMOVDQU32 Z2, (DX)
	RET

// 8. Scalar masked VMOVSS store & load with K1=0 on guard page
TEXT ·maskedScalarSS(SB),NOSPLIT,$0-24
	MOVQ ptr+0(FP), AX
	MOVQ mask+8(FP), BX
	MOVQ out+16(FP), DX
	KMOVB BX, K1
	MOVL $0x3f800000, CX
	VPBROADCASTD CX, X0
	VMOVSS X0, K1, (AX)
	MOVL $0x40000000, CX
	VPBROADCASTD CX, X1
	VMOVSS (AX), K1, X1
	VMOVUPS X1, (DX)
	RET
`
	file, err := Parse(ArchAMD64, src)
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	sig3 := func(name string) FuncSig {
		return FuncSig{
			Name: name,
			Args: []LLVMType{Ptr, I64, I64},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}
	}
	sigPtrPtrI64 := func(name string) FuncSig {
		return FuncSig{
			Name: name,
			Args: []LLVMType{Ptr, Ptr, I64},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}
	}
	sigPtrI64Ptr := func(name string) FuncSig {
		return FuncSig{
			Name: name,
			Args: []LLVMType{Ptr, I64, Ptr},
			Ret:  Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}
	}
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "amd64",
		ResolveSym:   func(s string) string { return strings.TrimPrefix(s, "·") },
		Sigs: map[string]FuncSig{
			"maskedStore32":     sig3("maskedStore32"),
			"maskedLoad32Merge": sigPtrI64Ptr("maskedLoad32Merge"),
			"maskedLoad32Zero":  sigPtrI64Ptr("maskedLoad32Zero"),
			"maskedStore8":      sig3("maskedStore8"),
			"maskedStore64":     sig3("maskedStore64"),
			"maskedStorePS":     sig3("maskedStorePS"),
			"maskedCompress32":  sigPtrPtrI64("maskedCompress32"),
			"maskedExpand32":    sigPtrPtrI64("maskedExpand32"),
			"maskedExtract32x4": sigPtrPtrI64("maskedExtract32x4"),
			"maskedAddMem32":    sigPtrI64Ptr("maskedAddMem32"),
			"maskedScalarSS":    sigPtrI64Ptr("maskedScalarSS"),
		},
	})
	if err != nil {
		t.Fatalf("Translate failed: %v", err)
	}
	for _, want := range []string{"@llvm.masked.store.", "@llvm.masked.load."} {
		if !strings.Contains(ll, want) {
			t.Fatalf("expected %q in masked memory IR", want)
		}
	}
	verifyLLVMWithTargetLLC(t, ll, "x86_64-unknown-linux-gnu")

	mainC := `
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern void maskedStore32(void *ptr, uint64_t mask, uint64_t val);
extern void maskedLoad32Merge(void *ptr, uint64_t mask, uint32_t *out);
extern void maskedLoad32Zero(void *ptr, uint64_t mask, uint32_t *out);
extern void maskedStore8(void *ptr, uint64_t mask, uint64_t val);
extern void maskedStore64(void *ptr, uint64_t mask, uint64_t val);
extern void maskedStorePS(void *ptr, uint64_t mask, uint64_t val);
extern void maskedCompress32(void *src, void *dst, uint64_t mask);
extern void maskedExpand32(void *src, void *out, uint64_t mask);
extern void maskedExtract32x4(void *src, void *dst, uint64_t mask);
extern void maskedAddMem32(void *ptr, uint64_t mask, uint32_t *out);
extern void maskedScalarSS(void *ptr, uint64_t mask, uint32_t *out);

int main(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    // Layout: [guard0: PROT_NONE][rw: PROT_READ|PROT_WRITE][guard1: PROT_NONE]
    uint8_t *base = mmap(NULL, 3 * ps, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (base == MAP_FAILED) return 100;
    if (mprotect(base, ps, PROT_NONE) != 0) return 101;
    if (mprotect(base + 2 * ps, ps, PROT_NONE) != 0) return 102;

    uint8_t *guardBefore = base;
    uint8_t *rwStart = base + ps;
    uint8_t *rwEnd = base + 2 * ps;
    uint8_t *guardAfter = base + 2 * ps;

    // 1a. VMOVDQU32 lane 0 at end of rw page (lanes 1..15 in guardAfter)
    uint32_t *pEnd4 = (uint32_t *)(rwEnd - 4);
    *pEnd4 = 0;
    maskedStore32(pEnd4, 0x1ULL, 42ULL);
    if (*pEnd4 != 42U) { fprintf(stderr, "1a got=%u\n", *pEnd4); return 1; }

    // 1b. VMOVDQU32 lane 15 at start of rw page (lanes 0..14 in guardBefore)
    uint32_t *pStart4 = (uint32_t *)rwStart;
    *pStart4 = 0;
    maskedStore32(rwStart - 60, 0x8000ULL, 0x12345678ULL);
    if (*pStart4 != 0x12345678U) { fprintf(stderr, "1b got=0x%x\n", *pStart4); return 2; }

    // 1c. VMOVDQU32 with K1=0 directly inside guard page
    maskedStore32(guardBefore + 64, 0ULL, 99ULL);

    // 2a/2b. VMOVDQU32 merge & zero masked loads at rwEnd - 4
    uint32_t out16[16];
    maskedLoad32Merge(pEnd4, 0x1ULL, out16);
    if (out16[0] != 42U || out16[1] != 0x11111111U || out16[15] != 0x11111111U) return 3;
    maskedLoad32Zero(pEnd4, 0x1ULL, out16);
    if (out16[0] != 42U || out16[1] != 0U || out16[15] != 0U) return 4;

    // 3. VMOVDQU8, VMOVDQU64, VMOVUPS at page end
    uint8_t *pEnd1 = rwEnd - 1;
    *pEnd1 = 0;
    maskedStore8(pEnd1, 0x1ULL, 0xabULL);
    if (*pEnd1 != 0xabU) return 5;

    uint64_t *pEnd8 = (uint64_t *)(rwEnd - 8);
    *pEnd8 = 0;
    maskedStore64(pEnd8, 0x1ULL, 0xdeadbeefcafebabeULL);
    if (*pEnd8 != 0xdeadbeefcafebabeULL) return 6;

    *pEnd4 = 0;
    maskedStorePS(pEnd4, 0x1ULL, 0x3f800000ULL);
    if (*pEnd4 != 0x3f800000U) return 7;

    // 4. VPCOMPRESSD: 2 active lanes (bits 0 and 2) into last 8 bytes before guardAfter
    uint32_t src16[16];
    for (int i = 0; i < 16; i++) src16[i] = (uint32_t)(1000 + i);
    uint32_t *pEnd8_32 = (uint32_t *)(rwEnd - 8);
    pEnd8_32[0] = 0; pEnd8_32[1] = 0;
    maskedCompress32(src16, pEnd8_32, 0x5ULL);
    if (pEnd8_32[0] != 1000U || pEnd8_32[1] != 1002U) {
        fprintf(stderr, "4 compress got=(%u,%u)\n", pEnd8_32[0], pEnd8_32[1]);
        return 8;
    }

    // 5. VPEXPANDD.Z: 2 active lanes from last 8 bytes before guardAfter
    pEnd8_32[0] = 55; pEnd8_32[1] = 66;
    maskedExpand32(pEnd8_32, out16, 0x5ULL);
    if (out16[0] != 55U || out16[1] != 0U || out16[2] != 66U || out16[3] != 0U) {
        fprintf(stderr, "5 expand got=(%u,%u,%u,%u)\n", out16[0], out16[1], out16[2], out16[3]);
        return 9;
    }

    // 6. VEXTRACTI32X4: 1 active lane at rwEnd - 4
    *pEnd4 = 0;
    maskedExtract32x4(src16, pEnd4, 0x1ULL);
    if (*pEnd4 != 1000U) return 10;

    // 7. VPADDD (AX), Z1, K1, Z2: masked ALU memory-source at rwEnd - 4
    *pEnd4 = 23;
    maskedAddMem32(pEnd4, 0x1ULL, out16);
    if (out16[0] != 123U || out16[1] != 777U || out16[15] != 777U) {
        fprintf(stderr, "7 addmem got=(%u,%u,%u)\n", out16[0], out16[1], out16[15]);
        return 11;
    }

    // 8. Scalar VMOVSS store & load with K1=0 on guardAfter (must preserve lane 0, zero upper lanes 1..3)
    uint32_t out4[4] = {1, 1, 1, 1};
    maskedScalarSS(guardAfter + 64, 0ULL, out4);
    if (out4[0] != 0x40000000U || out4[1] != 0U || out4[2] != 0U || out4[3] != 0U) {
        fprintf(stderr, "8 scalar got=(0x%x,0x%x,0x%x,0x%x)\n", out4[0], out4[1], out4[2], out4[3]);
        return 12;
    }

    munmap(base, 3 * ps);
    return 0;
}
`
	compileAndRunRuntimeTestWithCompiler(t, llc, []string{clang}, "x86_masked_guardpage", triple, ll, mainC, nil)
}
