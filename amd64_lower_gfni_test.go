package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64GFNIGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64GFNISpec{
		"VGF2P8MULB":        {mode: amd64GFNIMultiply},
		"VGF2P8AFFINEQB":    {mode: amd64GFNIAffine, immediate: true, broadcast: true},
		"VGF2P8AFFINEINVQB": {mode: amd64GFNIAffineInverse, immediate: true, broadcast: true},
	}
	if len(amd64GFNISpecs) != len(expected) {
		t.Fatalf("GFNI grammar has %d entries, want %d", len(amd64GFNISpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64GFNISpecs[op]; !ok {
			t.Errorf("GFNI grammar omitted %s", op)
		} else if got != want {
			t.Errorf("GFNI grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86GFNICompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
		{name: "linux-386", goarch: "386", triple: "i386-unknown-linux-gnu"},
		{name: "windows-386", goarch: "386", triple: "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT gfniforms(SB),$0-0\n")
			for _, width := range []string{"X", "Y", "Z"} {
				last := 31
				if target.goarch == "386" && width == "Z" {
					last = 7
				}
				fmt.Fprintf(&source, "\tVGF2P8MULB %s1, %s2, %s%d\n", width, width, width, last)
				fmt.Fprintf(&source, "\tVGF2P8MULB 8(AX), %s2, %s%d\n", width, width, last)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB $0x63, %s1, %s2, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB $0x63, 16(AX), %s2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB $0xa5, %s1, %s2, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB $0xa5, 24(AX), %s2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB.BCST $0x63, 32(AX), %s2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB.BCST $0xa5, 40(AX), %s2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8MULB %s1, %s2, K1, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8MULB.Z 48(AX), %s2, K2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB $0x63, %s1, %s2, K3, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB.Z $0x63, 56(AX), %s2, K4, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB $0xa5, %s1, %s2, K5, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB.Z $0xa5, 64(AX), %s2, K6, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEQB.BCST.Z $0x63, 72(AX), %s2, K7, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVGF2P8AFFINEINVQB.BCST.Z $0xa5, 80(AX), %s2, K1, %s%d\n", width, width, last)
				}
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)

			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"gfniforms": {Name: "gfniforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "gfni-"+target.name+".ll", "gfni-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86GFNIRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VGF2P8MULB X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VGF2P8MULB X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VGF2P8MULB.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VGF2P8MULB.BCST 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VGF2P8MULB X0, X1, 0(AX)"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEQB $256, X0, X1, X2"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEINVQB $1, X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEQB.BCST $1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEINVQB.Z.BCST $1, 0(AX), X1, K1, X2"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEQB $1, X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VGF2P8AFFINEQB $1, X0, X1"},
		{goarch: "386", instruction: "VGF2P8MULB X0, X1, K1, X2"},
		{goarch: "386", instruction: "VGF2P8AFFINEQB $1, X0, X1, X2"},
		{goarch: "386", instruction: "VGF2P8MULB Z0, Z1, Z8"},
	} {
		t.Run(test.goarch+"/"+strings.NewReplacer(" ", "_", ",", "", "(", "_", ")", "_").Replace(test.instruction), func(t *testing.T) {
			source := "TEXT bad(SB),$0-0\n\t" + test.instruction + "\n\tRET\n"
			requireX86GoAssemblerResult(t, test.goarch, source, false)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				return
			}
			triple := "x86_64-unknown-linux-gnu"
			if test.goarch == "386" {
				triple = "i386-unknown-linux-gnu"
			}
			if _, err := Translate(file, Options{
				Goarch: test.goarch, TargetTriple: triple,
				Sigs: map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's GFNI table", test.instruction)
			}
		})
	}
}

func TestAMD64GFNIRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT gfnisemantics(SB),$0-48
	MOVQ out+0(FP), AX
	MOVQ matrix+8(FP), BX
	MOVQ data+16(FP), CX
	MOVQ other+24(FP), DX
	MOVQ old+32(FP), R8
	MOVQ mask+40(FP), R9
	KMOVQ R9, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VMOVDQU64 0(DX), Z2
	VMOVDQU64 0(R8), Z3
	STC
	VGF2P8MULB Z2, Z1, Z4
	VMOVDQU64 Z4, 0(AX)
	VGF2P8AFFINEQB $0x63, Z0, Z1, Z4
	VMOVDQU64 Z4, 64(AX)
	VGF2P8AFFINEINVQB $0xa5, Z0, Z1, Z4
	VMOVDQU64 Z4, 128(AX)
	VGF2P8MULB Z2, Z1, K1, Z3
	VMOVDQU64 Z3, 192(AX)
	VGF2P8AFFINEQB.Z $0x63, Z0, Z1, K1, Z4
	VMOVDQU64 Z4, 256(AX)
	VGF2P8AFFINEQB.BCST $0x63, 0(BX), Z1, Z4
	VMOVDQU64 Z4, 320(AX)
	VMOVDQU64 0(R8), Z3
	VGF2P8AFFINEINVQB.BCST.Z $0xa5, 0(BX), Z1, K1, Z3
	VMOVDQU64 Z3, 384(AX)
	VGF2P8MULB Z2, Z1, Z2
	VMOVDQU64 Z2, 448(AX)
	SETCS 512(AX)
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	var runPrefix []string
	if crossRosetta {
		triple = "x86_64-apple-macosx"
		runPrefix = []string{"/usr/bin/arch", "-x86_64"}
	}
	ir, err := Translate(file, Options{
		Goarch: "amd64", TargetTriple: triple,
		Sigs: map[string]FuncSig{"gfnisemantics": {
			Name: "gfnisemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				{Offset: 40, Type: I64, Index: 5, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void gfnisemantics(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t r = 0;
  for (int i = 0; i < 8; i++) {
    if (b & 1) r ^= a;
    uint8_t hi = a & 0x80;
    a <<= 1;
    if (hi) a ^= 0x1b;
    b >>= 1;
  }
  return r;
}
static uint8_t gf_inv(uint8_t x) {
  if (!x) return 0;
  uint8_t r = 1, a = x;
  for (unsigned e = 254; e; e >>= 1) {
    if (e & 1) r = gf_mul(r, a);
    a = gf_mul(a, a);
  }
  return r;
}
static unsigned parity8(uint8_t x) {
  x ^= x >> 4; x &= 0xf;
  return (0x6996u >> x) & 1u;
}
static uint8_t affine(const uint8_t *matrix, uint8_t x, uint8_t imm, int inverse) {
  if (inverse) x = gf_inv(x);
  uint8_t r = 0;
  for (int bit = 0; bit < 8; bit++) r |= (uint8_t)(parity8(matrix[7-bit] & x) << bit);
  return r ^ imm;
}
int main(void) {
  uint8_t matrix[64], data[64], other[64], old[64], out[513] = {0};
  const uint64_t mask = UINT64_C(0xa55aa55af00f0ff0);
  for (int i = 0; i < 64; i++) {
    matrix[i] = (uint8_t)(0x81u + 29u * (unsigned)i);
    data[i] = (uint8_t)(3u + 17u * (unsigned)i);
    other[i] = (uint8_t)(7u + 11u * (unsigned)i);
    old[i] = (uint8_t)(0xe0u - (unsigned)i);
  }
  gfnisemantics(out, matrix, data, other, old, mask);
  for (int i = 0; i < 64; i++) {
    const uint8_t mul = gf_mul(other[i], data[i]);
    const uint8_t aq = affine(matrix + (i/8)*8, data[i], 0x63, 0);
    const uint8_t ai = affine(matrix + (i/8)*8, data[i], 0xa5, 1);
    if (out[i] != mul) return 10;
    if (out[64+i] != aq) return 11;
    if (out[128+i] != ai) return 12;
    if (out[192+i] != (((mask>>i)&1) ? mul : old[i])) return 13;
    if (out[256+i] != (((mask>>i)&1) ? aq : 0)) return 14;
    if (out[320+i] != affine(matrix, data[i], 0x63, 0)) return 15;
    if (out[384+i] != (((mask>>i)&1) ? affine(matrix, data[i], 0xa5, 1) : 0)) return 16;
    if (out[448+i] != mul) return 17;
  }
  if (out[512] != 1) return 18;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "gfni_semantics", triple, ir, mainC, runPrefix)
}
