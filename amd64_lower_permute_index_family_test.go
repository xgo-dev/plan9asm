package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64IndexedPermuteGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64IndexedPermuteSpec{
		"VPERMB":    {laneBits: 8, mode: amd64IndexedPermuteSingle},
		"VPERMW":    {laneBits: 16, mode: amd64IndexedPermuteSingle},
		"VPERMI2B":  {laneBits: 8, mode: amd64IndexedPermuteI2},
		"VPERMI2W":  {laneBits: 16, mode: amd64IndexedPermuteI2},
		"VPERMI2D":  {laneBits: 32, mode: amd64IndexedPermuteI2, broadcast: true},
		"VPERMI2PS": {laneBits: 32, mode: amd64IndexedPermuteI2, broadcast: true},
		"VPERMI2Q":  {laneBits: 64, mode: amd64IndexedPermuteI2, broadcast: true},
		"VPERMI2PD": {laneBits: 64, mode: amd64IndexedPermuteI2, broadcast: true},
		"VPERMT2B":  {laneBits: 8, mode: amd64IndexedPermuteT2},
		"VPERMT2W":  {laneBits: 16, mode: amd64IndexedPermuteT2},
		"VPERMT2D":  {laneBits: 32, mode: amd64IndexedPermuteT2, broadcast: true},
		"VPERMT2PS": {laneBits: 32, mode: amd64IndexedPermuteT2, broadcast: true},
		"VPERMT2Q":  {laneBits: 64, mode: amd64IndexedPermuteT2, broadcast: true},
		"VPERMT2PD": {laneBits: 64, mode: amd64IndexedPermuteT2, broadcast: true},
	}
	if len(amd64IndexedPermuteSpecs) != len(expected) {
		t.Fatalf("indexed-permute grammar has %d entries, want %d", len(amd64IndexedPermuteSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64IndexedPermuteSpecs[op]; !ok {
			t.Errorf("indexed-permute grammar omitted %s", op)
		} else if got != want {
			t.Errorf("indexed-permute grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86IndexedPermuteCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT indexedpermuteforms(SB),$0-0\n")
			for _, family := range []struct {
				op        string
				broadcast bool
			}{
				{op: "VPERMB"}, {op: "VPERMW"},
				{op: "VPERMI2B"}, {op: "VPERMI2W"},
				{op: "VPERMI2D", broadcast: true}, {op: "VPERMI2Q", broadcast: true},
				{op: "VPERMI2PS", broadcast: true}, {op: "VPERMI2PD", broadcast: true},
				{op: "VPERMT2B"}, {op: "VPERMT2W"},
				{op: "VPERMT2D", broadcast: true}, {op: "VPERMT2Q", broadcast: true},
				{op: "VPERMT2PS", broadcast: true}, {op: "VPERMT2PD", broadcast: true},
			} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" && width == "Z" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s %s1, %s2, %s%d\n", family.op, width, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(AX), %s2, %s%d\n", family.op, width, width, last)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s1, %s2, K1, %s%d\n", family.op, width, width, width, last)
						fmt.Fprintf(&source, "\t%s.Z 16(AX), %s2, K2, %s%d\n", family.op, width, width, last)
					}
					if family.broadcast {
						fmt.Fprintf(&source, "\t%s.BCST 24(AX), %s2, %s%d\n", family.op, width, width, last)
						if target.goarch == "amd64" {
							fmt.Fprintf(&source, "\t%s.BCST.Z 32(AX), %s2, K3, %s%d\n", family.op, width, width, last)
						}
					}
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
				Sigs: map[string]FuncSig{"indexedpermuteforms": {Name: "indexedpermuteforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "indexed-permute-"+target.name+".ll", "indexed-permute-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86IndexedPermuteRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPERMB X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VPERMW.BCST 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VPERMT2B.BCST 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VPERMT2D.BCST X0, X1, X2"},
		{goarch: "amd64", instruction: "VPERMT2D.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VPERMI2Q X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VPERMT2PS X0, X1, 0(AX)"},
		{goarch: "amd64", instruction: "VPERMI2D.Z.BCST 0(AX), X1, K1, X2"},
		{goarch: "amd64", instruction: "VPERMB X0, X1"},
		{goarch: "386", instruction: "VPERMT2D X0, X1, K1, X2"},
		{goarch: "386", instruction: "VPERMW Z0, Z1, Z8"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's indexed-permute table", test.instruction)
			}
		})
	}
}

func TestAMD64IndexedPermuteRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT indexedpermutesemantics(SB),$0-48
	MOVQ out+0(FP), AX
	MOVQ tableA+8(FP), BX
	MOVQ tableB+16(FP), CX
	MOVQ indices+24(FP), DX
	MOVQ old+32(FP), R8
	MOVQ mask+40(FP), R9
	KMOVQ R9, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VMOVDQU64 0(DX), Z2
	VMOVDQU64 0(R8), Z3
	STC
	VPERMB Z0, Z2, Z4
	VMOVDQU64 Z4, 0(AX)
	VPERMW Z0, Z2, Z4
	VMOVDQU64 Z4, 64(AX)
	VPERMI2B Z0, Z1, Z2
	VMOVDQU64 Z2, 128(AX)
	VMOVDQU64 0(DX), Z2
	VPERMT2B Z0, Z2, Z3
	VMOVDQU64 Z3, 192(AX)
	VMOVDQU64 0(R8), Z3
	VPERMB Z0, Z2, K1, Z3
	VMOVDQU64 Z3, 256(AX)
	VMOVDQU64 0(R8), Z3
	VPERMT2W.Z Z0, Z2, K1, Z3
	VMOVDQU64 Z3, 320(AX)
	VMOVDQU64 0(DX), Z2
	VPERMI2Q.BCST 0(BX), Z1, K1, Z2
	VMOVDQU64 Z2, 384(AX)
	VMOVDQU64 0(DX), Z2
	VMOVDQU64 0(R8), Z3
	VPERMT2D.BCST 0(BX), Z2, K1, Z3
	VMOVDQU64 Z3, 448(AX)
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
		Sigs: map[string]FuncSig{"indexedpermutesemantics": {
			Name: "indexedpermutesemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
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
extern void indexedpermutesemantics(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static uint16_t u16(const uint8_t *p) { uint16_t v; memcpy(&v,p,2); return v; }
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  uint64_t a64[8], b64[8], indices64[8], old64[8], output64[65] = {0};
  uint8_t *a=(uint8_t *)a64, *b=(uint8_t *)b64, *indices=(uint8_t *)indices64;
  uint8_t *old=(uint8_t *)old64, *out=(uint8_t *)output64;
  const uint64_t mask=UINT64_C(0xa55af00ff00fa55a);
  for (int i=0;i<64;i++) {
    a[i]=(uint8_t)(0x11u+3u*(unsigned)i);
    b[i]=(uint8_t)(0x80u+5u*(unsigned)i);
    indices[i]=(uint8_t)(7u+13u*(unsigned)i);
    old[i]=(uint8_t)(0xe0u-(unsigned)i);
  }
  indexedpermutesemantics(out,a,b,indices,old,mask);
  for (int i=0;i<64;i++) {
    unsigned index=indices[i]&63u;
    if (out[i]!=a[index]) return 10;
    unsigned two=indices[i]&127u;
    uint8_t want=two<64u ? b[two] : a[two-64u];
    if (out[128+i]!=want) return 11;
    want=two<64u ? old[two] : a[two-64u];
    if (out[192+i]!=want) return 12;
    want=(mask>>i)&1u ? a[index] : old[i];
    if (out[256+i]!=want) return 13;
  }
  for (int i=0;i<32;i++) {
    unsigned index=u16(indices+2*i)&31u;
    if (u16(out+64+2*i)!=u16(a+2*index)) return 20;
    unsigned two=u16(indices+2*i)&63u;
    uint16_t want=two<32u ? u16(old+2*two) : u16(a+2*(two-32u));
    if (u16(out+320+2*i)!=(((mask>>i)&1u)?want:0)) return 21;
  }
  for (int i=0;i<8;i++) {
    unsigned index=(unsigned)(u64(indices+8*i)&15u);
    uint64_t value=index<8u ? u64(b+8*index) : u64(a);
    uint64_t want=(mask>>i)&1u ? value : u64(indices+8*i);
    if (u64(out+384+8*i)!=want) return 30;
  }
  for (int i=0;i<16;i++) {
    unsigned index=u32(indices+4*i)&31u;
    uint32_t value=index<16u ? u32(old+4*index) : u32(a);
    uint32_t want=(mask>>i)&1u ? value : u32(old+4*i);
    if (u32(out+448+4*i)!=want) return 31;
  }
  if (out[512]!=1) return 40;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "indexed_permute_semantics", triple, ir, mainC, runPrefix)
}
