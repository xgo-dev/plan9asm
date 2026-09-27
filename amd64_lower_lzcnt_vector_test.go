package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64PackedBitCountGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64PackedBitCountSpec{
		"VPOPCNTB": {laneBits: 8, kind: amd64PackedPopulationCount},
		"VPOPCNTW": {laneBits: 16, kind: amd64PackedPopulationCount},
		"VPOPCNTD": {laneBits: 32, kind: amd64PackedPopulationCount, broadcast: true},
		"VPOPCNTQ": {laneBits: 64, kind: amd64PackedPopulationCount, broadcast: true},
		"VPLZCNTD": {laneBits: 32, kind: amd64PackedLeadingZeroCount, broadcast: true},
		"VPLZCNTQ": {laneBits: 64, kind: amd64PackedLeadingZeroCount, broadcast: true},
	}
	if len(amd64PackedBitCountSpecs) != len(expected) {
		t.Fatalf("packed-bit-count grammar has %d entries, want %d", len(amd64PackedBitCountSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64PackedBitCountSpecs[op]; !ok {
			t.Errorf("packed-bit-count grammar omitted %s", op)
		} else if got != want {
			t.Errorf("packed-bit-count grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86PackedLeadingZeroCountCompleteGoFormsAcrossTargets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
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
			source.WriteString("TEXT packedlzcntforms(SB),$0-0\n")
			for _, op := range []string{"VPLZCNTD", "VPLZCNTQ"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" && width == "Z" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s %s0, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(R9), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s %s1, K1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s.Z 16(R9), K7, %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s.BCST 24(R9), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s.BCST.Z 32(R9), K2, %s%d\n", op, width, last)
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
				Sigs: map[string]FuncSig{"packedlzcntforms": {Name: "packedlzcntforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"@llvm.ctlz.v4i32", "@llvm.ctlz.v8i64", "select i1"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("packed-LZCNT lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "packed-lzcnt-"+target.name+".ll", "packed-lzcnt-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PackedLeadingZeroCountRejectsFormsOutsideGoTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPLZCNTD X0, Y1"},
		{goarch: "amd64", instruction: "VPLZCNTQ Y0, Z1"},
		{goarch: "amd64", instruction: "VPLZCNTD X0, K0, X1"},
		{goarch: "amd64", instruction: "VPLZCNTQ.Z X0, X1"},
		{goarch: "amd64", instruction: "VPLZCNTD.BCST X0, X1"},
		{goarch: "amd64", instruction: "VPLZCNTQ.SAE X0, X1"},
		{goarch: "amd64", instruction: "VPLZCNTD X0, 0(AX)"},
		{goarch: "amd64", instruction: "VPLZCNTQ AX, X1"},
		{goarch: "amd64", instruction: "VPLZCNTD X0, K1, K2, X1"},
		{goarch: "386", instruction: "VPLZCNTD Z8, Z0"},
		{goarch: "386", instruction: "VPLZCNTQ Z0, K1, Z8"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's VPLZCNT _yvexpandpd grammar", test.instruction)
			}
		})
	}
}

func TestAMD64PackedLeadingZeroCountRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT packedlzcntsemantics(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ source+8(FP), BX
	MOVQ old+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VPLZCNTD Z0, Z2
	VMOVDQU64 Z2, 0(AX)
	VPLZCNTQ 0(BX), Z2
	VMOVDQU64 Z2, 64(AX)
	VPLZCNTD Z0, K1, Z1
	VMOVDQU64 Z1, 128(AX)
	VMOVDQU64 0(CX), Z1
	VPLZCNTQ.Z 0(BX), K1, Z1
	VMOVDQU64 Z1, 192(AX)
	VPLZCNTD.BCST 0(BX), Z2
	VMOVDQU64 Z2, 256(AX)
	VPLZCNTQ.BCST.Z 0(BX), K1, Z1
	VMOVDQU64 Z1, 320(AX)
	STC
	VPLZCNTD Z0, Z2
	SETCS 384(AX)
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
		Sigs: map[string]FuncSig{"packedlzcntsemantics": {
			Name: "packedlzcntsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: I64, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void packedlzcntsemantics(uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static unsigned lz32(uint32_t v) { unsigned n = 0; if (!v) return 32; while (!(v & UINT32_C(0x80000000))) { n++; v <<= 1; } return n; }
static unsigned lz64(uint64_t v) { unsigned n = 0; if (!v) return 64; while (!(v & UINT64_C(0x8000000000000000))) { n++; v <<= 1; } return n; }
int main(void) {
  uint32_t source32[16], old32[16]; uint8_t out[385] = {0};
  const uint64_t mask = UINT64_C(0xa55a);
  for (int i = 0; i < 16; i++) { source32[i] = i ? (UINT32_C(1) << ((i*7)%32)) : 0; old32[i] = UINT32_C(0x90000000) + i; }
  packedlzcntsemantics(out, (const uint8_t *)source32, (const uint8_t *)old32, mask);
  uint32_t *plain32=(uint32_t *)(out+0), *merge32=(uint32_t *)(out+128), *broadcast32=(uint32_t *)(out+256);
  for (int i=0;i<16;i++) {
    if (plain32[i] != lz32(source32[i])) return 10+i;
    uint32_t want = (mask>>i)&1 ? lz32(source32[i]) : old32[i];
    if (merge32[i] != want) return 30+i;
    if (broadcast32[i] != lz32(source32[0])) return 50+i;
  }
  uint64_t source64[8], old64[8], plain64[8], zero64[8], broadcast64[8];
  memcpy(source64, source32, 64); memcpy(old64, old32, 64);
  memcpy(plain64,out+64,64); memcpy(zero64,out+192,64); memcpy(broadcast64,out+320,64);
  for (int i=0;i<8;i++) {
    if (plain64[i] != lz64(source64[i])) return 70+i;
    uint64_t want = (mask>>i)&1 ? lz64(source64[i]) : 0;
    if (zero64[i] != want) return 80+i;
		want = (mask>>i)&1 ? lz64(source64[0]) : 0;
    if (broadcast64[i] != want) return 90+i;
  }
  if (out[384] != 1) return 100;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_lzcnt_semantics", triple, ir, mainC, runPrefix)
}
