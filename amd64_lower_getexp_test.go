package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64GetExpGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64GetExpSpec{
		"VGETEXPPS": {laneBits: 32},
		"VGETEXPPD": {laneBits: 64},
		"VGETEXPSS": {laneBits: 32, scalar: true},
		"VGETEXPSD": {laneBits: 64, scalar: true},
	}
	if len(amd64GetExpSpecs) != len(expected) {
		t.Fatalf("GETEXP grammar has %d entries, want %d", len(amd64GetExpSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64GetExpSpecs[op]; !ok {
			t.Errorf("GETEXP grammar omitted %s", op)
		} else if got != want {
			t.Errorf("GETEXP grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86GetExpCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT getexpforms(SB),$0-0\n")
			for _, op := range []string{"VGETEXPPS", "VGETEXPPD"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" && width == "Z" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s %s1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(AX), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s.BCST 16(AX), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s %s1, K1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s.Z 24(AX), K2, %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s.BCST.Z 32(AX), K3, %s%d\n", op, width, last)
					if width == "Z" {
						fmt.Fprintf(&source, "\t%s.SAE Z1, Z%d\n", op, last)
						fmt.Fprintf(&source, "\t%s.SAE.Z Z1, K4, Z%d\n", op, last)
					}
				}
			}
			for _, op := range []string{"VGETEXPSS", "VGETEXPSD"} {
				last := 31
				fmt.Fprintf(&source, "\t%s X1, X2, X%d\n", op, last)
				fmt.Fprintf(&source, "\t%s 40(AX), X2, X%d\n", op, last)
				fmt.Fprintf(&source, "\t%s.SAE X1, X2, X%d\n", op, last)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X2, K5, X%d\n", op, last)
					fmt.Fprintf(&source, "\t%s.Z 48(AX), X2, K6, X%d\n", op, last)
					fmt.Fprintf(&source, "\t%s.SAE.Z X1, X2, K7, X%d\n", op, last)
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
				Sigs: map[string]FuncSig{"getexpforms": {Name: "getexpforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "getexp-"+target.name+".ll", "getexp-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86GetExpRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VGETEXPPS X0"},
		{goarch: "amd64", instruction: "VGETEXPPS X0, Y1"},
		{goarch: "amd64", instruction: "VGETEXPPS.BCST X0, X1"},
		{goarch: "amd64", instruction: "VGETEXPPS.SAE X0, X1"},
		{goarch: "amd64", instruction: "VGETEXPPS.SAE 0(AX), Z1"},
		{goarch: "amd64", instruction: "VGETEXPPS.RN_SAE Z0, Z1"},
		{goarch: "amd64", instruction: "VGETEXPPS.Z X0, X1"},
		{goarch: "amd64", instruction: "VGETEXPPS X0, K0, X1"},
		{goarch: "amd64", instruction: "VGETEXPSS Y0, X1, X2"},
		{goarch: "amd64", instruction: "VGETEXPSS.BCST 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VGETEXPSD X0, X1, Y2"},
		{goarch: "386", instruction: "VGETEXPSS X0, X1, K1, X2"},
		{goarch: "386", instruction: "VGETEXPPS Z8, Z0"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's GETEXP table", test.instruction)
			}
		})
	}
}

func TestAMD64GetExpRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT getexpsemantics(SB),$0-56
	MOVQ out+0(FP), AX
	MOVQ source32+8(FP), BX
	MOVQ source64+16(FP), CX
	MOVQ old32+24(FP), DX
	MOVQ old64+32(FP), R8
	MOVQ upper+40(FP), R9
	MOVQ mask+48(FP), R10
	KMOVQ R10, K1
	STC
	VGETEXPPS 0(BX), Z0
	VMOVDQU32 Z0, 0(AX)
	VMOVDQU32 0(DX), Z1
	VGETEXPPS 0(BX), K1, Z1
	VMOVDQU32 Z1, 64(AX)
	VGETEXPPS.Z 0(BX), K1, Z1
	VMOVDQU32 Z1, 128(AX)
	VGETEXPPS.BCST 0(BX), Z1
	VMOVDQU32 Z1, 192(AX)
	VGETEXPPD 0(CX), Z2
	VMOVDQU64 Z2, 256(AX)
	VMOVDQU64 0(R8), Z3
	VGETEXPPD 0(CX), K1, Z3
	VMOVDQU64 Z3, 320(AX)
	VGETEXPPD.Z 0(CX), K1, Z3
	VMOVDQU64 Z3, 384(AX)
	VGETEXPPD.BCST 0(CX), Z3
	VMOVDQU64 Z3, 448(AX)
	VMOVDQU64 0(R9), X4
	VGETEXPSS 40(BX), X4, X5
	VMOVDQU64 X5, 512(AX)
	VGETEXPSD 40(CX), X4, X6
	VMOVDQU64 X6, 528(AX)
	SETCS 544(AX)
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
		Sigs: map[string]FuncSig{"getexpsemantics": {
			Name: "getexpsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				{Offset: 40, Type: Ptr, Index: 5, Field: -1},
				{Offset: 48, Type: I64, Index: 6, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
#include <xmmintrin.h>
extern void getexpsemantics(uint8_t *, const uint32_t *, const uint64_t *, const uint32_t *, const uint64_t *, const uint64_t *, uint64_t);
static uint32_t f32bits(float f) { uint32_t u; memcpy(&u,&f,4); return u; }
static uint64_t f64bits(double f) { uint64_t u; memcpy(&u,&f,8); return u; }
static uint32_t getexp32(uint32_t u, int daz) {
  uint32_t exp=u&UINT32_C(0x7f800000), mant=u&UINT32_C(0x007fffff);
  if (exp==UINT32_C(0x7f800000)) return mant?(u|UINT32_C(0x00400000)):UINT32_C(0x7f800000);
  if (exp==0 && (mant==0||daz)) return UINT32_C(0xff800000);
  int e;
  if (exp) e=(int)(exp>>23)-127;
  else { int p=31-__builtin_clz(mant); e=p-149; }
  return f32bits((float)e);
}
static uint64_t getexp64(uint64_t u, int daz) {
  uint64_t exp=u&UINT64_C(0x7ff0000000000000), mant=u&UINT64_C(0x000fffffffffffff);
  if (exp==UINT64_C(0x7ff0000000000000)) return mant?(u|UINT64_C(0x0008000000000000)):UINT64_C(0x7ff0000000000000);
  if (exp==0 && (mant==0||daz)) return UINT64_C(0xfff0000000000000);
  int e;
  if (exp) e=(int)(exp>>52)-1023;
  else { int p=63-__builtin_clzll(mant); e=p-1074; }
  return f64bits((double)e);
}
int main(void) {
  const uint32_t source32[16]={
    0x3f800000,0x40000000,0x3f400000,0xc1000000,0,0x80000000,0x7f800000,0xff800000,
    0x7fc12345,0x7f812345,1,0x007fffff,0x80000001,0x00800000,0x7f7fffff,0x3e800000};
  const uint64_t source64[8]={
    UINT64_C(0x3ff0000000000000),UINT64_C(0x4000000000000000),UINT64_C(0x3fe8000000000000),UINT64_C(0xc020000000000000),
    0,1,UINT64_C(0x000fffffffffffff),UINT64_C(0x8000000000000001)};
  uint32_t old32[16]; uint64_t old64[8];
  const uint64_t upper[2]={UINT64_C(0x1122334455667788),UINT64_C(0x99aabbccddeeff00)};
  uint8_t out[545]={0}, outDaz[545]={0}; const uint64_t mask=UINT64_C(0xa55a);
  for (int i=0;i<16;i++) old32[i]=UINT32_C(0x41000000)+(uint32_t)i;
  for (int i=0;i<8;i++) old64[i]=UINT64_C(0x4020000000000000)+(uint64_t)i;
  getexpsemantics(out,source32,source64,old32,old64,upper,mask);
  unsigned csr=_mm_getcsr(); _mm_setcsr(csr|UINT32_C(0x40));
  getexpsemantics(outDaz,source32,source64,old32,old64,upper,mask); _mm_setcsr(csr);
  for (int i=0;i<16;i++) {
    uint32_t want=getexp32(source32[i],0), got; memcpy(&got,out+4*i,4); if (got!=want) return 10;
    memcpy(&got,out+64+4*i,4); if (got!=(((mask>>i)&1)?want:old32[i])) return 11;
    memcpy(&got,out+128+4*i,4); if (got!=(((mask>>i)&1)?want:0)) return 12;
    memcpy(&got,out+192+4*i,4); if (got!=getexp32(source32[0],0)) return 13;
  }
  for (int i=0;i<8;i++) {
    uint64_t want=getexp64(source64[i],0), got; memcpy(&got,out+256+8*i,8); if (got!=want) return 20;
    memcpy(&got,out+320+8*i,8); if (got!=(((mask>>i)&1)?want:old64[i])) return 21;
    memcpy(&got,out+384+8*i,8); if (got!=(((mask>>i)&1)?want:0)) return 22;
    memcpy(&got,out+448+8*i,8); if (got!=getexp64(source64[0],0)) return 23;
  }
  uint32_t scalar32; memcpy(&scalar32,out+512,4); if (scalar32!=getexp32(source32[10],0)) return 30;
  if (memcmp(out+516,(uint8_t*)upper+4,12)) return 31;
  uint64_t scalar64; memcpy(&scalar64,out+528,8); if (scalar64!=getexp64(source64[5],0)) return 32;
  if (memcmp(out+536,(uint8_t*)upper+8,8)) return 33;
  if (out[544]!=1) return 34;
  uint32_t daz32; memcpy(&daz32,outDaz+40,4); if (daz32!=UINT32_C(0xff800000)) return 40;
  uint64_t daz64; memcpy(&daz64,outDaz+296,8); if (daz64!=UINT64_C(0xfff0000000000000)) return 41;
  memcpy(&daz32,outDaz+512,4); if (daz32!=UINT32_C(0xff800000)) return 42;
  memcpy(&daz64,outDaz+528,8); if (daz64!=UINT64_C(0xfff0000000000000)) return 43;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "getexp_semantics", triple, ir, mainC, runPrefix)
}
