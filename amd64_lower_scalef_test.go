package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64ScaleFGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64BinaryFloatingSpec{
		"VSCALEFPS": {laneBits: 32, mode: amd64BinaryFloatingScale},
		"VSCALEFPD": {laneBits: 64, mode: amd64BinaryFloatingScale},
		"VSCALEFSS": {laneBits: 32, mode: amd64BinaryFloatingScale, scalar: true},
		"VSCALEFSD": {laneBits: 64, mode: amd64BinaryFloatingScale, scalar: true},
	}
	for op, want := range expected {
		if got, ok := amd64BinaryFloatingSpecs[op]; !ok {
			t.Errorf("SCALEF grammar omitted %s", op)
		} else if got != want {
			t.Errorf("SCALEF grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86ScaleFCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT scalefforms(SB),$0-0\n")
			for _, op := range []string{"VSCALEFPS", "VSCALEFPD"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s %s1, %s2, %s%d\n", op, width, width, width, last)
					fmt.Fprintf(&source, "\t%s 8(AX), %s2, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s.BCST 16(AX), %s2, %s%d\n", op, width, width, last)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s %s1, %s2, K1, %s%d\n", op, width, width, width, last)
						fmt.Fprintf(&source, "\t%s.Z 24(AX), %s2, K2, %s%d\n", op, width, width, last)
						fmt.Fprintf(&source, "\t%s.BCST.Z 32(AX), %s2, K3, %s%d\n", op, width, width, last)
					}
					if width == "Z" {
						for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
							fmt.Fprintf(&source, "\t%s.%s Z1, Z2, Z%d\n", op, rounding, last)
							if target.goarch == "amd64" {
								fmt.Fprintf(&source, "\t%s.%s.Z Z1, Z2, K4, Z%d\n", op, rounding, last)
							}
						}
					}
				}
			}
			for _, op := range []string{"VSCALEFSS", "VSCALEFSD"} {
				fmt.Fprintf(&source, "\t%s X1, X2, X7\n", op)
				fmt.Fprintf(&source, "\t%s 40(AX), X2, X7\n", op)
				for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
					fmt.Fprintf(&source, "\t%s.%s X1, X2, X7\n", op, rounding)
				}
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s X1, X2, K5, X31\n", op)
					fmt.Fprintf(&source, "\t%s.Z 48(AX), X2, K6, X31\n", op)
					fmt.Fprintf(&source, "\t%s.RN_SAE.Z X1, X2, K7, X31\n", op)
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
				Sigs: map[string]FuncSig{"scalefforms": {Name: "scalefforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scalef-"+target.name+".ll", "scalef-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ScaleFRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VSCALEFPS X0, X1"},
		{goarch: "amd64", instruction: "VSCALEFPS X0, X1, X2, X3, X4"},
		{goarch: "amd64", instruction: "VSCALEFPS X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VSCALEFPS X0, 8(AX), X2"},
		{goarch: "amd64", instruction: "VSCALEFPS X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VSCALEFPS.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VSCALEFPS.BCST X0, X1, X2"},
		{goarch: "amd64", instruction: "VSCALEFPS.RN_SAE 8(AX), Z1, Z2"},
		{goarch: "amd64", instruction: "VSCALEFPS.SAE Z0, Z1, Z2"},
		{goarch: "amd64", instruction: "VSCALEFPS.RN_SAE Y0, Y1, Y2"},
		{goarch: "amd64", instruction: "VSCALEFSS Y0, X1, X2"},
		{goarch: "amd64", instruction: "VSCALEFSS.BCST 8(AX), X1, X2"},
		{goarch: "amd64", instruction: "VSCALEFSS.RN_SAE 8(AX), X1, X2"},
		{goarch: "amd64", instruction: "VSCALEFSS X0, Y1, X2"},
		{goarch: "386", instruction: "VSCALEFPS X0, X1, K1, X2"},
		{goarch: "386", instruction: "VSCALEFPS Z8, Z1, Z2"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's SCALEF tables", test.instruction)
			}
		})
	}
}

func TestAMD64ScaleFRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT scalefsemantics(SB),$0-72
	MOVQ out+0(FP), AX
	MOVQ value32+8(FP), BX
	MOVQ scale32+16(FP), CX
	MOVQ value64+24(FP), DX
	MOVQ scale64+32(FP), R8
	MOVQ old32+40(FP), R9
	MOVQ old64+48(FP), R10
	MOVQ upper+56(FP), R11
	MOVQ mask+64(FP), R12
	KMOVQ R12, K1
	VMOVDQU32 0(BX), Z1
	VMOVDQU32 0(CX), Z2
	VSCALEFPS Z2, Z1, Z3
	VMOVDQU32 Z3, 0(AX)
	VSCALEFPS.RN_SAE Z2, Z1, Z3
	VMOVDQU32 Z3, 64(AX)
	VMOVDQU32 0(R9), Z3
	VSCALEFPS Z2, Z1, K1, Z3
	VMOVDQU32 Z3, 128(AX)
	VSCALEFPS.BCST 0(CX), Z1, Z3
	VMOVDQU32 Z3, 192(AX)
	VMOVDQU64 0(DX), Z4
	VMOVDQU64 0(R8), Z5
	VSCALEFPD Z5, Z4, Z6
	VMOVDQU64 Z6, 256(AX)
	VSCALEFPD.RN_SAE Z5, Z4, Z6
	VMOVDQU64 Z6, 320(AX)
	VMOVDQU64 0(R10), Z6
	VSCALEFPD.Z Z5, Z4, K1, Z6
	VMOVDQU64 Z6, 384(AX)
	VSCALEFPD.BCST 0(R8), Z4, Z6
	VMOVDQU64 Z6, 448(AX)
	VMOVDQU64 0(R11), X7
	VSCALEFSS 60(CX), X7, X8
	VMOVDQU64 X8, 512(AX)
	VSCALEFSD 56(R8), X7, X9
	VMOVDQU64 X9, 528(AX)
	STC
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
		Sigs: map[string]FuncSig{"scalefsemantics": {
			Name: "scalefsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				{Offset: 40, Type: Ptr, Index: 5, Field: -1},
				{Offset: 48, Type: Ptr, Index: 6, Field: -1},
				{Offset: 56, Type: Ptr, Index: 7, Field: -1},
				{Offset: 64, Type: I64, Index: 8, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <string.h>
#include <xmmintrin.h>
extern void scalefsemantics(uint8_t *, const uint32_t *, const uint32_t *, const uint64_t *, const uint64_t *, const uint32_t *, const uint64_t *, const uint64_t *, uint64_t);
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
static uint32_t scale32(uint32_t x, uint32_t y, int daz) {
  const uint32_t em=UINT32_C(0x7f800000), fm=UINT32_C(0x007fffff), qb=UINT32_C(0x00400000), sb=UINT32_C(0x80000000), ind=UINT32_C(0xffc00000);
  if(daz && !(x&em) && (x&fm)) x&=sb; if(daz && !(y&em) && (y&fm)) y&=sb;
  uint32_t xf=x&fm,yf=y&fm; int xn=(x&em)==em&&xf, xs=xn&&!(xf&qb), xi=(x&~sb)==em, xz=(x&~sb)==0;
  int yn=(y&em)==em&&yf, yi=(y&~sb)==em, yp=yi&&!(y&sb), ym=yi&&(y&sb);
  if(xs) return x|qb;
  if(xn) return yi?(yp?em:0):(x|qb);
  if(yn) return y|qb;
  if(xi) return ym?ind:x;
  if(xz) return yp?ind:x;
  if(yp) return (x&sb)|em; if(ym) return x&sb;
  float a,b,r; memcpy(&a,&x,4); memcpy(&b,&y,4); int n=b>=512?512:(b<=-512?-512:(int)floorf(b)); r=scalbnf(a,n); memcpy(&x,&r,4); return x;
}
static uint64_t scale64(uint64_t x, uint64_t y, int daz) {
  const uint64_t em=UINT64_C(0x7ff0000000000000), fm=UINT64_C(0x000fffffffffffff), qb=UINT64_C(0x0008000000000000), sb=UINT64_C(0x8000000000000000), ind=UINT64_C(0xfff8000000000000);
  if(daz && !(x&em) && (x&fm)) x&=sb; if(daz && !(y&em) && (y&fm)) y&=sb;
  uint64_t xf=x&fm,yf=y&fm; int xn=(x&em)==em&&xf, xs=xn&&!(xf&qb), xi=(x&~sb)==em, xz=(x&~sb)==0;
  int yn=(y&em)==em&&yf, yi=(y&~sb)==em, yp=yi&&!(y&sb), ym=yi&&(y&sb);
  if(xs) return x|qb;
  if(xn) return yi?(yp?em:0):(x|qb);
  if(yn) return y|qb;
  if(xi) return ym?ind:x;
  if(xz) return yp?ind:x;
  if(yp) return (x&sb)|em; if(ym) return x&sb;
  double a,b,r; memcpy(&a,&x,8); memcpy(&b,&y,8); int n=b>=4096?4096:(b<=-4096?-4096:(int)floor(b)); r=scalbn(a,n); memcpy(&x,&r,8); return x;
}
int main(void) {
  const uint32_t v32[16]={0x3f800000,0xbf800000,0x7f7fffff,0xff7fffff,0x00800000,0x80800000,1,0x80000001,0,0x80000000,0x7f800000,0xff800000,0x7fc12345,0x7f812345,0x3fc00000,0xbfc00000};
  const uint32_t s32[16]={0x3ff33333,0xbf8ccccd,0x3f800000,0x3f800000,0xbf800000,0xbf800000,0x3f800000,0x3f800000,0x7f800000,0xff800000,0xff800000,0x7f800000,0x7f800000,0,0xc3160000,0xc3160000};
  const uint64_t v64[8]={UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff),UINT64_C(0x0010000000000000),1,UINT64_C(0x7ff8123456789abc),UINT64_C(0x7ff0123456789abc)};
  const uint64_t s64[8]={UINT64_C(0x3ffe666666666666),UINT64_C(0xbff199999999999a),UINT64_C(0x3ff0000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x7ff0000000000000),0};
  uint32_t old32[16]; uint64_t old64[8];
  uint64_t upper[2]={UINT64_C(0x112233443fc00000),UINT64_C(0x99aabbccddeeff00)};
  for(int i=0;i<16;i++)old32[i]=UINT32_C(0x41000000)+(uint32_t)i; for(int i=0;i<8;i++)old64[i]=UINT64_C(0x4020000000000000)+(uint64_t)i;
  const uint64_t mask=UINT64_C(0xa55a); unsigned original=_mm_getcsr();
  const int fes[4]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
  for(unsigned rc=0;rc<4;rc++) for(unsigned daz=0;daz<2;daz++) {
		uint8_t out[545]={0}; unsigned csr=(original&~UINT32_C(0xe040))|(rc<<13)|(daz?UINT32_C(0x40):0); _mm_setcsr(csr); fesetround(fes[rc]);
    scalefsemantics(out,v32,s32,v64,s64,old32,old64,upper,mask);
    for(int i=0;i<16;i++) {
      uint32_t want=scale32(v32[i],s32[i],daz); if(u32(out+i*4)!=want)return 10+rc;
      int saved=fegetround(); fesetround(FE_TONEAREST); uint32_t rn=scale32(v32[i],s32[i],daz); fesetround(saved); if(u32(out+64+i*4)!=rn)return 20+rc;
      if(u32(out+128+i*4)!=(((mask>>i)&1)?want:old32[i]))return 30+rc;
      if(u32(out+192+i*4)!=scale32(v32[i],s32[0],daz))return 40+rc;
    }
    for(int i=0;i<8;i++) {
      uint64_t want=scale64(v64[i],s64[i],daz); if(u64(out+256+i*8)!=want)return 50+rc;
      int saved=fegetround(); fesetround(FE_TONEAREST); uint64_t rn=scale64(v64[i],s64[i],daz); fesetround(saved); if(u64(out+320+i*8)!=rn)return 60+rc;
      if(u64(out+384+i*8)!=(((mask>>i)&1)?want:0))return 70+rc;
      if(u64(out+448+i*8)!=scale64(v64[i],s64[0],daz))return 80+rc;
    }
    if(u32(out+512)!=scale32((uint32_t)upper[0],s32[15],daz)||memcmp(out+516,(uint8_t*)upper+4,12))return 90+rc;
    if(u64(out+528)!=scale64(upper[0],s64[7],daz)||u64(out+536)!=upper[1])return 100+rc;
    if(out[544]!=1)return 110+rc;
  }
  _mm_setcsr(original); fesetround(FE_TONEAREST); return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalef_semantics", triple, ir, mainC, runPrefix)
}
