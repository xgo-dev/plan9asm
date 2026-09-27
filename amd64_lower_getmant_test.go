package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64GetMantGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64GetMantSpec{
		"VGETMANTPS": {laneBits: 32},
		"VGETMANTPD": {laneBits: 64},
		"VGETMANTSS": {laneBits: 32, scalar: true},
		"VGETMANTSD": {laneBits: 64, scalar: true},
	}
	if len(amd64GetMantSpecs) != len(expected) {
		t.Fatalf("GETMANT grammar has %d entries, want %d", len(amd64GetMantSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64GetMantSpecs[op]; !ok {
			t.Errorf("GETMANT grammar omitted %s", op)
		} else if got != want {
			t.Errorf("GETMANT grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86GetMantCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT getmantforms(SB),$0-0\n")
			for _, op := range []string{"VGETMANTPS", "VGETMANTPD"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" && width == "Z" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s $0, %s1, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s $255, 8(AX), %s%d\n", op, width, last)
					fmt.Fprintf(&source, "\t%s.BCST $1, 16(AX), %s%d\n", op, width, last)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s $2, %s1, K1, %s%d\n", op, width, width, last)
						fmt.Fprintf(&source, "\t%s.Z $3, 24(AX), K2, %s%d\n", op, width, last)
						fmt.Fprintf(&source, "\t%s.BCST.Z $4, 32(AX), K3, %s%d\n", op, width, last)
					}
					if width == "Z" {
						fmt.Fprintf(&source, "\t%s.SAE $5, Z1, Z%d\n", op, last)
						if target.goarch == "amd64" {
							fmt.Fprintf(&source, "\t%s.SAE.Z $6, Z1, K4, Z%d\n", op, last)
						}
					}
				}
			}
			if target.goarch == "amd64" {
				for _, op := range []string{"VGETMANTSS", "VGETMANTSD"} {
					fmt.Fprintf(&source, "\t%s $0, X1, X2, X31\n", op)
					fmt.Fprintf(&source, "\t%s $255, 40(AX), X2, X31\n", op)
					fmt.Fprintf(&source, "\t%s.SAE $1, X1, X2, X31\n", op)
					fmt.Fprintf(&source, "\t%s $2, X1, X2, K5, X31\n", op)
					fmt.Fprintf(&source, "\t%s.Z $3, 48(AX), X2, K6, X31\n", op)
					fmt.Fprintf(&source, "\t%s.SAE.Z $4, X1, X2, K7, X31\n", op)
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
				Sigs: map[string]FuncSig{"getmantforms": {Name: "getmantforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "getmant-"+target.name+".ll", "getmant-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86GetMantRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VGETMANTPS $-1, X0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS $256, X0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS X0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS $0, X0, Y1"},
		{goarch: "amd64", instruction: "VGETMANTPS.BCST $0, X0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS.SAE $0, Z0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS.SAE $0, 0(AX), Z1"},
		{goarch: "amd64", instruction: "VGETMANTPS.RN_SAE $0, Z0, Z1"},
		{goarch: "amd64", instruction: "VGETMANTPS.Z $0, X0, X1"},
		{goarch: "amd64", instruction: "VGETMANTPS $0, X0, K0, X1"},
		{goarch: "amd64", instruction: "VGETMANTSS $0, Y0, X1, X2"},
		{goarch: "amd64", instruction: "VGETMANTSS.BCST $0, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VGETMANTSD $0, X0, X1, Y2"},
		{goarch: "386", instruction: "VGETMANTSS $0, X0, X1, X2"},
		{goarch: "386", instruction: "VGETMANTPS $0, X0, K1, X2"},
		{goarch: "386", instruction: "VGETMANTPS $0, Z8, Z0"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's GETMANT table", test.instruction)
			}
		})
	}
}

func TestAMD64GetMantRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString(`TEXT getmantsemantics(SB),$0-56
	MOVQ out+0(FP), AX
	MOVQ source32+8(FP), BX
	MOVQ source64+16(FP), CX
	MOVQ old32+24(FP), DX
	MOVQ old64+32(FP), R8
	MOVQ upper+40(FP), R9
	MOVQ mask+48(FP), R10
	KMOVQ R10, K1
	STC
`)
	for immediate := 0; immediate < 16; immediate++ {
		fmt.Fprintf(&source, "\tVGETMANTPS $%d, 0(BX), Z0\n", immediate)
		fmt.Fprintf(&source, "\tVMOVDQU32 Z0, %d(AX)\n", immediate*64)
		fmt.Fprintf(&source, "\tVGETMANTPD $%d, 0(CX), Z1\n", immediate)
		fmt.Fprintf(&source, "\tVMOVDQU64 Z1, %d(AX)\n", 1024+immediate*64)
	}
	source.WriteString(`	VMOVDQU32 0(DX), Z2
	VGETMANTPS $3, 0(BX), K1, Z2
	VMOVDQU32 Z2, 2048(AX)
	VGETMANTPS.Z $3, 0(BX), K1, Z2
	VMOVDQU32 Z2, 2112(AX)
	VGETMANTPS.BCST $5, 0(BX), Z2
	VMOVDQU32 Z2, 2176(AX)
	VMOVDQU64 0(R8), Z3
	VGETMANTPD $3, 0(CX), K1, Z3
	VMOVDQU64 Z3, 2240(AX)
	VGETMANTPD.Z $3, 0(CX), K1, Z3
	VMOVDQU64 Z3, 2304(AX)
	VGETMANTPD.BCST $5, 0(CX), Z3
	VMOVDQU64 Z3, 2368(AX)
	VMOVDQU64 0(R9), X4
	VGETMANTSS $11, 12(BX), X4, X5
	VMOVDQU64 X5, 2432(AX)
	VGETMANTSD $11, 24(CX), X4, X6
	VMOVDQU64 X6, 2448(AX)
	SETCS 2464(AX)
	RET
`)
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
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
		Sigs: map[string]FuncSig{"getmantsemantics": {
			Name: "getmantsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
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
extern void getmantsemantics(uint8_t *, const uint32_t *, const uint64_t *, const uint32_t *, const uint64_t *, const uint64_t *, uint64_t);
static uint32_t getmant32(uint32_t u, unsigned imm, int daz) {
  const uint32_t em=UINT32_C(0x7f800000), fm=UINT32_C(0x007fffff), qb=UINT32_C(0x00400000), sb=UINT32_C(0x80000000);
  uint32_t exp=u&em, frac=u&fm, sign=u&sb; unsigned sc=(imm>>2)&3, interval=imm&3;
  int nan=exp==em&&frac!=0, inf=exp==em&&frac==0, zero=exp==0&&(frac==0||daz), neg=sign!=0;
  if (nan) return u|qb;
  uint32_t one=UINT32_C(0x3f800000), signedOne=one|((sc&1)?0:sign);
  if (neg && !zero && (sc&2)) return UINT32_C(0xffc00000);
  if (zero||inf) return neg?signedOne:one;
  int unbiased;
  if (exp==0) { int shift=__builtin_clz(frac)-8; frac=(frac<<shift)&fm; unbiased=-shift; }
  else unbiased=(int)(exp>>23)-127;
  uint32_t outExp=127;
  if (interval==1) outExp=(unbiased&1)?126:127;
  else if (interval==2) outExp=126;
  else if (interval==3) outExp=(frac&qb)?126:127;
  return (outExp<<23)|frac|((sc&1)?0:sign);
}
static uint64_t getmant64(uint64_t u, unsigned imm, int daz) {
  const uint64_t em=UINT64_C(0x7ff0000000000000), fm=UINT64_C(0x000fffffffffffff), qb=UINT64_C(0x0008000000000000), sb=UINT64_C(0x8000000000000000);
  uint64_t exp=u&em, frac=u&fm, sign=u&sb; unsigned sc=(imm>>2)&3, interval=imm&3;
  int nan=exp==em&&frac!=0, inf=exp==em&&frac==0, zero=exp==0&&(frac==0||daz), neg=sign!=0;
  if (nan) return u|qb;
  uint64_t one=UINT64_C(0x3ff0000000000000), signedOne=one|((sc&1)?0:sign);
  if (neg && !zero && (sc&2)) return UINT64_C(0xfff8000000000000);
  if (zero||inf) return neg?signedOne:one;
  int unbiased;
  if (exp==0) { int shift=__builtin_clzll(frac)-11; frac=(frac<<shift)&fm; unbiased=-shift; }
  else unbiased=(int)(exp>>52)-1023;
  uint64_t outExp=1023;
  if (interval==1) outExp=(unbiased&1)?1022:1023;
  else if (interval==2) outExp=1022;
  else if (interval==3) outExp=(frac&qb)?1022:1023;
  return (outExp<<52)|frac|((sc&1)?0:sign);
}
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  const uint32_t source32[16]={
    0x3f800000,0xbf800000,0x40400000,0xc0400000,0x3f400000,0xbf400000,0,0x80000000,
    0x7f800000,0xff800000,0x7fc12345,0xff812345,1,0x807fffff,0x00800000,0x7f7fffff};
  const uint64_t source64[8]={
    UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),UINT64_C(0x4008000000000000),UINT64_C(0xc008000000000000),
    0,UINT64_C(0x8000000000000000),UINT64_C(1),UINT64_C(0xfff0000000000000)};
  uint32_t old32[16]; uint64_t old64[8];
  const uint64_t upper[2]={UINT64_C(0x1122334455667788),UINT64_C(0x99aabbccddeeff00)};
  uint8_t out[2465]={0}, outDaz[2465]={0}; const uint64_t mask=UINT64_C(0xa55a);
  for (int i=0;i<16;i++) old32[i]=UINT32_C(0x41000000)+(uint32_t)i;
  for (int i=0;i<8;i++) old64[i]=UINT64_C(0x4020000000000000)+(uint64_t)i;
  getmantsemantics(out,source32,source64,old32,old64,upper,mask);
  unsigned csr=_mm_getcsr(); _mm_setcsr(csr|UINT32_C(0x40));
  getmantsemantics(outDaz,source32,source64,old32,old64,upper,mask); _mm_setcsr(csr);
  for (unsigned imm=0;imm<16;imm++) {
    for (int i=0;i<16;i++) {
      if (u32(out+imm*64+i*4)!=getmant32(source32[i],imm,0)) return 10;
      if (u32(outDaz+imm*64+i*4)!=getmant32(source32[i],imm,1)) return 11;
    }
    for (int i=0;i<8;i++) {
      if (u64(out+1024+imm*64+i*8)!=getmant64(source64[i],imm,0)) return 12;
      if (u64(outDaz+1024+imm*64+i*8)!=getmant64(source64[i],imm,1)) return 13;
    }
  }
  for (int i=0;i<16;i++) {
    uint32_t want=getmant32(source32[i],3,0);
    if (u32(out+2048+i*4)!=(((mask>>i)&1)?want:old32[i])) return 20;
    if (u32(out+2112+i*4)!=(((mask>>i)&1)?want:0)) return 21;
    if (u32(out+2176+i*4)!=getmant32(source32[0],5,0)) return 22;
  }
  for (int i=0;i<8;i++) {
    uint64_t want=getmant64(source64[i],3,0);
    if (u64(out+2240+i*8)!=(((mask>>i)&1)?want:old64[i])) return 23;
    if (u64(out+2304+i*8)!=(((mask>>i)&1)?want:0)) return 24;
    if (u64(out+2368+i*8)!=getmant64(source64[0],5,0)) return 25;
  }
  if (u32(out+2432)!=getmant32(source32[3],11,0)) return 30;
  if (memcmp(out+2436,(const uint8_t *)upper+4,12)) return 31;
  if (u64(out+2448)!=getmant64(source64[3],11,0)) return 32;
  if (memcmp(out+2456,(const uint8_t *)upper+8,8)) return 33;
  if (out[2464]!=1) return 34;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "getmant_semantics", triple, ir, mainC, runPrefix)
}
