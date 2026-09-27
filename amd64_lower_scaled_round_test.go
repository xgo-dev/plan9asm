package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateAMD64ScaledRoundRepresentativeForms(t *testing.T) {
	const source = `TEXT scaledroundforms(SB),$0-0
	VREDUCEPS $3, Z1, K2, Z3
	VRNDSCALESD $20, X4, X5, K6, X7
	RET
`
	requireX86GoAssemblerResult(t, "amd64", source, true)
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"scaledroundforms": {Name: "scaledroundforms", Ret: Void}},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAMD64ScaledRoundGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64ScaledRoundSpec{
		"VRNDSCALEPS": {laneBits: 32},
		"VRNDSCALEPD": {laneBits: 64},
		"VRNDSCALESS": {laneBits: 32, scalar: true},
		"VRNDSCALESD": {laneBits: 64, scalar: true},
		"VREDUCEPS":   {laneBits: 32, mode: amd64Reduce},
		"VREDUCEPD":   {laneBits: 64, mode: amd64Reduce},
		"VREDUCESS":   {laneBits: 32, scalar: true, mode: amd64Reduce},
		"VREDUCESD":   {laneBits: 64, scalar: true, mode: amd64Reduce},
	}
	if len(amd64ScaledRoundSpecs) != len(expected) {
		t.Fatalf("scaled-round grammar has %d entries, want %d", len(amd64ScaledRoundSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64ScaledRoundSpecs[op]; !ok {
			t.Errorf("scaled-round grammar omitted %s", op)
		} else if got != want {
			t.Errorf("scaled-round grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86ScaledRoundCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT scaledroundallforms(SB),$0-0\n")
			for _, op := range []string{"VRNDSCALEPS", "VRNDSCALEPD", "VREDUCEPS", "VREDUCEPD"} {
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
				for _, op := range []string{"VRNDSCALESS", "VRNDSCALESD", "VREDUCESS", "VREDUCESD"} {
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
				Sigs: map[string]FuncSig{"scaledroundallforms": {Name: "scaledroundallforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "scaled-round-"+target.name+".ll", "scaled-round-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86ScaledRoundRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VREDUCEPS $-1, X0, X1"},
		{goarch: "amd64", instruction: "VRNDSCALEPD $256, X0, X1"},
		{goarch: "amd64", instruction: "VREDUCEPS X0, X1"},
		{goarch: "amd64", instruction: "VRNDSCALEPS $0, X0, Y1"},
		{goarch: "amd64", instruction: "VREDUCEPS.BCST $0, X0, X1"},
		{goarch: "amd64", instruction: "VRNDSCALEPS.SAE $0, Z0, X1"},
		{goarch: "amd64", instruction: "VREDUCEPD.SAE $0, 0(AX), Z1"},
		{goarch: "amd64", instruction: "VRNDSCALEPS.RN_SAE $0, Z0, Z1"},
		{goarch: "amd64", instruction: "VREDUCEPS.Z $0, X0, X1"},
		{goarch: "amd64", instruction: "VRNDSCALEPS $0, X0, K0, X1"},
		{goarch: "amd64", instruction: "VREDUCESS $0, Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRNDSCALESD.BCST $0, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VREDUCESD $0, X0, X1, Y2"},
		{goarch: "386", instruction: "VRNDSCALESS $0, X0, X1, X2"},
		{goarch: "386", instruction: "VREDUCEPS $0, X0, K1, X2"},
		{goarch: "386", instruction: "VRNDSCALEPS $0, Z8, Z0"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's scaled-round tables", test.instruction)
			}
		})
	}
}

func TestAMD64ScaledRoundRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString(`TEXT scaledroundsemantics(SB),$0-56
	MOVQ out+0(FP), AX
	MOVQ source32+8(FP), BX
	MOVQ source64+16(FP), CX
	MOVQ old32+24(FP), DX
	MOVQ old64+32(FP), R8
	MOVQ upper+40(FP), R9
	MOVQ mask+48(FP), R10
	KMOVQ R10, K1
	VMOVDQU64 0(R9), X4
	STC
`)
	for scale := 0; scale < 16; scale++ {
		for rounding := 0; rounding < 4; rounding++ {
			index := scale*4 + rounding
			immediate := scale<<4 | rounding
			fmt.Fprintf(&source, "\tVRNDSCALESS $%d, %d(BX), X4, X5\n", immediate, index%16*4)
			fmt.Fprintf(&source, "\tVMOVSS X5, %d(AX)\n", index*4)
			fmt.Fprintf(&source, "\tVREDUCESS $%d, %d(BX), X4, X5\n", immediate, index%16*4)
			fmt.Fprintf(&source, "\tVMOVSS X5, %d(AX)\n", 256+index*4)
			fmt.Fprintf(&source, "\tVRNDSCALESD $%d, %d(CX), X4, X5\n", immediate, index%16*8)
			fmt.Fprintf(&source, "\tVMOVSD X5, %d(AX)\n", 512+index*8)
			fmt.Fprintf(&source, "\tVREDUCESD $%d, %d(CX), X4, X5\n", immediate, index%16*8)
			fmt.Fprintf(&source, "\tVMOVSD X5, %d(AX)\n", 1024+index*8)
		}
	}
	source.WriteString(`	VMOVDQU32 0(DX), Z2
	VRNDSCALEPS $35, 0(BX), K1, Z2
	VMOVDQU32 Z2, 1536(AX)
	VREDUCEPS.Z $35, 0(BX), K1, Z2
	VMOVDQU32 Z2, 1600(AX)
	VRNDSCALEPS.BCST $35, 0(BX), Z2
	VMOVDQU32 Z2, 1664(AX)
	VMOVDQU64 0(R8), Z3
	VRNDSCALEPD $35, 0(CX), K1, Z3
	VMOVDQU64 Z3, 1728(AX)
	VREDUCEPD.Z $35, 0(CX), K1, Z3
	VMOVDQU64 Z3, 1792(AX)
	VRNDSCALEPD.BCST $35, 0(CX), Z3
	VMOVDQU64 Z3, 1856(AX)
	VRNDSCALESS $0, 0(BX), X4, X5
	VMOVDQU64 X5, 1920(AX)
	VREDUCESD $0, 0(CX), X4, X6
	VMOVDQU64 X6, 1936(AX)
	VRNDSCALESS $36, 0(BX), X4, X5
	VMOVSS X5, 1952(AX)
	VREDUCESS $36, 8(BX), X4, X5
	VMOVSS X5, 1956(AX)
	VRNDSCALESD $36, 0(CX), X4, X5
	VMOVSD X5, 1960(AX)
	VREDUCESD $36, 16(CX), X4, X5
	VMOVSD X5, 1968(AX)
	SETCS 1976(AX)
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
		Sigs: map[string]FuncSig{"scaledroundsemantics": {
			Name: "scaledroundsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
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
extern void scaledroundsemantics(uint8_t *, const uint32_t *, const uint64_t *, const uint32_t *, const uint64_t *, const uint64_t *, uint64_t);
static int inc(unsigned rc,int neg,int nonzero,int nearest) { return rc==0?nearest:(rc==1?neg&&nonzero:(rc==2?!neg&&nonzero:0)); }
static uint32_t round32(uint32_t u,unsigned scale,unsigned rc,int daz) {
  const uint32_t em=0x7f800000,fm=0x007fffff,qb=0x00400000,sb=0x80000000,ib=0x00800000;
  uint32_t e=(u&em)>>23,f=u&fm,s=u&sb; if(e==255) return f?(u|qb):u;
  if(e==0&&(f==0||daz)) return s;
  unsigned already=127+23-scale, regular=127-scale;
  if(e>=already) return u;
  uint32_t sig=f|ib;
  if(e>=regular) { unsigned drop=23+127-scale-e; uint32_t q=sig>>drop, rem=sig&((UINT32_C(1)<<drop)-1), half=UINT32_C(1)<<(drop-1); int n=rem>half||(rem==half&&(q&1)); q+=(uint32_t)inc(rc,s!=0,rem!=0,n); uint32_t rs=q<<drop, carry=(rs&(ib<<1))!=0; return s|((e+carry)<<23)|(rs&fm); }
  int half=e==regular-1, n=half&&sig>ib; return s|(inc(rc,s!=0,1,n)?((127-scale)<<23):0);
}
static uint64_t round64(uint64_t u,unsigned scale,unsigned rc,int daz) {
  const uint64_t em=UINT64_C(0x7ff0000000000000),fm=UINT64_C(0x000fffffffffffff),qb=UINT64_C(0x0008000000000000),sb=UINT64_C(0x8000000000000000),ib=UINT64_C(0x0010000000000000);
  uint64_t e=(u&em)>>52,f=u&fm,s=u&sb; if(e==2047) return f?(u|qb):u;
  if(e==0&&(f==0||daz)) return s;
  unsigned already=1023+52-scale, regular=1023-scale;
  if(e>=already) return u;
  uint64_t sig=f|ib;
  if(e>=regular) { unsigned drop=52+1023-scale-(unsigned)e; uint64_t q=sig>>drop, rem=sig&((UINT64_C(1)<<drop)-1), half=UINT64_C(1)<<(drop-1); int n=rem>half||(rem==half&&(q&1)); q+=(uint64_t)inc(rc,s!=0,rem!=0,n); uint64_t rs=q<<drop, carry=(rs&(ib<<1))!=0; return s|((e+carry)<<52)|(rs&fm); }
  int half=e==regular-1, n=half&&sig>ib; return s|(inc(rc,s!=0,1,n)?((uint64_t)(1023-scale)<<52):0);
}
static uint32_t reduce32(uint32_t u,unsigned scale,unsigned rc,int daz) { uint32_t e=u&0x7f800000,f=u&0x007fffff,s=u&0x80000000; if(e==0x7f800000) return f?(u|0x00400000):0; uint32_t effective=(e==0&&(f==0||daz))?s:u, rounded=round32(u,scale,rc,daz), r; float a,b,c; memcpy(&a,&effective,4); memcpy(&b,&rounded,4); c=a-b; memcpy(&r,&c,4); return (r&0x7fffffff)?r:(rc==1?0x80000000:0); }
static uint64_t reduce64(uint64_t u,unsigned scale,unsigned rc,int daz) { uint64_t e=u&UINT64_C(0x7ff0000000000000),f=u&UINT64_C(0x000fffffffffffff),s=u&UINT64_C(0x8000000000000000); if(e==UINT64_C(0x7ff0000000000000)) return f?(u|UINT64_C(0x0008000000000000)):0; uint64_t effective=(e==0&&(f==0||daz))?s:u, rounded=round64(u,scale,rc,daz), r; double a,b,c; memcpy(&a,&effective,8); memcpy(&b,&rounded,8); c=a-b; memcpy(&r,&c,8); return (r&UINT64_C(0x7fffffffffffffff))?r:(rc==1?UINT64_C(0x8000000000000000):0); }
static uint32_t u32(const uint8_t *p) { uint32_t v; memcpy(&v,p,4); return v; }
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  const uint32_t s32[16]={0x3fc00000,0x40200000,0xbfc00000,0xc0200000,0x3fb00000,0xbfb00000,0,0x80000000,0x7f800000,0xff800000,0x7fc12345,0xff812345,1,0x80000001,0x4e800000,0x3f800001};
  const uint64_t s64[16]={UINT64_C(0x3ff8000000000000),UINT64_C(0x4004000000000000),UINT64_C(0xbff8000000000000),UINT64_C(0xc004000000000000),UINT64_C(0x3ff6000000000000),UINT64_C(0xbff6000000000000),0,UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff0123456789abc),1,UINT64_C(0x8000000000000001),UINT64_C(0x41d0000000000000),UINT64_C(0x3ff0000000000001)};
  uint32_t old32[16]; uint64_t old64[8]; const uint64_t upper[2]={UINT64_C(0x1122334455667788),UINT64_C(0x99aabbccddeeff00)}; const uint64_t mask=UINT64_C(0xa55a);
  uint8_t out[1977]={0},outDaz[1977]={0},dynamic[4][1977]; for(int i=0;i<16;i++)old32[i]=UINT32_C(0x41000000)+i; for(int i=0;i<8;i++)old64[i]=UINT64_C(0x4020000000000000)+i;
  unsigned csr=_mm_getcsr(); scaledroundsemantics(out,s32,s64,old32,old64,upper,mask); _mm_setcsr(csr|0x40); scaledroundsemantics(outDaz,s32,s64,old32,old64,upper,mask); _mm_setcsr(csr);
  for(unsigned rc=0;rc<4;rc++){_mm_setcsr((csr&~(3u<<13))|(rc<<13));scaledroundsemantics(dynamic[rc],s32,s64,old32,old64,upper,mask);} _mm_setcsr(csr);
  for(unsigned scale=0;scale<16;scale++)for(unsigned rc=0;rc<4;rc++){unsigned i=scale*4+rc,j=i&15;if(u32(out+i*4)!=round32(s32[j],scale,rc,0)||u32(out+256+i*4)!=reduce32(s32[j],scale,rc,0))return 10;if(u64(out+512+i*8)!=round64(s64[j],scale,rc,0)||u64(out+1024+i*8)!=reduce64(s64[j],scale,rc,0))return 11;if(u32(outDaz+i*4)!=round32(s32[j],scale,rc,1)||u32(outDaz+256+i*4)!=reduce32(s32[j],scale,rc,1))return 12;if(u64(outDaz+512+i*8)!=round64(s64[j],scale,rc,1)||u64(outDaz+1024+i*8)!=reduce64(s64[j],scale,rc,1))return 13;}
  for(int i=0;i<16;i++){uint32_t r=round32(s32[i],2,3,0),d=reduce32(s32[i],2,3,0);if(u32(out+1536+i*4)!=(((mask>>i)&1)?r:old32[i]))return 20;if(u32(out+1600+i*4)!=(((mask>>i)&1)?d:0))return 21;if(u32(out+1664+i*4)!=round32(s32[0],2,3,0))return 22;}
  for(int i=0;i<8;i++){uint64_t r=round64(s64[i],2,3,0),d=reduce64(s64[i],2,3,0);if(u64(out+1728+i*8)!=(((mask>>i)&1)?r:old64[i]))return 23;if(u64(out+1792+i*8)!=(((mask>>i)&1)?d:0))return 24;if(u64(out+1856+i*8)!=round64(s64[0],2,3,0))return 25;}
  if(u32(out+1920)!=round32(s32[0],0,0,0)||memcmp(out+1924,(const uint8_t*)upper+4,12))return 30;if(u64(out+1936)!=reduce64(s64[0],0,0,0)||memcmp(out+1944,(const uint8_t*)upper+8,8))return 31;if(out[1976]!=1)return 32;
  for(unsigned rc=0;rc<4;rc++){if(u32(dynamic[rc]+1952)!=round32(s32[0],2,rc,0)||u32(dynamic[rc]+1956)!=reduce32(s32[2],2,rc,0)||u64(dynamic[rc]+1960)!=round64(s64[0],2,rc,0)||u64(dynamic[rc]+1968)!=reduce64(s64[2],2,rc,0))return 40+rc;}
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scaled_round_semantics", triple, ir, mainC, runPrefix)
}
