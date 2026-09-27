package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type fixupImmediateTestSpec struct {
	op       string
	laneBits int
	scalar   bool
}

func go127FixupImmediateSpecs() []fixupImmediateTestSpec {
	return []fixupImmediateTestSpec{
		{op: "VFIXUPIMMPS", laneBits: 32},
		{op: "VFIXUPIMMPD", laneBits: 64},
		{op: "VFIXUPIMMSS", laneBits: 32, scalar: true},
		{op: "VFIXUPIMMSD", laneBits: 64, scalar: true},
	}
}

func TestAMD64FixupImmediateGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := go127FixupImmediateSpecs()
	if len(amd64FixupImmediateSpecs) != len(expected) {
		t.Fatalf("FIXUPIMM grammar has %d entries, want %d", len(amd64FixupImmediateSpecs), len(expected))
	}
	for _, want := range expected {
		got, ok := amd64FixupImmediateSpecs[Op(want.op)]
		if !ok {
			t.Errorf("FIXUPIMM grammar omitted %s", want.op)
			continue
		}
		if got.laneBits != want.laneBits || got.scalar != want.scalar {
			t.Errorf("FIXUPIMM grammar %s = %+v, want laneBits=%d scalar=%v", want.op, got, want.laneBits, want.scalar)
		}
	}
}

func TestTranslateX86FixupImmediateCompleteGoAssemblerForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		triple string
	}{
		{name: "darwin-amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT fixupimmforms(SB),$0-0\n")
			for index, spec := range go127FixupImmediateSpecs() {
				if spec.scalar {
					fmt.Fprintf(&source, "\t%s $%d, X0, X1, X23\n", spec.op, index)
					fmt.Fprintf(&source, "\t%s $%d, %d(AX), X1, X23\n", spec.op, index+16, index*8)
					fmt.Fprintf(&source, "\t%s $%d, X2, X1, K1, X23\n", spec.op, index+32)
					fmt.Fprintf(&source, "\t%s.Z $%d, %d(AX), X1, K2, X23\n", spec.op, index+48, index*8)
					fmt.Fprintf(&source, "\t%s.SAE $%d, X3, X1, X23\n", spec.op, index+64)
					fmt.Fprintf(&source, "\t%s.SAE.Z $%d, X4, X1, K3, X23\n", spec.op, index+80)
					continue
				}
				for _, width := range []string{"X", "Y", "Z"} {
					fmt.Fprintf(&source, "\t%s $%d, %s0, %s1, %s23\n", spec.op, index, width, width, width)
					fmt.Fprintf(&source, "\t%s $%d, %d(AX), %s1, %s23\n", spec.op, index+16, index*8, width, width)
					fmt.Fprintf(&source, "\t%s.BCST $%d, %d(AX), %s1, %s23\n", spec.op, index+32, index*8, width, width)
					fmt.Fprintf(&source, "\t%s $%d, %s2, %s1, K1, %s23\n", spec.op, index+48, width, width, width)
					fmt.Fprintf(&source, "\t%s.BCST.Z $%d, %d(AX), %s1, K2, %s23\n", spec.op, index+64, index*8, width, width)
				}
				fmt.Fprintf(&source, "\t%s.SAE $%d, Z3, Z1, Z23\n", spec.op, index+80)
				fmt.Fprintf(&source, "\t%s.SAE.Z $%d, Z4, Z1, K3, Z23\n", spec.op, index+96)
			}
			source.WriteString("\tRET\n")
			requireX86GoAssemblerResult(t, "amd64", source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"fixupimmforms": {Name: "fixupimmforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "fixupimm-"+target.name+".ll", "fixupimm-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FixupImmediateRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VFIXUPIMMPS $-1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS $256, X0, X1, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS.Z $1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS $1, X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS.SAE $1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS.SAE $1, 0(AX), Z1, Z2"},
		{goarch: "amd64", instruction: "VFIXUPIMMPS $1, X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMSS.BCST $1, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VFIXUPIMMSS.SAE $1, 0(AX), X1, X2"},
		{goarch: "386", instruction: "VFIXUPIMMPS $1, X0, X1, X2"},
		{goarch: "386", instruction: "VFIXUPIMMSS $1, X0, X1, X2"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's FIXUPIMM tables", test.instruction)
			}
		})
	}
}

func TestAMD64FixupImmediateRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT fixupimmsemantics(SB),$0-64
	MOVQ out+0(FP), AX
	MOVQ src32+8(FP), BX
	MOVQ table32+16(FP), CX
	MOVQ old32+24(FP), DX
	MOVQ src64+32(FP), R8
	MOVQ table64+40(FP), R9
	MOVQ old64+48(FP), R10
	MOVQ mask+56(FP), R11
	KMOVQ R11, K1
	VMOVDQU32 0(BX), Z1
	VMOVDQU32 0(CX), Z0
	VMOVDQU32 0(DX), Z2
	STC
	VFIXUPIMMPS $0, Z0, Z1, Z2
	VMOVDQU32 Z2, 0(AX)
	VMOVDQU32 0(DX), Z2
	VFIXUPIMMPS $0, Z0, Z1, K1, Z2
	VMOVDQU32 Z2, 64(AX)
	VFIXUPIMMPS.Z $0, Z0, Z1, K1, Z3
	VMOVDQU32 Z3, 128(AX)
	VMOVDQU64 0(R8), Z5
	VMOVDQU64 0(R9), Z4
	VMOVDQU64 0(R10), Z6
	VFIXUPIMMPD $0, Z4, Z5, Z6
	VMOVDQU64 Z6, 192(AX)
	VMOVDQU64 0(R8), X5
	VMOVDQU64 0(R9), X4
	VMOVDQU64 0(R10), X6
	VFIXUPIMMSD $0, X4, X5, X6
	VMOVDQU64 X6, 256(AX)
	VMOVDQU32 0(BX), X1
	VMOVDQU32 0(CX), X0
	VMOVDQU32 0(DX), X2
	VFIXUPIMMSS $0, X0, X1, X2
	VMOVDQU32 X2, 272(AX)
	SETCS 288(AX)
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
		Sigs: map[string]FuncSig{"fixupimmsemantics": {
			Name: "fixupimmsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: Ptr, Index: 4, Field: -1},
				{Offset: 40, Type: Ptr, Index: 5, Field: -1},
				{Offset: 48, Type: Ptr, Index: 6, Field: -1},
				{Offset: 56, Type: I64, Index: 7, Field: -1},
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
extern void fixupimmsemantics(uint8_t *, const uint32_t *, const uint32_t *, const uint32_t *, const uint64_t *, const uint64_t *, const uint64_t *, uint64_t);
static unsigned token32(uint32_t x, int daz) {
  if (daz && (x & UINT32_C(0x7f800000)) == 0) x = 0;
  uint32_t a=x&UINT32_C(0x7fffffff),m=x&UINT32_C(0x007fffff),e=x&UINT32_C(0x7f800000);
  if(e==UINT32_C(0x7f800000)&&m) return m&UINT32_C(0x00400000)?0:1;
  if(a==0)return 2;if(x==UINT32_C(0x3f800000))return 3;
  if(a==UINT32_C(0x7f800000))return x>>31?4:5;return x>>31?6:7;
}
static unsigned token64(uint64_t x, int daz) {
  if (daz && (x & UINT64_C(0x7ff0000000000000)) == 0) x = 0;
  uint64_t a=x&UINT64_C(0x7fffffffffffffff),m=x&UINT64_C(0x000fffffffffffff),e=x&UINT64_C(0x7ff0000000000000);
  if(e==UINT64_C(0x7ff0000000000000)&&m) return m&UINT64_C(0x0008000000000000)?0:1;
  if(a==0)return 2;if(x==UINT64_C(0x3ff0000000000000))return 3;
  if(a==UINT64_C(0x7ff0000000000000))return x>>63?4:5;return x>>63?6:7;
}
static uint32_t effective32(uint32_t x,int daz){return daz&&(x&UINT32_C(0x7f800000))==0?0:x;}
static uint64_t effective64(uint64_t x,int daz){return daz&&(x&UINT64_C(0x7ff0000000000000))==0?0:x;}
static uint32_t fix32(uint32_t old,uint32_t x,uint32_t table,int daz){
  x=effective32(x,daz);unsigned r=(table>>(4*token32(x,0)))&15;
  static const uint32_t c[16]={0,0,0,UINT32_C(0xffc00000),UINT32_C(0xff800000),UINT32_C(0x7f800000),0,UINT32_C(0x80000000),0,UINT32_C(0xbf800000),UINT32_C(0x3f800000),UINT32_C(0x3f000000),UINT32_C(0x42b40000),UINT32_C(0x3fc90fdb),UINT32_C(0x7f7fffff),UINT32_C(0xff7fffff)};
  if(r==0)return old;if(r==1)return x;if(r==2)return x|UINT32_C(0x7fc00000);if(r==6)return (x&UINT32_C(0x80000000))|UINT32_C(0x7f800000);return c[r];
}
static uint64_t fix64(uint64_t old,uint64_t x,uint64_t table,int daz){
  x=effective64(x,daz);unsigned r=(table>>(4*token64(x,0)))&15;
  static const uint64_t c[16]={0,0,0,UINT64_C(0xfff8000000000000),UINT64_C(0xfff0000000000000),UINT64_C(0x7ff0000000000000),0,UINT64_C(0x8000000000000000),0,UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0x3fe0000000000000),UINT64_C(0x4056800000000000),UINT64_C(0x3ff921fb54442d18),UINT64_C(0x7fefffffffffffff),UINT64_C(0xffefffffffffffff)};
  if(r==0)return old;if(r==1)return x;if(r==2)return x|UINT64_C(0x7ff8000000000000);if(r==6)return (x&UINT64_C(0x8000000000000000))|UINT64_C(0x7ff0000000000000);return c[r];
}
int main(void){
  const uint32_t src32[16]={UINT32_C(0x7fc12345),1,UINT32_C(0xc0200001),0,UINT32_C(0xff800000),UINT32_C(0x7f800000),UINT32_C(0xc0000000),UINT32_C(0x40000000),UINT32_C(0x80000000),UINT32_C(0x3f800000),UINT32_C(0x7f812345),UINT32_C(0x80000001),UINT32_C(0x40400000),UINT32_C(0xc0800000),UINT32_C(0x3f400000),UINT32_C(0xbf400000)};
  const uint64_t src64[8]={UINT64_C(0x7ff8123456789abc),1,UINT64_C(0xc004000000000001),0,UINT64_C(0xfff0000000000000),UINT64_C(0x7ff0000000000000),UINT64_C(0xc000000000000000),UINT64_C(0x4000000000000000)};
  uint32_t old32[16],table32[16],got32[48],want32[48];uint64_t old64[8],table64[8],got64[10],want64[10];uint8_t out[289];
  const uint64_t mask=UINT64_C(0xa55a);unsigned original=_mm_getcsr();
  for(int i=0;i<16;i++)old32[i]=UINT32_C(0x41000000)+i;for(int i=0;i<8;i++)old64[i]=UINT64_C(0x4020000000000000)+i;
  for(int daz=0;daz<2;daz++){
    _mm_setcsr((original&~64u)|(daz?64u:0));memset(out,0,sizeof(out));
    for(int i=0;i<16;i++)table32[i]=(uint32_t)i<<(4*token32(src32[i],daz));
    for(int i=0;i<8;i++)table64[i]=(uint64_t)(i+8)<<(4*token64(src64[i],daz));
    fixupimmsemantics(out,src32,table32,old32,src64,table64,old64,mask);memcpy(got32,out,192);memcpy(got64,out+192,80);
    for(int i=0;i<16;i++){uint32_t v=fix32(old32[i],src32[i],table32[i],daz);want32[i]=v;want32[16+i]=(mask>>i)&1?v:old32[i];want32[32+i]=(mask>>i)&1?v:0;}
    for(int i=0;i<8;i++)want64[i]=fix64(old64[i],src64[i],table64[i],daz);want64[8]=fix64(old64[0],src64[0],table64[0],daz);want64[9]=src64[1];
    for(int i=0;i<48;i++)if(got32[i]!=want32[i])return 10+daz;
    for(int i=0;i<10;i++)if(got64[i]!=want64[i])return 20+daz;
    uint32_t scalar32[4];memcpy(scalar32,out+272,16);if(scalar32[0]!=fix32(old32[0],src32[0],table32[0],daz)||scalar32[1]!=src32[1]||scalar32[2]!=src32[2]||scalar32[3]!=src32[3])return 30+daz;
    if(out[288]!=1)return 40+daz;
  }
  _mm_setcsr(original);return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fixupimm_semantics", triple, ir, mainC, runPrefix)
}
