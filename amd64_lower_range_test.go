package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64FloatingRangeGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64FloatingRangeSpec{
		"VRANGEPS": {laneBits: 32},
		"VRANGEPD": {laneBits: 64},
		"VRANGESS": {laneBits: 32, scalar: true},
		"VRANGESD": {laneBits: 64, scalar: true},
	}
	if len(amd64FloatingRangeSpecs) != len(expected) {
		t.Fatalf("floating-range grammar has %d entries, want %d", len(amd64FloatingRangeSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64FloatingRangeSpecs[op]; !ok {
			t.Errorf("floating-range grammar omitted %s", op)
		} else if got != want {
			t.Errorf("floating-range grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86FloatingRangeCompleteGoAssemblerForms(t *testing.T) {
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{name: "darwin-amd64", goarch: "amd64", triple: "x86_64-apple-darwin"},
		{name: "linux-amd64", goarch: "amd64", triple: "x86_64-unknown-linux-gnu"},
		{name: "windows-amd64", goarch: "amd64", triple: "x86_64-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT floatingrangeforms(SB),$0-0\n")
			for _, op := range []string{"VRANGEPS", "VRANGEPD"} {
				for _, width := range []string{"X", "Y", "Z"} {
					last := 31
					if target.goarch == "386" {
						last = 7
					}
					fmt.Fprintf(&source, "\t%s $0, %s1, %s2, %s%d\n", op, width, width, width, last)
					fmt.Fprintf(&source, "\t%s $255, 8(AX), %s2, %s%d\n", op, width, width, last)
					fmt.Fprintf(&source, "\t%s.BCST $2, 16(AX), %s2, %s%d\n", op, width, width, last)
					if target.goarch == "amd64" {
						fmt.Fprintf(&source, "\t%s $3, %s1, %s2, K1, %s%d\n", op, width, width, width, last)
						fmt.Fprintf(&source, "\t%s.Z $4, 24(AX), %s2, K2, %s%d\n", op, width, width, last)
						fmt.Fprintf(&source, "\t%s.BCST.Z $5, 32(AX), %s2, K3, %s%d\n", op, width, width, last)
						if width == "Z" {
							fmt.Fprintf(&source, "\t%s.SAE $6, Z1, Z2, Z%d\n", op, last)
							fmt.Fprintf(&source, "\t%s.SAE.Z $7, Z1, Z2, K4, Z%d\n", op, last)
						}
					}
				}
			}
			for _, op := range []string{"VRANGESS", "VRANGESD"} {
				last := 31
				if target.goarch == "386" {
					last = 7
				}
				fmt.Fprintf(&source, "\t%s $8, X1, X2, X%d\n", op, last)
				fmt.Fprintf(&source, "\t%s $9, 40(AX), X2, X%d\n", op, last)
				fmt.Fprintf(&source, "\t%s.SAE $10, X1, X2, X%d\n", op, last)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $11, X1, X2, K5, X%d\n", op, last)
					fmt.Fprintf(&source, "\t%s.Z $12, 48(AX), X2, K6, X%d\n", op, last)
					fmt.Fprintf(&source, "\t%s.SAE.Z $13, X1, X2, K7, X%d\n", op, last)
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
				Sigs: map[string]FuncSig{"floatingrangeforms": {Name: "floatingrangeforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "floating-range-"+target.name+".ll", "floating-range-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FloatingRangeRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VRANGEPS $-1, X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS $256, X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS $0, X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VRANGEPS.BCST $0, X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS.SAE $0, X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGESD.SAE $0, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS.RN_SAE $0, Z0, Z1, Z2"},
		{goarch: "amd64", instruction: "VRANGEPS.Z $0, X0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGEPS $0, X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VRANGESS $0, Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRANGESS.BCST $0, 0(AX), X1, X2"},
		{goarch: "amd64", instruction: "VRANGESD $0, X0, X1, Y2"},
		{goarch: "386", instruction: "VRANGEPS $0, X0, X1, X2"},
		{goarch: "386", instruction: "VRANGEPS $0, X0, X1, K1, X2"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's floating-range table", test.instruction)
			}
		})
	}
}

func TestAMD64FloatingRangeRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString(`TEXT floatingrangesemantics(SB),$0-40
	MOVQ out+0(FP), AX
	MOVQ source2+8(FP), BX
	MOVQ source1+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ mask+32(FP), R8
	KMOVQ R8, K1
	VMOVDQU32 0(BX), Z0
	VMOVDQU32 0(CX), Z1
	STC
`)
	for immediate := 0; immediate < 16; immediate++ {
		fmt.Fprintf(&source, "\tVRANGEPS $%d, Z0, Z1, Z2\n", immediate)
		fmt.Fprintf(&source, "\tVMOVDQU32 Z2, %d(AX)\n", immediate*64)
	}
	source.WriteString(`	VMOVDQU32 0(DX), Z2
	VRANGEPS $2, Z0, Z1, K1, Z2
	VMOVDQU32 Z2, 1024(AX)
	VRANGEPS.Z $3, Z0, Z1, K1, Z2
	VMOVDQU32 Z2, 1088(AX)
	VRANGEPS.BCST $2, 0(BX), Z1, Z2
	VMOVDQU32 Z2, 1152(AX)
	SETCS 1216(AX)
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
		Sigs: map[string]FuncSig{"floatingrangesemantics": {
			Name: "floatingrangesemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void floatingrangesemantics(uint8_t *, const uint32_t *, const uint32_t *, const uint32_t *, uint64_t);
static float f32(uint32_t u) { float f; memcpy(&f,&u,4); return f; }
static uint32_t range32(uint32_t a, uint32_t b, unsigned imm) {
  const uint32_t sign=UINT32_C(0x80000000), absMask=UINT32_C(0x7fffffff);
  const uint32_t quiet=UINT32_C(0x00400000), inf=UINT32_C(0x7f800000);
  uint32_t aa=a&absMask, ab=b&absMask, tmp;
  int nanA=aa>inf, nanB=ab>inf, snanA=nanA && !(a&quiet), snanB=nanB && !(b&quiet);
  unsigned op=imm&3, signs=(imm>>2)&3;
  if (nanB) tmp=a;
  else if (nanA) tmp=b;
  else if (((a^b)&sign) && aa==0 && ab==0) tmp=(op&1)?0:sign;
  else if (((a^b)&sign) && aa==ab && op>=2) tmp=(op&1)?aa:(aa|sign);
  else {
    int le=op>=2 ? f32(aa)<=f32(ab) : f32(a)<=f32(b);
    tmp=(op&1) ? (le?b:a) : (le?a:b);
  }
  if (signs==0) tmp=(tmp&absMask)|(a&sign);
  else if (signs==2) tmp&=absMask;
  else if (signs==3) tmp|=sign;
  if (snanB) tmp=b|quiet;
  if (snanA) tmp=a|quiet;
  return tmp;
}
int main(void) {
  const uint32_t source1[16]={
    0x00000000,0x80000000,0x3f800000,0xbf800000,
    0x40000000,0xc0000000,0x40400000,0xc0800000,
    0x7f800000,0xff800000,0x7fc12345,0xffc23456,
    0x7f812345,0xff823456,0x3f000000,0xbf400000};
  const uint32_t source2[16]={
    0x80000000,0x00000000,0xbf800000,0x3f800000,
    0xc0400000,0x3f000000,0xc0400000,0x40a00000,
    0x7f000000,0xff000000,0x3f800000,0x7fc34567,
    0x40000000,0x7f834567,0xbf000000,0x3fc00000};
  uint32_t old[16], out[305];
  const uint64_t mask=UINT64_C(0xa55a);
  for (int i=0;i<16;i++) old[i]=UINT32_C(0x41000000)+(uint32_t)i;
  memset(out,0,sizeof(out));
  floatingrangesemantics((uint8_t*)out,source2,source1,old,mask);
  for (unsigned imm=0;imm<16;imm++) for (int i=0;i<16;i++)
    if (out[imm*16+i]!=range32(source1[i],source2[i],imm)) return 10+(int)imm;
  for (int i=0;i<16;i++) {
    uint32_t r2=range32(source1[i],source2[i],2);
    uint32_t r3=range32(source1[i],source2[i],3);
    if (out[256+i]!=(((mask>>i)&1)?r2:old[i])) return 40;
    if (out[272+i]!=(((mask>>i)&1)?r3:0)) return 41;
    if (out[288+i]!=range32(source1[i],source2[0],2)) return 42;
  }
  if (((uint8_t*)out)[1216]!=1) return 43;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "floating_range_semantics", triple, ir, mainC, runPrefix)
}

func TestAMD64FloatingRangeDoubleAndScalarRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString(`TEXT floatingrangedoublesemantics(SB),$0-40
	MOVQ out+0(FP), AX
	MOVQ source2+8(FP), BX
	MOVQ source1+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ mask+32(FP), R8
	KMOVQ R8, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	STC
`)
	for immediate := 0; immediate < 16; immediate++ {
		fmt.Fprintf(&source, "\tVRANGEPD $%d, Z0, Z1, Z2\n", immediate)
		fmt.Fprintf(&source, "\tVMOVDQU64 Z2, %d(AX)\n", immediate*64)
	}
	source.WriteString(`	VMOVDQU64 0(BX), X0
	VMOVDQU64 0(CX), X1
	VMOVDQU64 0(DX), X2
	VRANGESD $2, X0, X1, X2
	VMOVDQU64 X2, 1024(AX)
	VMOVDQU64 0(DX), X2
	VRANGESD $2, X0, X1, K1, X2
	VMOVDQU64 X2, 1040(AX)
	VRANGESD.Z $2, X0, X1, K1, X2
	VMOVDQU64 X2, 1056(AX)
	SETCS 1072(AX)
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
		Sigs: map[string]FuncSig{"floatingrangedoublesemantics": {
			Name: "floatingrangedoublesemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				{Offset: 32, Type: I64, Index: 4, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void floatingrangedoublesemantics(uint8_t *, const uint64_t *, const uint64_t *, const uint64_t *, uint64_t);
static double f64(uint64_t u) { double f; memcpy(&f,&u,8); return f; }
static uint64_t range64(uint64_t a, uint64_t b, unsigned imm) {
  const uint64_t sign=UINT64_C(0x8000000000000000), absMask=UINT64_C(0x7fffffffffffffff);
  const uint64_t quiet=UINT64_C(0x0008000000000000), inf=UINT64_C(0x7ff0000000000000);
  uint64_t aa=a&absMask, ab=b&absMask, tmp;
  int nanA=aa>inf, nanB=ab>inf, snanA=nanA && !(a&quiet), snanB=nanB && !(b&quiet);
  unsigned op=imm&3, signs=(imm>>2)&3;
  if (nanB) tmp=a;
  else if (nanA) tmp=b;
  else if (((a^b)&sign) && aa==0 && ab==0) tmp=(op&1)?0:sign;
  else if (((a^b)&sign) && aa==ab && op>=2) tmp=(op&1)?aa:(aa|sign);
  else {
    int le=op>=2 ? f64(aa)<=f64(ab) : f64(a)<=f64(b);
    tmp=(op&1) ? (le?b:a) : (le?a:b);
  }
  if (signs==0) tmp=(tmp&absMask)|(a&sign);
  else if (signs==2) tmp&=absMask;
  else if (signs==3) tmp|=sign;
  if (snanB) tmp=b|quiet;
  if (snanA) tmp=a|quiet;
  return tmp;
}
int main(void) {
  const uint64_t source1[8]={
    UINT64_C(0),UINT64_C(0x8000000000000000),UINT64_C(0x3ff0000000000000),UINT64_C(0xbff0000000000000),
    UINT64_C(0x7ff8123456789abc),UINT64_C(0xfff823456789abcd),UINT64_C(0x7ff0123456789abc),UINT64_C(0xfff023456789abcd)};
  const uint64_t source2[8]={
    UINT64_C(0x8000000000000000),UINT64_C(0),UINT64_C(0xbff0000000000000),UINT64_C(0x3ff0000000000000),
    UINT64_C(0x4000000000000000),UINT64_C(0x7ff83456789abcde),UINT64_C(0x4008000000000000),UINT64_C(0x7ff0456789abcdef)};
  const uint64_t old[8]={UINT64_C(0x4020000000000000),UINT64_C(0x4030000000000000),0,0,0,0,0,0};
  uint64_t out[135];
  memset(out,0,sizeof(out));
  floatingrangedoublesemantics((uint8_t*)out,source2,source1,old,0);
  for (unsigned imm=0;imm<16;imm++) for (int i=0;i<8;i++)
    if (out[imm*8+i]!=range64(source1[i],source2[i],imm)) return 10+(int)imm;
  if (out[128]!=range64(source1[0],source2[0],2)) return 40;
  if (out[129]!=source1[1]) return 44;
  if (out[130]!=old[0] || out[131]!=source1[1]) return 41;
  if (out[132]!=0 || out[133]!=source1[1]) return 42;
  if (((uint8_t*)out)[1072]!=1) return 43;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "floating_range_double_scalar_semantics", triple, ir, mainC, runPrefix)
}
