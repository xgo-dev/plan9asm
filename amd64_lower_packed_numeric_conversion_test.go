package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type packedNumericConversionTestShape struct {
	source      string
	destination string
}

type packedNumericConversionTestSpec struct {
	op       string
	shapes   []packedNumericConversionTestShape
	explicit string
}

func go127PackedNumericConversionSpecs() []packedNumericConversionTestSpec {
	same := []packedNumericConversionTestShape{{"X", "X"}, {"Y", "Y"}, {"Z", "Z"}}
	widen := []packedNumericConversionTestShape{{"X", "X"}, {"X", "Y"}, {"Y", "Z"}}
	return []packedNumericConversionTestSpec{
		{op: "VCVTPD2QQ", shapes: same, explicit: "round"},
		{op: "VCVTPD2UQQ", shapes: same, explicit: "round"},
		{op: "VCVTTPD2QQ", shapes: same, explicit: "sae"},
		{op: "VCVTTPD2UQQ", shapes: same, explicit: "sae"},
		{op: "VCVTPS2UDQ", shapes: same, explicit: "round"},
		{op: "VCVTTPS2UDQ", shapes: same, explicit: "sae"},
		{op: "VCVTUDQ2PS", shapes: same, explicit: "round"},
		{op: "VCVTQQ2PD", shapes: same, explicit: "round"},
		{op: "VCVTUQQ2PD", shapes: same, explicit: "round"},
		{op: "VCVTPS2QQ", shapes: widen, explicit: "round"},
		{op: "VCVTPS2UQQ", shapes: widen, explicit: "round"},
		{op: "VCVTTPS2QQ", shapes: widen, explicit: "sae"},
		{op: "VCVTTPS2UQQ", shapes: widen, explicit: "sae"},
		{op: "VCVTUDQ2PD", shapes: widen},
		{op: "VCVTPD2UDQX", shapes: []packedNumericConversionTestShape{{"X", "X"}}},
		{op: "VCVTPD2UDQY", shapes: []packedNumericConversionTestShape{{"Y", "X"}}},
		{op: "VCVTPD2UDQ", shapes: []packedNumericConversionTestShape{{"Z", "Y"}}, explicit: "round"},
		{op: "VCVTTPD2UDQX", shapes: []packedNumericConversionTestShape{{"X", "X"}}},
		{op: "VCVTTPD2UDQY", shapes: []packedNumericConversionTestShape{{"Y", "X"}}},
		{op: "VCVTTPD2UDQ", shapes: []packedNumericConversionTestShape{{"Z", "Y"}}, explicit: "sae"},
		{op: "VCVTQQ2PSX", shapes: []packedNumericConversionTestShape{{"X", "X"}}},
		{op: "VCVTQQ2PSY", shapes: []packedNumericConversionTestShape{{"Y", "X"}}},
		{op: "VCVTQQ2PS", shapes: []packedNumericConversionTestShape{{"Z", "Y"}}, explicit: "round"},
		{op: "VCVTUQQ2PSX", shapes: []packedNumericConversionTestShape{{"X", "X"}}},
		{op: "VCVTUQQ2PSY", shapes: []packedNumericConversionTestShape{{"Y", "X"}}},
		{op: "VCVTUQQ2PS", shapes: []packedNumericConversionTestShape{{"Z", "Y"}}, explicit: "round"},
	}
}

func TestAMD64PackedNumericConversionGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := go127PackedNumericConversionSpecs()
	if len(amd64PackedNumericConversionSpecs) != len(expected) {
		t.Fatalf("packed numeric conversion grammar has %d entries, want %d", len(amd64PackedNumericConversionSpecs), len(expected))
	}
	for _, want := range expected {
		if _, ok := amd64PackedNumericConversionSpecs[Op(want.op)]; !ok {
			t.Errorf("packed numeric conversion grammar omitted %s", want.op)
		}
	}
}

func TestTranslateX86PackedNumericConversionCompleteGoAssemblerForms(t *testing.T) {
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
			last := 23
			if target.goarch == "386" {
				last = 7
			}
			var source strings.Builder
			source.WriteString("TEXT packednumericconversionforms(SB),$0-0\n")
			for index, spec := range go127PackedNumericConversionSpecs() {
				for _, shape := range spec.shapes {
					fmt.Fprintf(&source, "\t%s %s1, %s%d\n", spec.op, shape.source, shape.destination, last)
					fmt.Fprintf(&source, "\t%s %d(AX), %s%d\n", spec.op, 8+index*8, shape.destination, last)
					fmt.Fprintf(&source, "\t%s.BCST %d(AX), %s%d\n", spec.op, 16+index*8, shape.destination, last)
					fmt.Fprintf(&source, "\t%s %s2, K1, %s%d\n", spec.op, shape.source, shape.destination, last)
					fmt.Fprintf(&source, "\t%s.Z %d(AX), K2, %s%d\n", spec.op, 24+index*8, shape.destination, last)
					fmt.Fprintf(&source, "\t%s.BCST.Z %d(AX), K3, %s%d\n", spec.op, 32+index*8, shape.destination, last)
				}
				if spec.explicit == "round" {
					shape := spec.shapes[len(spec.shapes)-1]
					for _, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
						fmt.Fprintf(&source, "\t%s.%s %s3, %s%d\n", spec.op, rounding, shape.source, shape.destination, last)
					}
					fmt.Fprintf(&source, "\t%s.RN_SAE.Z %s4, K4, %s%d\n", spec.op, shape.source, shape.destination, last)
				} else if spec.explicit == "sae" {
					shape := spec.shapes[len(spec.shapes)-1]
					fmt.Fprintf(&source, "\t%s.SAE %s3, %s%d\n", spec.op, shape.source, shape.destination, last)
					fmt.Fprintf(&source, "\t%s.SAE.Z %s4, K4, %s%d\n", spec.op, shape.source, shape.destination, last)
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
				Sigs: map[string]FuncSig{"packednumericconversionforms": {Name: "packednumericconversionforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "packed-numeric-conversion-"+target.name+".ll", "packed-numeric-conversion-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PackedNumericConversionRejectsFormsOutsideGoAssemblerTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VCVTPD2QQ X0"},
		{goarch: "amd64", instruction: "VCVTPD2QQ X0, Y1"},
		{goarch: "amd64", instruction: "VCVTPS2QQ Y0, Y1"},
		{goarch: "amd64", instruction: "VCVTUDQ2PD Y0, Y1"},
		{goarch: "amd64", instruction: "VCVTPD2UDQX Y0, X1"},
		{goarch: "amd64", instruction: "VCVTPD2UDQY X0, X1"},
		{goarch: "amd64", instruction: "VCVTPD2UDQ Z0, Z1"},
		{goarch: "amd64", instruction: "VCVTQQ2PSX X0, Y1"},
		{goarch: "amd64", instruction: "VCVTQQ2PSY X0, X1"},
		{goarch: "amd64", instruction: "VCVTQQ2PS Z0, Z1"},
		{goarch: "amd64", instruction: "VCVTUDQ2PS.Z X0, X1"},
		{goarch: "amd64", instruction: "VCVTUDQ2PS X0, K0, X1"},
		{goarch: "amd64", instruction: "VCVTUDQ2PS.BCST X0, X1"},
		{goarch: "amd64", instruction: "VCVTPD2QQ.RN_SAE Y0, Y1"},
		{goarch: "amd64", instruction: "VCVTPD2QQ.RN_SAE 0(AX), Z1"},
		{goarch: "amd64", instruction: "VCVTTPD2QQ.RN_SAE Z0, Z1"},
		{goarch: "amd64", instruction: "VCVTPD2UDQX.RN_SAE X0, X1"},
		{goarch: "386", instruction: "VCVTPD2QQ Z8, Z1"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's packed numeric conversion tables", test.instruction)
			}
		})
	}
}

func TestAMD64PackedNumericConversionRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT packednumericconversionsemantics(SB),$0-64
	MOVQ out+0(FP), AX
	MOVQ f64+8(FP), BX
	MOVQ f32+16(FP), CX
	MOVQ u32+24(FP), DX
	MOVQ i64+32(FP), R8
	MOVQ u64+40(FP), R9
	MOVQ old64+48(FP), R10
	MOVQ mask+56(FP), R11
	KMOVQ R11, K1
	VMOVDQU64 0(BX), Z0
	VCVTPD2QQ Z0, Z1
	VMOVDQU64 Z1, 0(AX)
	VCVTPD2UQQ Z0, Z2
	VMOVDQU64 Z2, 64(AX)
	VCVTPD2QQ.RU_SAE Z0, Z1
	VMOVDQU64 Z1, 128(AX)
	VCVTTPD2UQQ.SAE Z0, Z2
	VMOVDQU64 Z2, 192(AX)
	VMOVDQU32 0(CX), Y3
	VCVTPS2QQ Y3, Z4
	VMOVDQU64 Z4, 256(AX)
	VCVTTPS2UQQ Y3, Z5
	VMOVDQU64 Z5, 320(AX)
	VMOVDQU32 0(CX), Z6
	VCVTPS2UDQ.BCST 0(CX), Z7
	VMOVDQU32 Z7, 384(AX)
	VCVTTPS2UDQ Z6, Z7
	VMOVDQU32 Z7, 448(AX)
	VMOVDQU32 0(DX), Z8
	VCVTUDQ2PS Z8, Z9
	VMOVDQU32 Z9, 512(AX)
	VCVTUDQ2PS.RD_SAE Z8, Z9
	VMOVDQU32 Z9, 576(AX)
	VCVTUDQ2PD 0(DX), Z10
	VMOVDQU64 Z10, 640(AX)
	VMOVDQU64 0(R8), Z11
	VCVTQQ2PD Z11, Z12
	VMOVDQU64 Z12, 704(AX)
	VMOVDQU64 0(R9), Z13
	VCVTUQQ2PD Z13, Z14
	VMOVDQU64 Z14, 768(AX)
	VCVTQQ2PS Z11, Y15
	VMOVDQU32 Y15, 832(AX)
	VCVTUQQ2PS.RU_SAE Z13, Y16
	VMOVDQU32 Y16, 864(AX)
	VMOVDQU64 0(R10), Z17
	VCVTPD2QQ.Z Z0, K1, Z17
	VMOVDQU64 Z17, 896(AX)
	VMOVDQU64 0(BX), X0
	VCVTPD2UDQX X0, X18
	VMOVDQU32 X18, 960(AX)
	VMOVDQU64 0(BX), Y0
	VCVTTPD2UDQY Y0, X19
	VMOVDQU32 X19, 976(AX)
	STC
	SETCS 992(AX)
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
		Sigs: map[string]FuncSig{"packednumericconversionsemantics": {
			Name: "packednumericconversionsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
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
#pragma STDC FENV_ACCESS ON
#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xmmintrin.h>
extern void packednumericconversionsemantics(uint8_t *, const double *, const float *, const uint32_t *, const int64_t *, const uint64_t *, const uint64_t *, uint64_t);
static uint32_t u32(const uint8_t *p){uint32_t v;memcpy(&v,p,4);return v;} static uint64_t u64(const uint8_t *p){uint64_t v;memcpy(&v,p,8);return v;}
static double rd(double x,int truncating,int fixed){if(truncating)return trunc(x);if(fixed==1)return nearbyint(x);int rc=fegetround();return rc==FE_DOWNWARD?floor(x):(rc==FE_UPWARD?ceil(x):(rc==FE_TOWARDZERO?trunc(x):nearbyint(x)));}
static float rf(float x,int truncating){if(truncating)return truncf(x);int rc=fegetround();return rc==FE_DOWNWARD?floorf(x):(rc==FE_UPWARD?ceilf(x):(rc==FE_TOWARDZERO?truncf(x):nearbyintf(x)));}
static uint64_t f64i(double x,int uns,int truncating,int fixed){double r=rd(x,truncating,fixed);if(uns){if(!(r>=0.0&&r<18446744073709551616.0))return UINT64_MAX;return (uint64_t)r;}if(!(r>=-9223372036854775808.0&&r<9223372036854775808.0))return UINT64_C(0x8000000000000000);return (uint64_t)(int64_t)r;}
static uint64_t f32i64(float x,int uns,int truncating){float r=rf(x,truncating);if(uns){if(!(r>=0.0f&&r<18446744073709551616.0f))return UINT64_MAX;return (uint64_t)r;}if(!(r>=-9223372036854775808.0f&&r<9223372036854775808.0f))return UINT64_C(0x8000000000000000);return (uint64_t)(int64_t)r;}
static uint32_t f32u32(float x,int truncating){float r=rf(x,truncating);if(!(r>=0.0f&&r<4294967296.0f))return UINT32_MAX;return (uint32_t)r;}
static uint32_t fb(float x){uint32_t u;memcpy(&u,&x,4);return u;} static uint64_t db(double x){uint64_t u;memcpy(&u,&x,8);return u;}
static float cu32f(uint32_t x){volatile uint32_t v=x;return (float)v;} static double cu32d(uint32_t x){volatile uint32_t v=x;return (double)v;}
static float ci64f(int64_t x){volatile int64_t v=x;return (float)v;} static double ci64d(int64_t x){volatile int64_t v=x;return (double)v;}
static float cu64f(uint64_t x){volatile uint64_t v=x;return (float)v;} static double cu64d(uint64_t x){volatile uint64_t v=x;return (double)v;}
int main(void){
 const double d[8]={1.5,2.5,-1.5,-2.5,9223372036854775808.0,-9223372036854775808.0,18446744073709551616.0,NAN};
 const float f[16]={1.5f,2.5f,-1.5f,-2.5f,0.0f,-0.0f,4294967296.0f,NAN,16777217.0f,2147483648.0f,-2147483904.0f,3.75f,INFINITY,-INFINITY,0x1p-149f,0x1.fffffep127f};
 const uint32_t ui32[16]={0,1,16777215,16777217,UINT32_MAX,2147483648u,3,5,7,9,11,13,15,17,19,21};
 const int64_t si64[8]={0,1,-1,INT64_C(9007199254740993),-INT64_C(9007199254740993),INT64_MAX,INT64_MIN,123456789};
 const uint64_t ui64[8]={0,1,UINT64_C(9007199254740993),UINT64_C(16777217),UINT64_MAX,UINT64_C(1)<<63,3,123456789};
 const uint64_t old[8]={10,11,12,13,14,15,16,17},mask=UINT64_C(0xa5); unsigned original=_mm_getcsr(); const int modes[4]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
 for(int rc=0;rc<4;rc++){uint8_t out[993]={0};fesetround(modes[rc]);packednumericconversionsemantics(out,d,f,ui32,si64,ui64,old,mask);
  for(int i=0;i<8;i++){if(u64(out+i*8)!=f64i(d[i],0,0,0))return 10+rc;if(u64(out+64+i*8)!=f64i(d[i],1,0,0))return 20+rc;
   int save=fegetround();fesetround(FE_UPWARD);uint64_t ru=f64i(d[i],0,0,0);fesetround(save);if(u64(out+128+i*8)!=ru)return 30+rc;if(u64(out+192+i*8)!=f64i(d[i],1,1,0))return 40+rc;
   if(u64(out+256+i*8)!=f32i64(f[i],0,0))return 50+rc;if(u64(out+320+i*8)!=f32i64(f[i],1,1))return 60+rc;}
  for(int i=0;i<16;i++){if(u32(out+384+i*4)!=f32u32(f[0],0))return 70+rc;if(u32(out+448+i*4)!=f32u32(f[i],1))return 80+rc;if(u32(out+512+i*4)!=fb(cu32f(ui32[i])))return 90+rc;
		int save=fegetround();fesetround(FE_DOWNWARD);uint32_t down=fb(cu32f(ui32[i]));fesetround(save);if(u32(out+576+i*4)!=down){fprintf(stderr,"rd rc=%d i=%d got=%08x want=%08x\n",rc,i,u32(out+576+i*4),down);return 100+i;}}
  for(int i=0;i<8;i++){if(u64(out+640+i*8)!=db(cu32d(ui32[i])))return 110+rc;if(u64(out+704+i*8)!=db(ci64d(si64[i])))return 120+rc;if(u64(out+768+i*8)!=db(cu64d(ui64[i])))return 130+rc;if(u32(out+832+i*4)!=fb(ci64f(si64[i])))return 140+rc;
   int save=fegetround();fesetround(FE_UPWARD);uint32_t up=fb(cu64f(ui64[i]));fesetround(save);if(u32(out+864+i*4)!=up)return 150+rc;if(u64(out+896+i*8)!=(((mask>>i)&1)?f64i(d[i],0,0,0):0))return 160+rc;}
  if(u32(out+960)!=f32u32((float)d[0],0)||u32(out+964)!=f32u32((float)d[1],0)||u64(out+968)!=0){fprintf(stderr,"narrow rc=%d got=%08x,%08x,%016llx want=%08x,%08x,0\n",rc,u32(out+960),u32(out+964),(unsigned long long)u64(out+968),f32u32((float)d[0],0),f32u32((float)d[1],0));return 170+rc;}
  for(int i=0;i<4;i++)if(u32(out+976+i*4)!=f32u32((float)d[i],1))return 180+rc;if(out[992]!=1)return 190+rc;
 }
 _mm_setcsr(original);fesetround(FE_TONEAREST);return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_numeric_conversion_semantics", triple, ir, mainC, runPrefix)
}
