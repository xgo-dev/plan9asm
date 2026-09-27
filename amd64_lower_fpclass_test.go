package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64FPClassGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64FPClassSpec{
		"VFPCLASSPDX": {laneBits: 64, bytes: 16},
		"VFPCLASSPDY": {laneBits: 64, bytes: 32},
		"VFPCLASSPDZ": {laneBits: 64, bytes: 64},
		"VFPCLASSPSX": {laneBits: 32, bytes: 16},
		"VFPCLASSPSY": {laneBits: 32, bytes: 32},
		"VFPCLASSPSZ": {laneBits: 32, bytes: 64},
		"VFPCLASSSD":  {laneBits: 64, bytes: 16, scalar: true},
		"VFPCLASSSS":  {laneBits: 32, bytes: 16, scalar: true},
	}
	if len(amd64FPClassSpecs) != len(expected) {
		t.Fatalf("FPCLASS grammar has %d entries, want %d", len(amd64FPClassSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64FPClassSpecs[op]; !ok {
			t.Errorf("FPCLASS grammar omitted %s", op)
		} else if got != want {
			t.Errorf("FPCLASS grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86FPClassCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT fpclassforms(SB),$0-0\n")
			for _, test := range []struct {
				op     string
				width  string
				packed bool
			}{
				{op: "VFPCLASSPDX", width: "X", packed: true},
				{op: "VFPCLASSPDY", width: "Y", packed: true},
				{op: "VFPCLASSPDZ", width: "Z", packed: true},
				{op: "VFPCLASSPSX", width: "X", packed: true},
				{op: "VFPCLASSPSY", width: "Y", packed: true},
				{op: "VFPCLASSPSZ", width: "Z", packed: true},
				{op: "VFPCLASSSD", width: "X"},
				{op: "VFPCLASSSS", width: "X"},
			} {
				last := 31
				if target.goarch == "386" && test.width == "Z" {
					last = 7
				}
				fmt.Fprintf(&source, "\t%s $0, %s%d, K0\n", test.op, test.width, last)
				fmt.Fprintf(&source, "\t%s $255, 8(AX), K7\n", test.op)
				if test.packed {
					fmt.Fprintf(&source, "\t%s.BCST $1, 16(AX), K6\n", test.op)
				}
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\t%s $2, %s%d, K1, K5\n", test.op, test.width, last)
					fmt.Fprintf(&source, "\t%s $3, 24(AX), K2, K4\n", test.op)
					if test.packed {
						fmt.Fprintf(&source, "\t%s.BCST $4, 32(AX), K3, K0\n", test.op)
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
				Sigs: map[string]FuncSig{"fpclassforms": {Name: "fpclassforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "fpclass-"+target.name+".ll", "fpclass-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FPClassRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VFPCLASSPSX $-1, X0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX $256, X0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX X0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX $1, Y0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSY $1, X0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPDZ $1, Y0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSZ.BCST $1, Z0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSSS.BCST $1, 0(AX), K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX.Z $1, X0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX $1, X0, K0, K1"},
		{goarch: "amd64", instruction: "VFPCLASSPSX $1, X0, X1"},
		{goarch: "386", instruction: "VFPCLASSPSX $1, X0, K1, K2"},
		{goarch: "386", instruction: "VFPCLASSPSX $1, X32, K1"},
		{goarch: "386", instruction: "VFPCLASSPSZ $1, Z8, K1"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's FPCLASS table", test.instruction)
			}
		})
	}
}

func TestAMD64FPClassRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	var source strings.Builder
	source.WriteString(`TEXT fpclasssemantics(SB),$0-32
	MOVQ out+0(FP), AX
	MOVQ source32+8(FP), BX
	MOVQ source64+16(FP), CX
	MOVQ mask+24(FP), DX
	KMOVQ DX, K1
	STC
`)
	for category := 0; category < 8; category++ {
		immediate := 1 << category
		fmt.Fprintf(&source, "\tVFPCLASSPSZ $%d, 0(BX), K2\n", immediate)
		fmt.Fprintf(&source, "\tKMOVQ K2, %d(AX)\n", category*8)
		fmt.Fprintf(&source, "\tVFPCLASSPDZ $%d, 0(CX), K2\n", immediate)
		fmt.Fprintf(&source, "\tKMOVQ K2, %d(AX)\n", 64+category*8)
		fmt.Fprintf(&source, "\tVFPCLASSSS $%d, %d(BX), K2\n", immediate, category*4)
		fmt.Fprintf(&source, "\tKMOVQ K2, %d(AX)\n", 128+category*8)
		fmt.Fprintf(&source, "\tVFPCLASSSD $%d, %d(CX), K2\n", immediate, category*8)
		fmt.Fprintf(&source, "\tKMOVQ K2, %d(AX)\n", 192+category*8)
	}
	source.WriteString(`	VFPCLASSPSZ $255, 0(BX), K1, K2
	KMOVQ K2, 256(AX)
	VFPCLASSPSZ.BCST $1, 0(BX), K2
	KMOVQ K2, 264(AX)
	SETCS 272(AX)
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
		Sigs: map[string]FuncSig{"fpclasssemantics": {
			Name: "fpclasssemantics", Args: []LLVMType{Ptr, Ptr, Ptr, I64}, Ret: Void,
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
#include <xmmintrin.h>
extern void fpclasssemantics(uint8_t *, const uint32_t *, const uint64_t *, uint64_t);
static uint64_t u64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  const uint32_t source32[16]={
    0x7fc12345,0x00000000,0x80000000,0x7f800000,
    0xff800000,0x00000001,0xbf800000,0x7f812345,
    0x3f800000,0x40000000,0x00800000,0x7f7fffff,
    0x3f000000,0x40400000,0x3f800001,0x3f800002};
  const uint64_t source64[8]={
    UINT64_C(0x7ff8123456789abc),UINT64_C(0),UINT64_C(0x8000000000000000),UINT64_C(0x7ff0000000000000),
    UINT64_C(0xfff0000000000000),UINT64_C(1),UINT64_C(0xbff0000000000000),UINT64_C(0x7ff0123456789abc)};
  uint8_t out[273]={0}, outDaz[273]={0};
  fpclasssemantics(out,source32,source64,UINT64_C(0xa5));
	unsigned oldCsr=_mm_getcsr();
	_mm_setcsr(oldCsr|UINT32_C(0x40));
	fpclasssemantics(outDaz,source32,source64,UINT64_C(0xa5));
	_mm_setcsr(oldCsr);
  for (int category=0;category<8;category++) {
    uint64_t bit=UINT64_C(1)<<category;
    if (u64(out+category*8)!=bit) return 10+category;
    if (u64(out+64+category*8)!=bit) return 20+category;
    if (u64(out+128+category*8)!=1) return 30+category;
    if (u64(out+192+category*8)!=1) return 40+category;
  }
  if (u64(out+256)!=UINT64_C(0xa5)) return 50;
  if (u64(out+264)!=UINT64_C(0xffff)) return 51;
  if (out[272]!=1) return 52;
  if (u64(outDaz+8)!=UINT64_C(0x22) || u64(outDaz+40)!=0) return 53;
  if (u64(outDaz+72)!=UINT64_C(0x22) || u64(outDaz+104)!=0) return 54;
  if (u64(outDaz+168)!=0 || u64(outDaz+232)!=0) return 55;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "fpclass_semantics", triple, ir, mainC, runPrefix)
}
