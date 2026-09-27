package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64QwordBitLookupGrammarCoversCompleteGoFamilies(t *testing.T) {
	expected := map[Op]amd64QwordBitLookupSpec{
		"VPMULTISHIFTQB": {output: amd64QwordBitLookupBytes, broadcast: true},
		"VPSHUFBITQMB":   {output: amd64QwordBitLookupMask},
	}
	if len(amd64QwordBitLookupSpecs) != len(expected) {
		t.Fatalf("qword-bit-lookup grammar has %d entries, want %d", len(amd64QwordBitLookupSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64QwordBitLookupSpecs[op]; !ok {
			t.Errorf("qword-bit-lookup grammar omitted %s", op)
		} else if got != want {
			t.Errorf("qword-bit-lookup grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86QwordBitLookupCompleteGoAssemblerForms(t *testing.T) {
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
			source.WriteString("TEXT qwordbitlookupforms(SB),$0-0\n")
			for _, width := range []string{"X", "Y", "Z"} {
				last := 31
				if target.goarch == "386" && width == "Z" {
					last = 7
				}
				fmt.Fprintf(&source, "\tVPMULTISHIFTQB %s1, %s2, %s%d\n", width, width, width, last)
				fmt.Fprintf(&source, "\tVPMULTISHIFTQB 8(AX), %s2, %s%d\n", width, width, last)
				fmt.Fprintf(&source, "\tVPMULTISHIFTQB.BCST 16(AX), %s2, %s%d\n", width, width, last)
				fmt.Fprintf(&source, "\tVPSHUFBITQMB %s1, %s2, K0\n", width, width)
				fmt.Fprintf(&source, "\tVPSHUFBITQMB 24(AX), %s2, K7\n", width)
				if target.goarch == "amd64" {
					fmt.Fprintf(&source, "\tVPMULTISHIFTQB %s1, %s2, K1, %s%d\n", width, width, width, last)
					fmt.Fprintf(&source, "\tVPMULTISHIFTQB.Z 32(AX), %s2, K2, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVPMULTISHIFTQB.BCST.Z 40(AX), %s2, K3, %s%d\n", width, width, last)
					fmt.Fprintf(&source, "\tVPSHUFBITQMB %s1, %s2, K4, K7\n", width, width)
					fmt.Fprintf(&source, "\tVPSHUFBITQMB 48(AX), %s2, K5, K6\n", width)
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
				Sigs: map[string]FuncSig{"qwordbitlookupforms": {Name: "qwordbitlookupforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, target.triple, "qword-bit-lookup-"+target.name+".ll", "qword-bit-lookup-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86QwordBitLookupRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "VPMULTISHIFTQB X0, Y1, Y2"},
		{goarch: "amd64", instruction: "VPMULTISHIFTQB.BCST X0, X1, X2"},
		{goarch: "amd64", instruction: "VPMULTISHIFTQB.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VPMULTISHIFTQB X0, X1, K0, X2"},
		{goarch: "amd64", instruction: "VPMULTISHIFTQB X0, X1, 0(AX)"},
		{goarch: "amd64", instruction: "VPSHUFBITQMB.Z X0, X1, K2"},
		{goarch: "amd64", instruction: "VPSHUFBITQMB.BCST 0(AX), X1, K2"},
		{goarch: "amd64", instruction: "VPSHUFBITQMB X0, Y1, K2"},
		{goarch: "amd64", instruction: "VPSHUFBITQMB X0, X1, K0, K2"},
		{goarch: "amd64", instruction: "VPSHUFBITQMB X0, X1, AX"},
		{goarch: "386", instruction: "VPMULTISHIFTQB X0, X1, K1, X2"},
		{goarch: "386", instruction: "VPSHUFBITQMB X0, X1, K1, K2"},
		{goarch: "386", instruction: "VPMULTISHIFTQB Z0, Z1, Z8"},
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
				t.Fatalf("Translate accepted %q outside Go 1.27's qword-bit-lookup table", test.instruction)
			}
		})
	}
}

func TestAMD64QwordBitLookupRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT qwordbitlookupsemantics(SB),$0-40
	MOVQ out+0(FP), AX
	MOVQ data+8(FP), BX
	MOVQ controls+16(FP), CX
	MOVQ old+24(FP), DX
	MOVQ mask+32(FP), R8
	KMOVQ R8, K1
	VMOVDQU64 0(BX), Z0
	VMOVDQU64 0(CX), Z1
	VMOVDQU64 0(DX), Z2
	STC
	VPMULTISHIFTQB Z0, Z1, Z3
	VMOVDQU64 Z3, 0(AX)
	VPMULTISHIFTQB Z0, Z1, K1, Z2
	VMOVDQU64 Z2, 64(AX)
	VPMULTISHIFTQB.Z Z0, Z1, K1, Z3
	VMOVDQU64 Z3, 128(AX)
	VPMULTISHIFTQB.BCST 0(BX), Z1, Z3
	VMOVDQU64 Z3, 192(AX)
	VPSHUFBITQMB Z1, Z0, K2
	KMOVQ K2, 256(AX)
	VPSHUFBITQMB Z1, Z0, K1, K3
	KMOVQ K3, 264(AX)
	SETCS 272(AX)
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
		Sigs: map[string]FuncSig{"qwordbitlookupsemantics": {
			Name: "qwordbitlookupsemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr, I64}, Ret: Void,
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
extern void qwordbitlookupsemantics(uint8_t *, const uint8_t *, const uint8_t *, const uint8_t *, uint64_t);
static uint64_t ror64(uint64_t value, unsigned count) {
  count &= 63u;
  return (value >> count) | (value << ((0u-count)&63u));
}
static uint64_t load64(const uint8_t *p) { uint64_t v; memcpy(&v,p,8); return v; }
int main(void) {
  uint64_t data64[8], controls64[8], old64[8], output64[35] = {0};
  uint8_t *data=(uint8_t *)data64, *controls=(uint8_t *)controls64;
  uint8_t *old=(uint8_t *)old64, *out=(uint8_t *)output64;
  const uint64_t mask=UINT64_C(0xa55af00ff00fa55a);
  for (int q=0;q<8;q++) data64[q]=UINT64_C(0x0123456789abcdef)^((uint64_t)q*UINT64_C(0x11100f0e0d0c0b0a));
  for (int i=0;i<64;i++) { controls[i]=(uint8_t)(13u*(unsigned)i+((unsigned)i>>2)); old[i]=(uint8_t)(0xe0u-(unsigned)i); }
  qwordbitlookupsemantics(out,data,controls,old,mask);
  uint64_t gathered=0;
  for (int i=0;i<64;i++) {
    uint64_t qword=data64[i/8];
    uint8_t selected=(uint8_t)ror64(qword,controls[i]);
    if (out[i]!=selected) return 10;
    if (out[64+i]!=(((mask>>i)&1u)?selected:old[i])) return 11;
    if (out[128+i]!=(((mask>>i)&1u)?selected:0)) return 12;
    uint8_t broadcast=(uint8_t)ror64(data64[0],controls[i]);
    if (out[192+i]!=broadcast) return 13;
    gathered|=((qword>>(controls[i]&63u))&1u)<<i;
  }
  if (load64(out+256)!=gathered) return 20;
  if (load64(out+264)!=(gathered&mask)) return 21;
  if (out[272]!=1) return 22;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "qword_bit_lookup_semantics", triple, ir, mainC, runPrefix)
}
