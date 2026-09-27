package plan9asm

import (
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestAMD64FourSourceGrammarIsComplete(t *testing.T) {
	got := make([]string, 0, len(amd64FourSourceSpecs))
	for op := range amd64FourSourceSpecs {
		got = append(got, string(op))
	}
	sort.Strings(got)
	want := []string{"V4FMADDPS", "V4FMADDSS", "V4FNMADDPS", "V4FNMADDSS", "VP4DPWSSD", "VP4DPWSSDS"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("four-source grammar opcodes = %v, want %v", got, want)
	}
}

func TestTranslateX86FourSourceCompleteGoAssemblerForms(t *testing.T) {
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
			source := `TEXT foursourceforms(SB),$0-0
	V4FMADDPS (BX), [Z0-Z3], Z4
	V4FNMADDPS 32(BX), [Z0-Z3], Z5
	V4FMADDSS 64(BX), [X0-X3], X4
	V4FNMADDSS 96(BX), [X0-X3], X5
	VP4DPWSSD 128(BX), [Z0-Z3], Z6
	VP4DPWSSDS 160(BX), [Z0-Z3], Z7
`
			if target.goarch == "amd64" {
				source += `	V4FMADDPS 8(BX), [Z2-Z5], K7, Z4
	V4FMADDPS.Z 16(BX), [Z2-Z5], K1, Z4
	V4FNMADDPS 40(BX), [Z2-Z5], K7, Z5
	V4FNMADDPS.Z 48(BX), [Z2-Z5], K2, Z5
	V4FMADDSS 72(BX), [X2-X5], K7, X4
	V4FMADDSS.Z 80(BX), [X2-X5], K3, X4
	V4FNMADDSS 104(BX), [X2-X5], K7, X5
	V4FNMADDSS.Z 112(BX), [X2-X5], K4, X5
	VP4DPWSSD 136(BX), [Z2-Z5], K7, Z6
	VP4DPWSSD.Z 144(BX), [Z2-Z5], K5, Z6
	VP4DPWSSDS 168(BX), [Z2-Z5], K7, Z7
	VP4DPWSSDS.Z 176(BX), [Z2-Z5], K6, Z7
`
			}
			source += "\tRET\n"
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch: target.goarch, TargetTriple: target.triple,
				Sigs: map[string]FuncSig{"foursourceforms": {Name: "foursourceforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "four-source-"+target.name+".ll", "four-source-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86FourSourceRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "V4FMADDPS Z0, [Z0-Z3], Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS (AX), [Z0-Z2], Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS (AX), [Z0,Z1,Z2,Z3], Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS (AX), [X0-X3], Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS (AX), [Z0-Z3], K0, Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS.Z (AX), [Z0-Z3], Z4"},
		{goarch: "amd64", instruction: "V4FMADDPS.BCST (AX), [Z0-Z3], Z4"},
		{goarch: "amd64", instruction: "V4FMADDSS (AX), [X0-X3], Z4"},
		{goarch: "amd64", instruction: "VP4DPWSSD (AX), [Z0-Z3], X4"},
		{goarch: "386", instruction: "VP4DPWSSD (AX), [Z6-Z9], Z4"},
	} {
		t.Run(test.goarch+"_"+strings.NewReplacer(" ", "_", "$", "").Replace(test.instruction), func(t *testing.T) {
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
				t.Fatalf("Translate accepted %q outside Go 1.27's four-source tables", test.instruction)
			}
		})
	}
}

func TestAMD64FourSourceRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT foursourcesemantics(SB),NOSPLIT,$0-24
	MOVQ in+0(FP), AX
	MOVQ out+8(FP), BX
	MOVQ mask+16(FP), CX
	VBROADCASTSS 0(AX), Z0
	VBROADCASTSS 16(AX), Z1
	VBROADCASTSS 32(AX), Z2
	VBROADCASTSS 48(AX), Z3
	VBROADCASTSS 64(AX), Z4
	V4FMADDPS 128(AX), [Z2-Z5], Z4
	VMOVUPS Z4, 0(BX)
	VBROADCASTSS 64(AX), Z5
	KMOVQ CX, K1
	V4FNMADDPS.Z 128(AX), [Z0-Z3], K1, Z5
	VMOVUPS Z5, 64(BX)
	MOVUPS 0(AX), X0
	MOVUPS 16(AX), X1
	MOVUPS 32(AX), X2
	MOVUPS 48(AX), X3
	MOVUPS 64(AX), X6
	V4FMADDSS 128(AX), [X0-X3], X6
	MOVUPS X6, 128(BX)
	VMOVDQU64 192(AX), Z0
	VMOVDQU64 256(AX), Z1
	VMOVDQU64 320(AX), Z2
	VMOVDQU64 384(AX), Z3
	VMOVDQU64 448(AX), Z7
	VP4DPWSSD 144(AX), [Z0-Z3], Z7
	VMOVDQU64 Z7, 144(BX)
	VMOVDQU64 448(AX), Z7
	VP4DPWSSDS 144(AX), [Z0-Z3], Z7
	VMOVDQU64 Z7, 208(BX)
	RET

TEXT foursourcefaultsuppression(SB),NOSPLIT,$0-24
	MOVQ memory+0(FP), AX
	MOVQ out+8(FP), BX
	MOVQ mask+16(FP), CX
	KMOVQ CX, K1
	V4FMADDPS.Z (AX), [Z0-Z3], K1, Z4
	VMOVUPS Z4, 0(BX)
	V4FMADDSS.Z (AX), [X0-X3], K1, X4
	MOVUPS X4, 64(BX)
	VP4DPWSSD.Z (AX), [Z0-Z3], K1, Z5
	VMOVUPS Z5, 80(BX)
	RET
`
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
		Sigs: map[string]FuncSig{
			"foursourcesemantics": {
				Name: "foursourcesemantics", Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
			"foursourcefaultsuppression": {
				Name: "foursourcefaultsuppression", Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: I64, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <limits.h>
#include <stdint.h>
#include <string.h>
extern void foursourcesemantics(void *, void *, uint64_t);
extern void foursourcefaultsuppression(void *, void *, uint64_t);
static void putf(uint8_t *p, float v) { memcpy(p, &v, 4); }
static float getf(const uint8_t *p) { float v; memcpy(&v, p, 4); return v; }
static void put16(uint8_t *p, int16_t v) { memcpy(p, &v, 2); }
static void put32(uint8_t *p, int32_t v) { memcpy(p, &v, 4); }
static int32_t get32(const uint8_t *p) { int32_t v; memcpy(&v, p, 4); return v; }
int main(void) {
  uint8_t in[512] = {0}, out[272] = {0}, faultOut[144] = {1};
  for (int r=0;r<4;r++) for (int lane=0;lane<4;lane++) putf(in+r*16+lane*4, (float)(r+1));
  for (int lane=0;lane<4;lane++) putf(in+64+lane*4, 10.0f+(float)lane);
  putf(in+128, 1); putf(in+132, 2); putf(in+136, 3); putf(in+140, 4);
  for (int r=0;r<4;r++) for (int lane=0;lane<32;lane++) put16(in+192+r*64+lane*2, (int16_t)(r+1));
  put16(in+144, 1); put16(in+146, 2); put16(in+148, 3); put16(in+150, 4);
  put16(in+152, 5); put16(in+154, 6); put16(in+156, 7); put16(in+158, 8);
  for (int lane=0;lane<16;lane++) put32(in+448+lane*4, lane==0 ? INT_MAX-5 : lane);
  foursourcesemantics(in, out, 5);
  foursourcefaultsuppression(0, faultOut, 0);
	if (getf(out) != 40 || getf(out+4) != 40 || getf(out+8) != 40 || getf(out+12) != 40) return 10;
	if (getf(out+64) != -20) return 21;
	if (getf(out+68) != 0) return 22;
	if (getf(out+72) != -20) return 23;
	if (getf(out+76) != 0) return 24;
  if (getf(out+128) != 40 || getf(out+132) != 11 || getf(out+136) != 12 || getf(out+140) != 13) return 12;
	if (get32(out+144) != INT_MIN+104 || get32(out+148) != 111) return 13;
	if (get32(out+208) != INT_MAX || get32(out+212) != 111) return 14;
	for (int i=0;i<144;i++) if (faultOut[i] != 0) return 15;
	return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "four_source_semantics", triple, ir, mainC, runPrefix)
}
