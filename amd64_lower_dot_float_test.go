package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestAMD64PackedFloatingDotGrammarCoversCompleteGoFamily(t *testing.T) {
	expected := map[Op]amd64PackedFloatingDotSpec{
		"DPPD":  {form: amd64PackedFloatingDotLegacy, laneBits: 64},
		"DPPS":  {form: amd64PackedFloatingDotLegacy, laneBits: 32},
		"VDPPD": {form: amd64PackedFloatingDotVEX128, laneBits: 64},
		"VDPPS": {form: amd64PackedFloatingDotVEX128Or256, laneBits: 32},
	}
	if len(amd64PackedFloatingDotSpecs) != len(expected) {
		t.Fatalf("floating dot grammar has %d entries, want %d", len(amd64PackedFloatingDotSpecs), len(expected))
	}
	for op, want := range expected {
		if got, ok := amd64PackedFloatingDotSpecs[op]; !ok {
			t.Errorf("floating dot grammar omitted %s", op)
		} else if got != want {
			t.Errorf("floating dot grammar %s = %+v, want %+v", op, got, want)
		}
	}
}

func TestTranslateX86PackedFloatingDotCompleteFormsAcrossTargets(t *testing.T) {
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
			last := 15
			if target.goarch == "386" {
				last = 7
			}
			var sourceBuilder strings.Builder
			sourceBuilder.WriteString("TEXT floatdotforms(SB),$0-0\n")
			fmt.Fprintf(&sourceBuilder, "\tDPPD $0x31, X0, X%d\n", last)
			fmt.Fprintf(&sourceBuilder, "\tDPPD $0x31, 0(AX), X%d\n", last)
			fmt.Fprintf(&sourceBuilder, "\tDPPS $0xf1, X0, X%d\n", last)
			fmt.Fprintf(&sourceBuilder, "\tDPPS $0xf1, 16(AX), X%d\n", last)
			if target.goarch == "amd64" {
				fmt.Fprintf(&sourceBuilder, "\tVDPPD $0x31, X0, X1, X%d\n", last)
				fmt.Fprintf(&sourceBuilder, "\tVDPPD $0x31, 32(AX), X1, X%d\n", last)
				fmt.Fprintf(&sourceBuilder, "\tVDPPS $0xf1, X0, X1, X%d\n", last)
				fmt.Fprintf(&sourceBuilder, "\tVDPPS $0xf1, 48(AX), X1, X%d\n", last)
				fmt.Fprintf(&sourceBuilder, "\tVDPPS $0xf1, Y0, Y1, Y%d\n", last)
				fmt.Fprintf(&sourceBuilder, "\tVDPPS $0xf1, 64(AX), Y1, Y%d\n", last)
			}
			sourceBuilder.WriteString("\tRET\n")
			source := sourceBuilder.String()
			requireX86GoAssemblerResult(t, target.goarch, source, true)
			file, err := Parse(ArchAMD64, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"floatdotforms": {Name: "floatdotforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"call <2 x double> @llvm.x86.sse41.dppd",
				"call <4 x float> @llvm.x86.sse41.dpps",
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("packed floating dot lowering omitted %q:\n%s", want, ir)
				}
			}
			if target.goarch == "amd64" && !strings.Contains(ir, "call <8 x float> @llvm.x86.avx.dp.ps.256") {
				t.Fatalf("packed floating dot lowering omitted Y-width intrinsic:\n%s", ir)
			}
			wantFeatures := `"target-features"="+sse4.1"`
			if target.goarch == "amd64" {
				wantFeatures = `"target-features"="+avx,+sse4.1"`
			}
			if !strings.Contains(ir, wantFeatures) {
				t.Fatalf("packed floating dot lowering omitted %s:\n%s", wantFeatures, ir)
			}
			compileLLVMToObject(t, llc, target.triple, "float-dot-"+target.name+".ll", "float-dot-"+target.name+".o", ir)
		})
	}
}

func TestTranslateX86PackedFloatingDotRejectsFormsOutsideGoTables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "DPPD $-1, X0, X1"},
		{goarch: "amd64", instruction: "DPPD $256, X0, X1"},
		{goarch: "amd64", instruction: "DPPS.Z $1, X0, X1"},
		{goarch: "amd64", instruction: "DPPD $1, Y0, Y1"},
		{goarch: "amd64", instruction: "VDPPD $1, Y0, Y1, Y2"},
		{goarch: "amd64", instruction: "VDPPS $1, Z0, Z1, Z2"},
		{goarch: "amd64", instruction: "VDPPS $1, X0, Y1, Y2"},
		{goarch: "386", instruction: "DPPD $1, X0, X8"},
		{goarch: "386", instruction: "VDPPS $1, Y0, Y1, Y2"},
		{goarch: "386", instruction: "VDPPS $1, Y0, Y1, Y8"},
		{goarch: "386", instruction: "VDPPS $1, 8(R9), Y1, Y2"},
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
				Goarch:       test.goarch,
				TargetTriple: triple,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside the Go table for %s", test.instruction, test.goarch)
			}
		})
	}
}

func TestAMD64PackedFloatingDotRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT floatdotsemantics(SB),$0-24
	MOVQ out+0(FP), AX
	MOVQ a+8(FP), CX
	MOVQ b+16(FP), DX
	MOVUPS 0(CX), X0
	MOVUPS 0(DX), X1
	STC
	DPPS $0xf1, X0, X1
	MOVUPS X1, 0(AX)
	SETCS 16(AX)
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
		Goarch:       "amd64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"floatdotsemantics": {
				Name: "floatdotsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void floatdotsemantics(uint8_t *, const float *, const float *);
int main(void) {
  uint8_t out[17] = {0};
  const float a[4] = {1.0f, 2.0f, 3.0f, 4.0f};
  const float b[4] = {5.0f, 6.0f, 7.0f, 8.0f};
  float got[4];
  floatdotsemantics(out, a, b);
  memcpy(got, out, 16);
  if (got[0] != 70.0f || got[1] != 0.0f || got[2] != 0.0f || got[3] != 0.0f) return 10;
  if (out[16] != 1) return 11;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "packed_float_dot_semantics", triple, ir, mainC, runPrefix)
}
