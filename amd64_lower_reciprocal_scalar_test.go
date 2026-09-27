package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateX86ScalarReciprocalCompleteGo127FormsAcrossTargets(t *testing.T) {
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
			legacyLast := 15
			if target.goarch == "386" {
				legacyLast = 7
			}
			const vexLast = 15
			var source strings.Builder
			source.WriteString("DATA scalarreciprocaldata+0(SB)/4, $0\n")
			source.WriteString("GLOBL scalarreciprocaldata(SB), $4\n")
			source.WriteString("TEXT scalarreciprocalforms(SB),$0-4\n")
			for _, op := range []string{"RCPSS", "RSQRTSS"} {
				fmt.Fprintf(&source, "\t%s X1, X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s scalarreciprocaldata(SB), X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s arg+0(FP), X%d\n", op, legacyLast)
				fmt.Fprintf(&source, "\t%s 0, X%d\n", op, legacyLast)
			}
			for _, op := range []string{"VRCPSS", "VRSQRTSS"} {
				fmt.Fprintf(&source, "\t%s X1, X2, X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s 8(AX), X2, X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s scalarreciprocaldata(SB), X2, X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s arg+0(FP), X2, X%d\n", op, vexLast)
				fmt.Fprintf(&source, "\t%s 0, X2, X%d\n", op, vexLast)
				if target.goarch == "386" {
					// Go's VEX register classes retain their 16-register
					// compatibility closure even in 32-bit mode.
					fmt.Fprintf(&source, "\t%s 16(R9), X13, X14\n", op)
				}
			}
			if target.goarch == "amd64" {
				for _, op := range []string{"RCPSS", "RSQRTSS"} {
					fmt.Fprintf(&source, "\t%s 16(R11)(R12*2), X13\n", op)
				}
				for _, op := range []string{"VRCPSS", "VRSQRTSS"} {
					fmt.Fprintf(&source, "\t%s 16(R11)(R12*2), X13, X14\n", op)
				}
			}
			source.WriteString("\tRET\n")

			requireX86GoAssemblerResult(t, target.goarch, source.String(), true)
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: target.triple,
				Goarch:       target.goarch,
				Sigs: map[string]FuncSig{
					"scalarreciprocalforms": {
						Name: "scalarreciprocalforms", Args: []LLVMType{LLVMType("float")}, Ret: Void,
						Frame: FrameLayout{Params: []FrameSlot{{Offset: 0, Type: LLVMType("float"), Index: 0, Field: -1}}},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.x86.sse.rcp.ps", "@llvm.x86.sse.rsqrt.ps",
				"extractelement <4 x float>", "insertelement <4 x float>",
				`"target-features"="+avx,+sse"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("scalar reciprocal lowering omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, target.triple, "scalar-reciprocal-"+target.name+".ll", "scalar-reciprocal-"+target.name+".o", ir)
		})
	}
}

func TestAMD64ScalarReciprocalRuntimeSemantics(t *testing.T) {
	crossRosetta := runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" && rosettaAvailable()
	if runtime.GOARCH != "amd64" && !crossRosetta {
		t.Skip("runtime execution test requires amd64 or Rosetta")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT scalarreciprocalsemantics(SB),$0-24
	MOVQ out+0(FP), DI
	MOVQ source+8(FP), AX
	MOVQ upper+16(FP), BX

	MOVUPS (BX), X0
	STC
	RCPSS (AX), X0
	MOVUPS X0, 0(DI)
	SETCS 64(DI)

	MOVUPS (BX), X1
	STC
	RSQRTSS (AX), X1
	MOVUPS X1, 16(DI)
	SETCS 65(DI)

	MOVUPS (BX), X2
	STC
	VRCPSS (AX), X2, X3
	MOVUPS X3, 32(DI)
	SETCS 66(DI)

	MOVUPS (BX), X4
	STC
	VRSQRTSS (AX), X4, X5
	MOVUPS X5, 48(DI)
	SETCS 67(DI)
	VZEROUPPER
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
			"scalarreciprocalsemantics": {
				Name: "scalarreciprocalsemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void scalarreciprocalsemantics(uint8_t *, const float *, const float *);
static int close_enough(float got, float want) {
  float delta = got - want;
  if (delta < 0) delta = -delta;
  return delta < 0.01f;
}
int main(void) {
  float source[4] = {4.0f, 100.0f, 200.0f, 300.0f};
  float upper[4] = {99.0f, 10.0f, 20.0f, 30.0f};
  uint8_t out[68] = {0};
  scalarreciprocalsemantics(out, source, upper);
  const float *values = (const float *)out;
  for (int vector = 0; vector < 4; ++vector) {
    float want = (vector & 1) ? 0.5f : 0.25f;
    if (!close_enough(values[4*vector], want)) return 10+vector;
    if (values[4*vector+1] != 10.0f || values[4*vector+2] != 20.0f || values[4*vector+3] != 30.0f) return 20+vector;
    if (out[64+vector] != 1) return 30+vector;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "scalar_reciprocal_semantics", triple, ir, mainC, runPrefix)
}

func TestTranslateX86ScalarReciprocalRejectsFormsOutsideGo127Tables(t *testing.T) {
	for _, test := range []struct {
		goarch      string
		instruction string
	}{
		{goarch: "amd64", instruction: "RCPSS X0"},
		{goarch: "amd64", instruction: "RSQRTSS X0, X1, X2"},
		{goarch: "amd64", instruction: "RCPSS Y0, X1"},
		{goarch: "amd64", instruction: "RCPSS X0, X16"},
		{goarch: "amd64", instruction: "VRCPSS X0, X1"},
		{goarch: "amd64", instruction: "VRSQRTSS X0, X1, Y2"},
		{goarch: "amd64", instruction: "VRCPSS Y0, X1, X2"},
		{goarch: "amd64", instruction: "VRCPSS.Z X0, X1, X2"},
		{goarch: "amd64", instruction: "VRSQRTSS X0, X1, K1, X2"},
		{goarch: "386", instruction: "RCPSS X0, X8"},
		{goarch: "386", instruction: "RSQRTSS 8(R9), X0"},
		{goarch: "386", instruction: "VRCPSS X16, X1, X2"},
		{goarch: "386", instruction: "VRSQRTSS X0, X1, X16"},
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
				TargetTriple: triple,
				Goarch:       test.goarch,
				Sigs:         map[string]FuncSig{"bad": {Name: "bad", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's scalar reciprocal tables for %s", test.instruction, test.goarch)
			}
		})
	}
}
