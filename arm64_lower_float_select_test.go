package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64FloatConditionalSelectCompleteGoAssemblerForms(t *testing.T) {
	conditions := []string{"EQ", "NE", "HS", "LO", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
	var source strings.Builder
	source.WriteString("TEXT floatconditionalselectforms(SB),$0-0\n\tCMP R0, R1\n")
	for _, op := range []string{"FCSELS", "FCSELD"} {
		for _, condition := range conditions {
			source.WriteString("\t" + op + " " + condition + ", F0, F1, F31\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"floatconditionalselectforms": {Name: "floatconditionalselectforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"select i1", "float", "double"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("floating conditional-select family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-float-conditional-select.ll", "arm64-float-conditional-select.o", ir)
		})
	}
}

func TestTranslateARM64FloatConditionalSelectRejectsFormsOutsideGoOptab(t *testing.T) {
	for _, instruction := range []string{
		"FCSELS EQ, F0, F1",
		"FCSELD EQ, F0, F1, F2, F3",
		"FCSELS BAD, F0, F1, F2",
		"FCSELS EQ, R0, F1, F2",
		"FCSELD EQ, F0, (R1), F2",
		"FCSELS.P EQ, F0, F1, F2",
	} {
		source := "TEXT badfloatconditionalselect(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
			Sigs: map[string]FuncSig{"badfloatconditionalselect": {Name: "badfloatconditionalselect", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted %q outside Go 1.27's FCSEL optab", instruction)
		}
	}
}

func TestARM64FloatConditionalSelectRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT floatconditionalselect(SB),$0-24
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	MOVD flag+16(FP), R2
	FMOVS 0(R0), F0
	FMOVS 4(R0), F1
	FMOVD 8(R0), F2
	FMOVD 16(R0), F3
	CMP $0, R2
	FCSELS GT, F0, F1, F4
	FCSELD LE, F2, F3, F5
	FMOVS F4, 0(R1)
	FMOVD F5, 8(R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"floatconditionalselect": {
			Name: "floatconditionalselect", Args: []LLVMType{Ptr, Ptr, I64}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
struct input { float a, b; double c, d; };
struct output { float s; uint32_t pad; double d; };
extern void floatconditionalselect(const struct input *, struct output *, uint64_t);
int main(void) {
  const struct input input = {1.25f, -2.5f, 3.75, -4.5};
  struct output positive = {0}, zero = {0};
  floatconditionalselect(&input, &positive, 1);
  floatconditionalselect(&input, &zero, 0);
  if (positive.s != input.a || positive.d != input.d) return 1;
  if (zero.s != input.b || zero.d != input.c) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_float_conditional_select", triple, ir, mainC, nil)
}
