package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawScalarVectorFCVTZCompleteFamily(t *testing.T) {
	forms := []struct {
		name       string
		encoding   uint32
		irFragment string
	}{
		{"FCVTZS H", 0x5ef9b800, "@llvm.fptosi.sat.i16.f16"},
		{"FCVTZS S", 0x5ea1b800, "@llvm.fptosi.sat.i32.f32"},
		{"FCVTZS D", 0x5ee1b800, "@llvm.fptosi.sat.i64.f64"},
		{"FCVTZU H", 0x7ef9b800, "@llvm.fptoui.sat.i16.f16"},
		{"FCVTZU S", 0x7ea1b800, "@llvm.fptoui.sat.i32.f32"},
		{"FCVTZU D", 0x7ee1b800, "@llvm.fptoui.sat.i64.f64"},
	}
	for _, form := range forms {
		for sourceReg := 0; sourceReg < 32; sourceReg++ {
			for destinationReg := 0; destinationReg < 32; destinationReg++ {
				word := form.encoding | uint32(sourceReg)<<5 | uint32(destinationReg)
				decoded, ok := decodeARM64RawScalarVectorFCVTZ(word)
				if !ok || decoded.source != sourceReg || decoded.destination != destinationReg {
					t.Fatalf("%s register fields not decoded for %#08x: %+v, ok=%v", form.name, word, decoded, ok)
				}
			}
		}
	}

	var source strings.Builder
	source.WriteString("TEXT rawscalarvectorfcvtz(SB),$0-0\n")
	for _, form := range forms {
		word := form.encoding | 31<<5 | 30
		fmt.Fprintf(&source, "\tWORD $%#08x // %s F31, F30\n", word, form.name)
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
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-unknown-freebsd",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawscalarvectorfcvtz": {Name: "rawscalarvectorfcvtz", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, form := range forms {
				if !strings.Contains(ir, form.irFragment) {
					t.Fatalf("%s IR omitted %q", form.name, form.irFragment)
				}
			}
			if !strings.Contains(ir, `"target-features"="+fullfp16"`) {
				t.Fatal("scalar half conversion IR omitted +fullfp16")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-vector-fcvtz.ll", "arm64-raw-scalar-vector-fcvtz.o", ir)
		})
	}
}

func TestARM64RawScalarVectorFCVTZRuntime(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("native ARM64 runtime required")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawscalarvectorfcvtzruntime(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V1.S4]
	WORD $0x5ea1b820 // FCVTZS S1, S0
	VST1 [V0.S4], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawscalarvectorfcvtzruntime": {
			Name: "rawscalarvectorfcvtzruntime", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawscalarvectorfcvtzruntime(const float *, uint32_t *);
int main(void) {
  const float input[4] = {3.75f};
  uint32_t output[4] = {0};
  rawscalarvectorfcvtzruntime(input, output);
  return output[0] == 3 ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_scalar_vector_fcvtz", triple, ir, mainC, nil)
}

func TestARM64RawScalarVectorFCVTZRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x4ea1b800, // Four-lane vector FCVTZS, not scalar.
		0x1e380000, // FCVTZS to a general-purpose register.
		0x5ea1d800, // Scalar FRECPE, not a conversion.
		0x5ee9b800, // Reserved size/opcode combination.
	} {
		if _, ok := decodeARM64RawScalarVectorFCVTZ(word); ok {
			t.Fatalf("scalar vector FCVTZ decoder accepted adjacent encoding %#08x", word)
		}
	}
}
