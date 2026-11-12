package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawScalarHalfUnaryCompleteFamily(t *testing.T) {
	operations := []struct {
		name       string
		encoding   uint32
		irFragment string
	}{
		{"FABS", 0x1ee0c000, "@llvm.fabs.f16"},
		{"FNEG", 0x1ee14000, "fneg half"},
		{"FSQRT", 0x1ee1c000, "@llvm.sqrt.f16"},
		{"FRINTA", 0x1ee64000, "@llvm.round.f16"},
		{"FRINTI", 0x1ee7c000, "@llvm.nearbyint.f16"},
		{"FRINTM", 0x1ee54000, "@llvm.floor.f16"},
		{"FRINTN", 0x1ee44000, "@llvm.roundeven.f16"},
		{"FRINTP", 0x1ee4c000, "@llvm.ceil.f16"},
		{"FRINTX", 0x1ee74000, "@llvm.rint.f16"},
		{"FRINTZ", 0x1ee5c000, "@llvm.trunc.f16"},
	}
	for _, operation := range operations {
		for sourceReg := 0; sourceReg < 32; sourceReg++ {
			for destinationReg := 0; destinationReg < 32; destinationReg++ {
				word := operation.encoding | uint32(sourceReg)<<5 | uint32(destinationReg)
				form, ok := decodeARM64RawScalarHalfUnary(word)
				if !ok || form.source != sourceReg || form.destination != destinationReg {
					t.Fatalf("%s register fields not decoded for %#08x: %+v, ok=%v", operation.name, word, form, ok)
				}
			}
		}
	}

	var source strings.Builder
	source.WriteString("TEXT rawscalarhalfunary(SB),$0-0\n")
	for _, operation := range operations {
		word := operation.encoding | 31<<5 | 30
		fmt.Fprintf(&source, "\tWORD $%#08x // %s H31, H30\n", word, operation.name)
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
					"rawscalarhalfunary": {Name: "rawscalarhalfunary", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range operations {
				if !strings.Contains(ir, operation.irFragment) {
					t.Fatalf("%s IR omitted %q:\n%s", operation.name, operation.irFragment, ir)
				}
			}
			if !strings.Contains(ir, `"target-features"="+fullfp16"`) {
				t.Fatalf("scalar half IR omitted +fullfp16:\n%s", ir)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-half-unary.ll", "arm64-raw-scalar-half-unary.o", ir)
		})
	}
}

func TestARM64RawScalarHalfUnaryRuntime(t *testing.T) {
	if runtime.GOARCH != "arm64" {
		t.Skip("native ARM64 runtime required")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawscalarhalfneg(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V1.H8]
	WORD $0x1ee14020 // FNEG H1, H0
	VST1 [V0.H8], (R1)
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
		Sigs: map[string]FuncSig{"rawscalarhalfneg": {
			Name: "rawscalarhalfneg", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawscalarhalfneg(const uint16_t *, uint16_t *);
int main(void) {
  const uint16_t input[8] = {0x3c00};
  uint16_t output[8] = {0};
  rawscalarhalfneg(input, output);
  return output[0] == 0xbc00 ? 0 : 1;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_scalar_half_neg", triple, ir, mainC, nil)
}

func TestARM64RawScalarHalfUnaryRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1e20c000, // Single-precision FABS belongs to the named Go family.
		0x1e60c000, // Double-precision FABS belongs to the named Go family.
		0x1ee24000, // Reserved scalar half unary opcode.
		0x5ef9d800, // Scalar half FRECPE is a different instruction family.
	} {
		if _, ok := decodeARM64RawScalarHalfUnary(word); ok {
			t.Fatalf("scalar half unary decoder accepted adjacent encoding %#08x", word)
		}
	}
}
