package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawFloatMultiplyLongTestOperation struct {
	name        string
	vectorBase  uint32
	elementBase uint32
	subtract    bool
	highHalf    bool
}

var arm64RawFloatMultiplyLongTestOperations = []arm64RawFloatMultiplyLongTestOperation{
	{name: "FMLAL", vectorBase: 0x0e20ec00, elementBase: 0x0f800000},
	{name: "FMLAL2", vectorBase: 0x2e20cc00, elementBase: 0x2f808000, highHalf: true},
	{name: "FMLSL", vectorBase: 0x0ea0ec00, elementBase: 0x0f804000, subtract: true},
	{name: "FMLSL2", vectorBase: 0x2ea0cc00, elementBase: 0x2f80c000, subtract: true, highHalf: true},
}

func encodeARM64RawFloatMultiplyLongVector(base uint32, lanes, second, first, destination int) uint32 {
	word := base | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
	if lanes == 4 {
		word |= 1 << 30
	}
	return word
}

func encodeARM64RawFloatMultiplyLongElement(base uint32, lanes, lane, element, first, destination int) uint32 {
	word := base | uint32(element&15)<<16 | uint32(first)<<5 | uint32(destination)
	if lanes == 4 {
		word |= 1 << 30
	}
	word |= uint32(lane&1) << 20
	word |= uint32((lane>>1)&1) << 21
	word |= uint32((lane>>2)&1) << 11
	return word
}

func TestTranslateARM64RawFloatMultiplyLongCompleteArchitecturalFamily(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawfloatmultiplylongforms(SB),$0-0\n")
	for _, operation := range arm64RawFloatMultiplyLongTestOperations {
		for _, lanes := range []int{2, 4} {
			word := encodeARM64RawFloatMultiplyLongVector(operation.vectorBase, lanes, 31, 30, 29)
			fmt.Fprintf(&source, "\tWORD $%#08x // %s vector %dS\n", word, operation.name, lanes)
			for lane := 0; lane < 8; lane++ {
				word = encodeARM64RawFloatMultiplyLongElement(operation.elementBase, lanes, lane, 15, 28, 27)
				fmt.Fprintf(&source, "\tWORD $%#08x // %s element %dS lane %d\n", word, operation.name, lanes, lane)
			}
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
				Sigs: map[string]FuncSig{"rawfloatmultiplylongforms": {Name: "rawfloatmultiplylongforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"fpext <2 x half>", "fpext <4 x half>", "@llvm.fma.v2f32", "@llvm.fma.v4f32", "extractelement <8 x half>", "shufflevector", "+fp16fml"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw floating multiply-long family for %s omitted %q:\n%s", triple, want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-multiply-long.ll", "arm64-raw-float-multiply-long.o", ir)
		})
	}
}

func TestARM64RawFloatMultiplyLongDecoderCoversEveryEncodingField(t *testing.T) {
	for _, operation := range arm64RawFloatMultiplyLongTestOperations {
		for _, lanes := range []int{2, 4} {
			for destination := 0; destination < 32; destination++ {
				word := encodeARM64RawFloatMultiplyLongVector(operation.vectorBase, lanes, 31-destination, destination, destination)
				got, ok := decodeARM64RawFloatMultiplyLong(word)
				if !ok || got.byElement || got.lanes != lanes || got.first != destination || got.second != 31-destination || got.destination != destination || got.subtract != operation.subtract || got.highHalf != operation.highHalf {
					t.Fatalf("decode %s vector %#08x = %#v, %v", operation.name, word, got, ok)
				}
			}
			for lane := 0; lane < 8; lane++ {
				for element := 0; element < 16; element++ {
					word := encodeARM64RawFloatMultiplyLongElement(operation.elementBase, lanes, lane, element, 31-element, element)
					got, ok := decodeARM64RawFloatMultiplyLong(word)
					if !ok || !got.byElement || got.lanes != lanes || got.lane != lane || got.first != 31-element || got.second != element || got.destination != element || got.subtract != operation.subtract || got.highHalf != operation.highHalf {
						t.Fatalf("decode %s element %#08x = %#v, %v", operation.name, word, got, ok)
					}
				}
			}
		}
	}
}

func TestARM64RawFloatMultiplyLongDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0e20e800, 0x0e20f000, 0x2e20ec00,
		0x0f800400, 0x0f801000, 0x2f800000,
	} {
		if _, ok := decodeARM64RawFloatMultiplyLong(word); ok {
			t.Fatalf("floating multiply-long decoder accepted adjacent encoding %#08x", word)
		}
	}
}

func TestARM64RawFloatMultiplyLongRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	words := []uint32{
		encodeARM64RawFloatMultiplyLongVector(0x0e20ec00, 4, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongVector(0x2e20cc00, 4, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongVector(0x0ea0ec00, 4, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongVector(0x2ea0cc00, 4, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongElement(0x0f800000, 4, 7, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongElement(0x2f808000, 4, 3, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongElement(0x0f804000, 4, 1, 2, 1, 0),
		encodeARM64RawFloatMultiplyLongElement(0x2f80c000, 4, 6, 2, 1, 0),
	}
	var source strings.Builder
	source.WriteString(`TEXT rawfloatmultiplylong(SB),$0-32
	MOVD source+0(FP), R0
	MOVD elements+8(FP), R1
	MOVD accumulator+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V1.H8]
	VLD1 (R1), [V2.H8]
`)
	for _, word := range words {
		source.WriteString("\tVLD1 (R2), [V0.S4]\n")
		fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		source.WriteString("\tVST1 [V0.S4], (R3)\n\tADD $16, R3\n")
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{"rawfloatmultiplylong": {
			Name: "rawfloatmultiplylong", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatmultiplylong(const _Float16 *, const _Float16 *, const float *, float *);
int main(void) {
  const _Float16 source[8] = {1,2,3,4,5,6,7,8};
  const _Float16 elements[8] = {10,20,30,40,50,60,70,80};
  const float accumulator[4] = {1000,2000,3000,4000};
  float got[32] = {0};
  float want[32] = {0};
  rawfloatmultiplylong(source, elements, accumulator, got);
  for (int i = 0; i < 4; i++) {
    want[0*4+i] = accumulator[i] + (float)source[i] * (float)elements[i];
    want[1*4+i] = accumulator[i] + (float)source[i+4] * (float)elements[i+4];
    want[2*4+i] = accumulator[i] - (float)source[i] * (float)elements[i];
    want[3*4+i] = accumulator[i] - (float)source[i+4] * (float)elements[i+4];
    want[4*4+i] = accumulator[i] + (float)source[i] * (float)elements[7];
    want[5*4+i] = accumulator[i] + (float)source[i+4] * (float)elements[3];
    want[6*4+i] = accumulator[i] - (float)source[i] * (float)elements[1];
    want[7*4+i] = accumulator[i] - (float)source[i+4] * (float)elements[6];
  }
  for (int i = 0; i < 32; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_multiply_long", triple, ir, mainC, nil)
}
