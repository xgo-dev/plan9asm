package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64RawDUPElementForTest(bits, element, source, destination int, q bool) uint32 {
	position := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[bits]
	imm5 := element<<(position+1) | 1<<position
	word := uint32(0x0e000400 | imm5<<16 | source<<5 | destination)
	if q {
		word |= 1 << 30
	}
	return word
}

func TestTranslateARM64RawDUPElementCompleteAdvancedSIMDFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawdupelementforms(SB),$0-0\n")
	for _, form := range []struct {
		bits    int
		element int
		q       bool
	}{{8, 15, false}, {8, 15, true}, {16, 7, false}, {16, 7, true}, {32, 3, false}, {32, 3, true}, {64, 1, true}} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawDUPElementForTest(form.bits, form.element, 1, 16, form.q))
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawdupelementforms": {Name: "rawdupelementforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"extractelement", "shufflevector", "<8 x i8>", "<16 x i8>", "<4 x i16>", "<8 x i16>", "<2 x i32>", "<4 x i32>", "<2 x i64>"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw DUP-element lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-dup-element.ll", "arm64-raw-dup-element.o", ll)
		})
	}
}

func TestARM64RawDUPElementDecoderCoversEveryLane(t *testing.T) {
	for _, bits := range []int{8, 16, 32, 64} {
		for element := 0; element < 128/bits; element++ {
			for _, q := range []bool{false, true} {
				if bits == 64 && !q {
					continue
				}
				word := encodeARM64RawDUPElementForTest(bits, element, 7, 23, q)
				form, ok := decodeARM64RawDUPElement(word)
				if !ok || form.arrangement.elementBits != bits || form.element != element || form.source != 7 || form.destination != 23 {
					t.Fatalf("decode DUP element bits=%d lane=%d q=%v: form=%#v ok=%v", bits, element, q, form, ok)
				}
			}
		}
	}
}

func TestARM64RawDUPElementRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawdupelement(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V1.S4]
	WORD $0x4e040430 // DUP V16.4S, V1.S[0]
	VST1 [V16.S4], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"rawdupelement": {
				Name: "rawdupelement", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawdupelement(const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t input[4] = {0x12345678u, 2, 3, 4};
  uint32_t got[4] = {0};
  rawdupelement(input, got);
  for (int i = 0; i < 4; i++) if (got[i] != input[0]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_dup_element", triple, ll, mainC, nil)
}

func TestARM64RawDUPElementDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x4e040c20, // DUP from W register.
		0x5e040420, // Scalar DUP from vector element.
		encodeARM64RawDUPElementForTest(64, 0, 1, 0, false), // Reserved D1 vector form.
	} {
		t.Run(fmt.Sprintf("%08x", word), func(t *testing.T) {
			if _, ok := decodeARM64RawDUPElement(word); ok {
				t.Fatalf("DUP-element decoder claimed adjacent/reserved encoding %#08x", word)
			}
		})
	}
}
