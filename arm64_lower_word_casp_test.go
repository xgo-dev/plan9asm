package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64EncodeRawCASP(bits int, acquire, release bool, expected, newValue, base int) uint32 {
	word := uint32(0x08207c00)
	if bits == 64 {
		word |= 1 << 30
	}
	if acquire {
		word |= 1 << 22
	}
	if release {
		word |= 1 << 15
	}
	return word | uint32(expected)<<16 | uint32(base)<<5 | uint32(newValue)
}

func TestTranslateARM64RawCASPCompleteArchitecturalFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawcaspforms(SB),$0-0\n")
	for _, bits := range []int{32, 64} {
		for _, order := range []struct{ acquire, release bool }{
			{}, {acquire: true}, {release: true}, {acquire: true, release: true},
		} {
			for _, registers := range []struct{ expected, newValue, base int }{{0, 2, 4}, {30, 28, 31}} {
				word := arm64EncodeRawCASP(bits, order.acquire, order.release, registers.expected, registers.newValue, registers.base)
				decoded, ok := decodeARM64RawCASP(word)
				if !ok || decoded.elementBits != bits || decoded.acquire != order.acquire || decoded.release != order.release ||
					decoded.expected != registers.expected || decoded.newValue != registers.newValue || decoded.base != registers.base {
					t.Fatalf("decode CASP word %#08x = %+v, ok=%v", word, decoded, ok)
				}
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawcaspforms": {Name: "rawcaspforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, ordering := range []string{"monotonic monotonic", "acquire acquire", "release monotonic", "acq_rel acquire"} {
				if !strings.Contains(ir, ordering) {
					t.Fatalf("raw CASP lowering for %s omitted %q:\n%s", triple, ordering, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-casp.ll", "arm64-raw-casp.o", ir)
		})
	}
}

func TestARM64RawCASPDecoderRejectsAdjacentAndInvalidPairs(t *testing.T) {
	for _, word := range []uint32{
		0x08217c02, // odd expected-pair start.
		0x08207c01, // odd new-value-pair start.
		0x08207800, // adjacent opcode bits.
		0x88207c00, // single-register CAS instruction class.
	} {
		if _, ok := decodeARM64RawCASP(word); ok {
			t.Fatalf("CASP decoder accepted adjacent/invalid encoding %#08x", word)
		}
	}
}

func TestARM64RawCASPRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawcaspl(SB),$0-32
	MOVD memory+0(FP), R4
	MOVD expected+8(FP), R5
	MOVD desired+16(FP), R6
	MOVD observed+24(FP), R7
	MOVD 0(R5), R0
	MOVD 8(R5), R1
	MOVD 0(R6), R2
	MOVD 8(R6), R3
	WORD $0x4820fc82 // CASPL X0, X1, X2, X3, [X4]
	MOVD R0, 0(R7)
	MOVD R1, 8(R7)
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
		Sigs: map[string]FuncSig{
			"rawcaspl": {
				Name: "rawcaspl", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawcaspl(uint64_t *, const uint64_t *, const uint64_t *, uint64_t *);
int main(void) {
  _Alignas(16) uint64_t memory[2] = {11,22};
  const uint64_t success_expected[2] = {11,22};
  const uint64_t failure_expected[2] = {10,22};
  const uint64_t desired[2] = {33,44};
  uint64_t observed[2] = {0,0};
  rawcaspl(memory, success_expected, desired, observed);
  if (memory[0] != 33 || memory[1] != 44 || observed[0] != 11 || observed[1] != 22) return 1;
  memory[0] = 11; memory[1] = 22; observed[0] = 0; observed[1] = 0;
  rawcaspl(memory, failure_expected, desired, observed);
  if (memory[0] != 11 || memory[1] != 22 || observed[0] != 11 || observed[1] != 22) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_casp", triple, ir, mainC, nil)
}
