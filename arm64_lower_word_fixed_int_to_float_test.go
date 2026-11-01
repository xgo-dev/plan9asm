package plan9asm

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func TestARM64RawFixedIntToFloatDecoderCompleteFamily(t *testing.T) {
	check := func(word uint32, want arm64RawFixedIntToFloat) {
		t.Helper()
		var code [4]byte
		binary.LittleEndian.PutUint32(code[:], word)
		if _, err := arm64asm.Decode(code[:]); err != nil {
			t.Fatalf("Go's architecture decoder rejected %#08x: %v", word, err)
		}
		got, ok := decodeARM64RawFixedIntToFloat(word)
		if !ok || got != want {
			t.Fatalf("decode %#08x = %+v, %v; want %+v", word, got, ok, want)
		}
	}
	for _, unsigned := range []bool{false, true} {
		for _, integerBits := range []int{32, 64} {
			for _, floatBits := range []int{32, 64} {
				for _, fractionalBits := range []int{1, integerBits / 2, integerBits} {
					for _, register := range []int{0, 31} {
						word := uint32(0x1e020000 | (64-fractionalBits)<<10 | register<<5 | register)
						if integerBits == 64 {
							word |= 1 << 31
						}
						if floatBits == 64 {
							word |= 1 << 22
						}
						if unsigned {
							word |= 1 << 16
						}
						check(word, arm64RawFixedIntToFloat{
							unsigned: unsigned, scalar: true, integerBits: integerBits,
							fractionalBits: fractionalBits, vectorBits: floatBits,
							source: register, destination: register,
						})
					}
				}
			}
		}
	}
	for _, unsigned := range []bool{false, true} {
		for _, integerBits := range []int{32, 64} {
			for _, fractionalBits := range []int{1, integerBits / 2, integerBits} {
				for _, register := range []int{0, 31} {
					shift := uint32(2*integerBits-fractionalBits) << 16
					word := uint32(0x5f00e400|register<<5|register) | shift
					if unsigned {
						word |= 1 << 29
					}
					check(word, arm64RawFixedIntToFloat{
						unsigned: unsigned, scalar: true, vectorSource: true,
						integerBits: integerBits, fractionalBits: fractionalBits,
						vectorBits: integerBits, source: register, destination: register,
					})
				}
			}
		}
	}
	for _, unsigned := range []bool{false, true} {
		for _, arrangement := range []struct{ integerBits, vectorBits int }{
			{32, 64}, {32, 128}, {64, 128},
		} {
			for _, fractionalBits := range []int{1, arrangement.integerBits / 2, arrangement.integerBits} {
				for _, register := range []int{0, 31} {
					shift := uint32(2*arrangement.integerBits-fractionalBits) << 16
					word := uint32(0x0f00e400|register<<5|register) | shift
					if unsigned {
						word |= 1 << 29
					}
					if arrangement.vectorBits == 128 {
						word |= 1 << 30
					}
					check(word, arm64RawFixedIntToFloat{
						unsigned: unsigned, vectorSource: true,
						integerBits: arrangement.integerBits, fractionalBits: fractionalBits,
						vectorBits: arrangement.vectorBits, source: register, destination: register,
					})
				}
			}
		}
	}
}

func TestARM64RawFixedIntToFloatDecoderRejectsOtherForms(t *testing.T) {
	for _, word := range []uint32{
		0x1e220000, // Unscaled scalar SCVTF.
		0x4e21d800, // Unscaled vector SCVTF.
		0x5e21d800, // Unscaled Advanced SIMD scalar SCVTF.
		0x1e027c00, // W-source fractional width exceeds 32 bits.
		0x0f00e400, // Missing element-width indicator.
		0x0f40e400, // A 64-bit vector cannot hold one 64-bit lane.
		0x4f00e000, // Adjacent vector opcode.
	} {
		if _, ok := decodeARM64RawFixedIntToFloat(word); ok {
			t.Fatalf("decoder accepted invalid/adjacent encoding %#08x", word)
		}
	}
}

func TestTranslateARM64RawFixedIntToFloatGoHighwayRegression(t *testing.T) {
	const source = `
TEXT rawFixedIntToFloat(SB),$0-0
	WORD $0x1e43fc00 // UCVTF D0, W0, #1
	WORD $0x4f28e631 // SCVTF V17.4S, V17.4S, #24
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
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
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawFixedIntToFloat": {Name: "rawFixedIntToFloat", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"uitofp i32", "sitofp <4 x i32>", "fmul double", "fmul <4 x float>"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("fixed-point conversion omitted %q:\n%s", want, ir)
				}
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fixed-int-to-float.ll", "arm64-raw-fixed-int-to-float.o", ir)
		})
	}
}

func TestARM64RawFixedIntToFloatRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawFixedRuntime(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x4f28e401 // SCVTF V1.4S, V0.4S, #24
	WORD $0x6f28e402 // UCVTF V2.4S, V0.4S, #24
	VST1 [V1.S4, V2.S4], (R1)
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
		Sigs: map[string]FuncSig{"rawFixedRuntime": {
			Name: "rawFixedRuntime", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawFixedRuntime(const uint32_t *, float *);
int main(void) {
  const uint32_t input[4] = {0x01000000u, 0xff000000u, 0, 0x00800000u};
  float got[8] = {0};
  rawFixedRuntime(input, got);
  const float signed_want[4] = {1.0f, -1.0f, 0.0f, 0.5f};
  const float unsigned_want[4] = {1.0f, 255.0f, 0.0f, 0.5f};
  for (int i = 0; i < 4; i++) {
    if (got[i] != signed_want[i]) return i + 1;
    if (got[4+i] != unsigned_want[i]) return i + 11;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fixed_cvtf", triple, ir, mainC, nil)
}

func TestARM64RawFixedIntToFloatAllModesCompile(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawFixedAllModes(SB),$0-0\n")
	for _, form := range []struct {
		name string
		word uint32
	}{
		{"signed GPR S/W", 0x1e02fc20},
		{"unsigned GPR S/W", 0x1e03fc20},
		{"signed GPR S/X", 0x9e02fc20},
		{"unsigned GPR S/X", 0x9e03a1c0},
		{"signed GPR D/W", 0x1e42fc20},
		{"unsigned GPR D/W", 0x1e43fc20},
		{"signed GPR D/X", 0x9e42fc20},
		{"unsigned GPR D/X", 0x9e43fc20},
		{"signed scalar S", 0x5f28e420},
		{"unsigned scalar D", 0x7f40e420},
		{"signed vector 2S", 0x0f28e420},
		{"unsigned vector 4S", 0x6f28e420},
		{"signed vector 2D", 0x4f40e420},
	} {
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", form.word, form.name)
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
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawFixedAllModes": {Name: "rawFixedAllModes", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fixed-all-modes.ll", "arm64-raw-fixed-all-modes.o", ir)
		})
	}
}
