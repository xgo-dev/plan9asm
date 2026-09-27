package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawScalarFloatSelectDecoderCompleteArchitectureFamily(t *testing.T) {
	formats := []struct {
		base uint32
		bits int
	}{
		{base: 0x1ee00c00, bits: 16},
		{base: 0x1e200c00, bits: 32},
		{base: 0x1e600c00, bits: 64},
	}

	count := 0
	for _, format := range formats {
		for condition := 0; condition < 16; condition++ {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for destination := 0; destination < 32; destination++ {
						word := format.base |
							uint32(second)<<16 |
							uint32(condition)<<12 |
							uint32(first)<<5 |
							uint32(destination)
						form, ok := decodeARM64RawScalarFloatSelect(word)
						if !ok {
							t.Fatalf("decoder rejected %#08x", word)
						}
						if form.bits != format.bits || form.condition != condition ||
							form.first != first || form.second != second ||
							form.destination != destination {
							t.Fatalf("decode %#08x = %+v", word, form)
						}
						count++
					}
				}
			}
		}
	}
	if count != 1572864 {
		t.Fatalf("covered %d scalar FCSEL encodings, want 1572864", count)
	}
}

func TestTranslateARM64RawScalarFloatSelectCompleteArchitectureFamily(t *testing.T) {
	const source = `
TEXT rawScalarFloatSelectFamily(SB),$0-0
	CMP R0, R1
	WORD $0x1ee1dc02 // FCSEL H2, H0, H1, LE
	WORD $0x1e24ac83 // FCSEL S3, S4, S4, GE
	WORD $0x1e679ce5 // FCSEL D5, D7, D7, LS
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
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
					"rawScalarFloatSelectFamily": {Name: "rawScalarFloatSelectFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"select i1", " half ", " float ", " double ",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw scalar FCSEL IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-fcsel.ll", "arm64-raw-scalar-fcsel.o", ir)
		})
	}
}

func TestARM64RawScalarFloatSelectRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawscalarfloatselect(SB),$0-32
	MOVD first+0(FP), R0
	MOVD second+8(FP), R1
	MOVD chooseFirst+16(FP), R2
	MOVD out+24(FP), R4
	WORD $0x1ee70000 // FMOV H0, W0
	WORD $0x1ee70021 // FMOV H1, W1
	CMP $0, R2
	WORD $0x1ee11c02 // FCSEL H2, H0, H1, NE
	WORD $0x1ee60043 // FMOV W3, H2
	MOVD R3, (R4)
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
		Sigs: map[string]FuncSig{"rawscalarfloatselect": {
			Name: "rawscalarfloatselect", Args: []LLVMType{I64, I64, I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: I64, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawscalarfloatselect(uint64_t, uint64_t, uint64_t, uint64_t *);
int main(void) {
  uint64_t got = 0;
  rawscalarfloatselect(0x3c00, 0xc000, 1, &got);
  if (got != 0x3c00) return 1;
  rawscalarfloatselect(0x3c00, 0xc000, 0, &got);
  if (got != 0xc000) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_scalar_fcsel", triple, ir, mainC, nil)
}

func TestARM64RawScalarFloatSelectDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ea00c00, // Reserved scalar floating type.
		0x1ee00800, // FCCMP scalar half-precision family.
		0x1ee02000, // FCMP scalar half-precision family.
		0x0e20cc00, // Advanced SIMD FMLA family.
	} {
		if _, ok := decodeARM64RawScalarFloatSelect(word); ok {
			t.Fatalf("scalar FCSEL decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
