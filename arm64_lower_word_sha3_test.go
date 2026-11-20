package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawSHA3DecoderCompleteArchitectureFamily(t *testing.T) {
	count := 0
	for _, base := range []uint32{0xce000000, 0xce200000} {
		for destination := 0; destination < 32; destination++ {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					for third := 0; third < 32; third++ {
						word := base |
							uint32(destination) |
							uint32(first)<<5 |
							uint32(third)<<10 |
							uint32(second)<<16
						form, ok := decodeARM64RawSHA3(word)
						if !ok || form.destination != destination || form.first != first ||
							form.second != second || form.third != third {
							t.Fatalf("decode %#08x = %+v, %v", word, form, ok)
						}
						count++
					}
				}
			}
		}
	}

	for destination := 0; destination < 32; destination++ {
		for first := 0; first < 32; first++ {
			for second := 0; second < 32; second++ {
				word := uint32(0xce608c00) |
					uint32(destination) |
					uint32(first)<<5 |
					uint32(second)<<16
				form, ok := decodeARM64RawSHA3(word)
				if !ok || form.kind != arm64RawSHA3RAX1 || form.destination != destination ||
					form.first != first || form.second != second {
					t.Fatalf("decode %#08x = %+v, %v", word, form, ok)
				}
				count++
			}
		}
	}

	for rotate := 0; rotate < 64; rotate++ {
		for destination := 0; destination < 32; destination++ {
			for first := 0; first < 32; first++ {
				for second := 0; second < 32; second++ {
					word := uint32(0xce800000) |
						uint32(destination) |
						uint32(first)<<5 |
						uint32(rotate)<<10 |
						uint32(second)<<16
					form, ok := decodeARM64RawSHA3(word)
					if !ok || form.kind != arm64RawSHA3XAR || form.rotate != rotate ||
						form.destination != destination || form.first != first || form.second != second {
						t.Fatalf("decode %#08x = %+v, %v", word, form, ok)
					}
					count++
				}
			}
		}
	}
	if count != 4227072 {
		t.Fatalf("covered %d SHA3 encodings, want 4227072", count)
	}
}

func TestTranslateARM64RawSHA3CompleteArchitectureFamily(t *testing.T) {
	const source = `
TEXT rawSHA3Family(SB),$0-0
	WORD $0xce1e0922 // EOR3 V2.16B, V9.16B, V30.16B, V2.16B
	WORD $0xce261ca4 // BCAX V4.16B, V5.16B, V6.16B, V7.16B
	WORD $0xce6a8d28 // RAX1 V8.2D, V9.2D, V10.2D
	WORD $0xce8d458b // XAR V11.2D, V12.2D, V13.2D, #17
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
					"rawSHA3Family": {Name: "rawSHA3Family", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"xor <2 x i64>", "and <2 x i64>",
				"lshr <2 x i64>", "shl <2 x i64>",
				`"target-features"="+sha3"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw SHA3 IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sha3.ll", "arm64-raw-sha3.o", ir)
		})
	}
}

func TestARM64RawSHA3RuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawsha3(SB),$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD c+16(FP), R2
	MOVD out+24(FP), R3
	VLD1 (R0), [V0.D2]
	VLD1 (R1), [V1.D2]
	VLD1 (R2), [V2.D2]
	WORD $0xce010803 // EOR3 V3.16B, V0.16B, V1.16B, V2.16B
	WORD $0xce210804 // BCAX V4.16B, V0.16B, V1.16B, V2.16B
	WORD $0xce618c05 // RAX1 V5.2D, V0.2D, V1.2D
	WORD $0xce814406 // XAR V6.2D, V0.2D, V1.2D, #17
	VST1.P [V3.D2], 16(R3)
	VST1.P [V4.D2], 16(R3)
	VST1.P [V5.D2], 16(R3)
	VST1 [V6.D2], (R3)
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
		Sigs: map[string]FuncSig{"rawsha3": {
			Name: "rawsha3", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawsha3(const uint64_t *, const uint64_t *, const uint64_t *, uint64_t *);
static uint64_t ror(uint64_t value, unsigned amount) {
  return (value >> amount) | (value << (64 - amount));
}
int main(void) {
  const uint64_t a[2] = {0x0123456789abcdefULL, 0xfedcba9876543210ULL};
  const uint64_t b[2] = {0x1111222233334444ULL, 0x5555666677778888ULL};
  const uint64_t c[2] = {0xff00ff00aa55aa55ULL, 0x0f0ff0f05a5aa5a5ULL};
  uint64_t got[8] = {0};
  rawsha3(a, b, c, got);
  for (int lane = 0; lane < 2; lane++) {
    if (got[lane] != (a[lane] ^ b[lane] ^ c[lane])) return 1 + lane;
    if (got[2 + lane] != (a[lane] ^ (b[lane] & ~c[lane]))) return 3 + lane;
    if (got[4 + lane] != (a[lane] ^ ror(b[lane], 1))) return 5 + lane;
    if (got[6 + lane] != ror(a[lane] ^ b[lane], 17)) return 7 + lane;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_sha3", triple, ir, mainC, nil)
}

func TestARM64RawSHA3DecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0xce400000, // Reserved four-register opcode.
		0xce608800, // RAX1 with reserved fixed bits.
		0xcec00000, // Different immediate opcode.
		0x4e201c00, // Advanced SIMD EOR.
	} {
		if _, ok := decodeARM64RawSHA3(word); ok {
			t.Fatalf("SHA3 decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
