package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64RawLDnRForTest(count, size int, q, post bool, rm, rn, rt int) uint32 {
	word := uint32(0x0d40c000)
	if q {
		word |= 1 << 30
	}
	if post {
		word |= 1 << 23
	}
	if count&1 == 0 {
		word |= 1 << 21
	}
	if count >= 3 {
		word |= 1 << 13
	}
	word |= uint32(size&3) << 10
	word |= uint32(rm&31) << 16
	word |= uint32(rn&31) << 5
	word |= uint32(rt & 31)
	return word
}

func TestTranslateARM64RawLDnRCompleteAdvancedSIMDFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawldnrforms(SB),$0-0\n")
	for count := 1; count <= 4; count++ {
		for size := 0; size <= 3; size++ {
			for _, q := range []bool{false, true} {
				for _, addressing := range []struct {
					post bool
					rm   int
				}{{false, 0}, {true, 31}, {true, 2}} {
					word := encodeARM64RawLDnRForTest(count, size, q, addressing.post, addressing.rm, 0, 28)
					fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
				}
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
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawldnrforms": {Name: "rawldnrforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"load i8", "load i16", "load i32", "load i64", "shufflevector", "add i64"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw LDnR lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-ldnr.ll", "arm64-raw-ldnr.o", ll)
		})
	}
}

func TestARM64RawLDnRDecoderCoversEveryFormat(t *testing.T) {
	for count := 1; count <= 4; count++ {
		for size := 0; size <= 3; size++ {
			for _, q := range []bool{false, true} {
				for _, addressing := range []struct {
					post bool
					rm   int
				}{{false, 0}, {true, 31}, {true, 17}} {
					word := encodeARM64RawLDnRForTest(count, size, q, addressing.post, addressing.rm, 9, 30)
					form, ok := decodeARM64RawLDnR(word)
					if !ok || form.count != count || form.post != addressing.post || form.base != 9 || form.firstRegister != 30 || form.arrangement.elementBits != 8<<size {
						t.Fatalf("decode LDnR count=%d size=%d q=%v post=%v rm=%d: form=%#v ok=%v", count, size, q, addressing.post, addressing.rm, form, ok)
					}
					wantLanes := 64 / (8 << size)
					if q {
						wantLanes *= 2
					}
					if form.arrangement.lanes != wantLanes || form.postRegister != addressing.rm {
						t.Fatalf("decode LDnR arrangement/addressing mismatch: form=%#v", form)
					}
				}
			}
		}
	}
}

func TestARM64RawLDnRRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawldnr(SB),$0-24
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	MOVD advanced+16(FP), R2
	WORD $0x4dffe804 // LD4R {V4.4S-V7.4S}, [R0], #16
	VST1 [V4.S4, V5.S4, V6.S4, V7.S4], (R1)
	MOVD R0, (R2)
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
			"rawldnr": {
				Name: "rawldnr", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
#include <stddef.h>
extern void rawldnr(const uint32_t *, uint32_t *, uintptr_t *);
int main(void) {
  const uint32_t input[4] = {11, 22, 33, 44};
  uint32_t output[16] = {0};
  uintptr_t advanced = 0;
  rawldnr(input, output, &advanced);
  for (int reg = 0; reg < 4; reg++)
    for (int lane = 0; lane < 4; lane++)
      if (output[reg*4+lane] != input[reg]) return 1 + reg*4 + lane;
  return advanced == (uintptr_t)(input+4) ? 0 : 30;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_ldnr", triple, ll, mainC, nil)
}

func TestARM64RawLDnRDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x4c407000, // LD1, not LD1R.
		encodeARM64RawLDnRForTest(1, 0, true, false, 3, 0, 0), // Rm must be zero without post-indexing.
	} {
		t.Run(fmt.Sprintf("%08x", word), func(t *testing.T) {
			if _, ok := decodeARM64RawLDnR(word); ok {
				t.Fatalf("LDnR decoder claimed adjacent/reserved encoding %#08x", word)
			}
		})
	}
}
