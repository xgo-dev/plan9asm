package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawLogicalCompleteAdvancedSIMDFormats(t *testing.T) {
	bases := []uint32{0x0e201c00, 0x0e601c00, 0x0ea01c00, 0x0ee01c00, 0x2e201c00, 0x2e601c00, 0x2ea01c00, 0x2ee01c00}
	var source strings.Builder
	source.WriteString("TEXT rawlogicalforms(SB),$0-0\n")
	for _, base := range bases {
		for _, q := range []uint32{0, 1 << 30} { // B8 and B16.
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|q|1<<16|2<<5|3)
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
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawlogicalforms": {Name: "rawlogicalforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"and <", "or <", "xor <"} {
				if !strings.Contains(ll, operation) {
					t.Fatalf("ARM64 raw logical lowering for %s omitted %q:\n%s", triple, operation, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-logical.ll", "arm64-raw-logical.o", ll)
		})
	}
}

func TestARM64RawLogicalRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawlogical(SB),$0-32
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD initial+16(FP), R2
	MOVD out+24(FP), R3
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VLD1.P 64(R2), [V2.B16, V3.B16, V4.B16, V5.B16]
	VLD1 (R2), [V6.B16, V7.B16, V8.B16, V9.B16]
	WORD $0x4e211c02 // AND V2.16B, V0.16B, V1.16B
	WORD $0x4e611c03 // BIC V3.16B, V0.16B, V1.16B
	WORD $0x4ea11c04 // ORR V4.16B, V0.16B, V1.16B
	WORD $0x4ee11c05 // ORN V5.16B, V0.16B, V1.16B
	WORD $0x6e211c06 // EOR V6.16B, V0.16B, V1.16B
	WORD $0x6e611c07 // BSL V7.16B, V0.16B, V1.16B
	WORD $0x6ea11c08 // BIT V8.16B, V0.16B, V1.16B
	WORD $0x6ee11c09 // BIF V9.16B, V0.16B, V1.16B
	VST1.P [V2.B16, V3.B16, V4.B16, V5.B16], 64(R3)
	VST1 [V6.B16, V7.B16, V8.B16, V9.B16], (R3)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawlogical": {
			Name: "rawlogical", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawlogical(const uint8_t *, const uint8_t *, const uint8_t *, uint8_t *);
int main(void) {
  uint8_t a[16], b[16], initial[128], got[128] = {0};
  for (int i = 0; i < 16; i++) { a[i] = i * 17u; b[i] = 255u - i * 11u; }
  for (int i = 0; i < 128; i++) initial[i] = 0xa5u ^ i;
  rawlogical(a, b, initial, got);
  for (int i = 0; i < 16; i++) {
    const uint8_t old_bsl = initial[5*16+i], old_bit = initial[6*16+i], old_bif = initial[7*16+i];
    const uint8_t want[8] = {
      a[i]&b[i], a[i]&~b[i], a[i]|b[i], a[i]|~b[i], a[i]^b[i],
      (old_bsl&a[i])|(~old_bsl&b[i]),
      (old_bit&~b[i])|(a[i]&b[i]),
      (old_bif&b[i])|(a[i]&~b[i]),
    };
    for (int op = 0; op < 8; op++) if (got[op*16+i] != want[op]) return op*16+i+1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_logical", triple, ll, mainC, nil)
}

func TestARM64RawLogicalDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x0e201800, 0x0e205c00, 0x5e201c00} {
		if _, ok := decodeARM64RawLogical(word); ok {
			t.Fatalf("logical decoder accepted adjacent/scalar encoding %#08x", word)
		}
	}
}
