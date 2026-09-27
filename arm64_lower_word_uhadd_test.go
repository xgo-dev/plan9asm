package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

const arm64RawUHADDForms = `
TEXT rawuhaddforms(SB),$0-0
	WORD $0x2e220420 // UHADD V0.8B, V1.8B, V2.8B
	WORD $0x6e250483 // UHADD V3.16B, V4.16B, V5.16B
	WORD $0x2e6804e6 // UHADD V6.4H, V7.4H, V8.4H
	WORD $0x6e6b0549 // UHADD V9.8H, V10.8H, V11.8H
	WORD $0x2eae05ac // UHADD V12.2S, V13.2S, V14.2S
	WORD $0x6eb1060f // UHADD V15.4S, V16.4S, V17.4S
	RET
`

func TestTranslateARM64RawUHADDCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUHADDForms, true)
	file, err := Parse(ArchARM64, arm64RawUHADDForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawuhaddforms": {Name: "rawuhaddforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"lshr <8 x i16>", "lshr <16 x i16>",
				"lshr <4 x i32>", "lshr <8 x i32>",
				"lshr <2 x i64>", "lshr <4 x i64>",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw UHADD lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-uhadd.ll", "arm64-raw-uhadd.o", ll)
		})
	}
}

func TestTranslateARM64RawHalvingAddSubCompleteAdvancedSIMDFamily(t *testing.T) {
	families := []struct {
		name string
		base uint32
	}{
		{"SHADD", 0x0e200400},
		{"UHADD", 0x2e200400},
		{"SRHADD", 0x0e201400},
		{"URHADD", 0x2e201400},
		{"SHSUB", 0x0e202400},
		{"UHSUB", 0x2e202400},
	}

	var source strings.Builder
	source.WriteString("TEXT rawHalvingAddSubFamily(SB),$0-0\n")
	for _, family := range families {
		for size := 0; size < 3; size++ {
			for q := 0; q < 2; q++ {
				word := family.base | uint32(size)<<22 | uint32(q)<<30 | 31<<16 | 30<<5 | 29
				fmt.Fprintf(&source, "\tWORD $%#08x // %s size=%d q=%d\n", word, family.name, size, q)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawHalvingAddSubFamily": {Name: "rawHalvingAddSubFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{" add <", " sub <", "sext <", "zext <", "ashr <", "lshr <", "trunc <"} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw halving add/sub IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-halving-add-sub.ll", "arm64-raw-halving-add-sub.o", ir)
		})
	}
}

func TestARM64RawUHADDRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawuhadd(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x6ea10402 // UHADD V2.4S, V0.4S, V1.4S
	VST1 [V2.S4], (R2)
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
			"rawuhadd": {
				Name: "rawuhadd", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
#include <limits.h>
extern void rawuhadd(const uint32_t *, const uint32_t *, uint32_t *);
int main(void) {
  const uint32_t a[4] = {UINT32_MAX, UINT32_MAX, 1, 4};
  const uint32_t b[4] = {UINT32_MAX, 1, 2, 3};
  const uint32_t want[4] = {UINT32_MAX, 2147483648u, 1, 3};
  uint32_t got[4] = {0};
  rawuhadd(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_uhadd", triple, ll, mainC, nil)
}

func TestARM64RawHalvingAddSubDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x0e203400, 0x2e203400, 0x6ee20420} { // Compare opcodes and reserved D2.
		t.Run(fmt.Sprintf("%#08x", word), func(t *testing.T) {
			if _, ok := decodeARM64RawHalvingAddSub(word); ok {
				t.Fatalf("halving add/sub decoder claimed adjacent/reserved encoding %#08x", word)
			}
		})
	}
}
