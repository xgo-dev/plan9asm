package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawSHSUBForms = `
TEXT rawshsubforms(SB),$0-0
	WORD $0x0e222420 // SHSUB V0.8B, V1.8B, V2.8B
	WORD $0x4e252483 // SHSUB V3.16B, V4.16B, V5.16B
	WORD $0x0e6824e6 // SHSUB V6.4H, V7.4H, V8.4H
	WORD $0x4e6b2549 // SHSUB V9.8H, V10.8H, V11.8H
	WORD $0x0eae25ac // SHSUB V12.2S, V13.2S, V14.2S
	WORD $0x4eb1260f // SHSUB V15.4S, V16.4S, V17.4S
	RET
`

func TestTranslateARM64RawSHSUBCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawSHSUBForms, true)
	file, err := Parse(ArchARM64, arm64RawSHSUBForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawshsubforms": {Name: "rawshsubforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"sub <8 x i16>", "sub <16 x i16>",
				"sub <4 x i32>", "sub <8 x i32>",
				"sub <2 x i64>", "sub <4 x i64>", "ashr <",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SHSUB lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-shsub.ll", "arm64-raw-shsub.o", ll)
		})
	}
}

func TestARM64RawSHSUBRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawshsub(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4ea12402 // SHSUB V2.4S, V0.4S, V1.4S
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
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawshsub": {
				Name: "rawshsub", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawshsub(const int32_t *, const int32_t *, int32_t *);
int main(void) {
  const int32_t a[4] = {INT32_MIN, INT32_MAX, -3, 4};
  const int32_t b[4] = {INT32_MAX, INT32_MIN, 4, -3};
  const int32_t want[4] = {INT32_MIN, INT32_MAX, -4, 3};
  int32_t got[4] = {0};
  rawshsub(a, b, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_shsub", triple, ll, mainC, nil)
}

func TestARM64RawSHSUBAndUHSUBDecodeAsOneTypedFamily(t *testing.T) {
	signed, ok := decodeARM64RawHalvingAddSub(0x0e222420)
	if !ok || !signed.spec.signed || !signed.spec.subtract {
		t.Fatalf("SHSUB decode = %#v, %v", signed, ok)
	}
	unsigned, ok := decodeARM64RawHalvingAddSub(0x2e222420)
	if !ok || unsigned.spec.signed || !unsigned.spec.subtract {
		t.Fatalf("UHSUB decode = %#v, %v", unsigned, ok)
	}
}
