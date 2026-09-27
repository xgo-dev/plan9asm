package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawUADALPForms = `
TEXT rawuadalpforms(SB),$0-0
	WORD $0x2e206820 // UADALP V0.4H, V1.8B
	WORD $0x6e206862 // UADALP V2.8H, V3.16B
	WORD $0x2e6068a4 // UADALP V4.2S, V5.4H
	WORD $0x6e6068e6 // UADALP V6.4S, V7.8H
	WORD $0x2ea06928 // UADALP V8.1D, V9.2S
	WORD $0x6ea0696a // UADALP V10.2D, V11.4S
	RET
`

func TestTranslateARM64RawUADALPCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawUADALPForms, true)
	file, err := Parse(ArchARM64, arm64RawUADALPForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawuadalpforms": {Name: "rawuadalpforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"zext <4 x i8>", "zext <8 x i8>",
				"zext <2 x i16>", "zext <4 x i16>",
				"zext <1 x i32>", "zext <2 x i32>", "add <",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw UADALP lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-uadalp.ll", "arm64-raw-uadalp.o", ll)
		})
	}
}

func TestARM64RawUADALPRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawuadalp(SB),$0-16
	MOVD in+0(FP), R0
	MOVD inout+8(FP), R1
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V4.D2]
	WORD $0x6ea06804 // UADALP V4.2D, V0.4S
	VST1 [V4.D2], (R1)
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
			"rawuadalp": {
				Name: "rawuadalp", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawuadalp(const uint32_t *, uint64_t *);
int main(void) {
  const uint32_t in[4] = {0xffffffffu, 1, 2, 0xfffffffeu};
  uint64_t got[2] = {7, 9};
  const uint64_t want[2] = {UINT64_C(0x100000007), UINT64_C(0x100000009)};
  rawuadalp(in, got);
  for (int i = 0; i < 2; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_uadalp", triple, ll, mainC, nil)
}

func TestARM64RawUADALPDecoderRejectsAdjacentSADALPEncoding(t *testing.T) {
	if _, ok := decodeARM64RawUADALP(0x0e206820); ok {
		t.Fatal("UADALP decoder claimed adjacent SADALP encoding")
	}
}
