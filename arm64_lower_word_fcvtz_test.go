package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawFCVTZForms = `
TEXT rawfcvtzforms(SB),$0-0
	WORD $0x0ea1b820 // FCVTZS V1.S2, V0.S2
	WORD $0x4ea1b862 // FCVTZS V3.S4, V2.S4
	WORD $0x4ee1b8a4 // FCVTZS V5.D2, V4.D2
	WORD $0x2ea1b8e6 // FCVTZU V7.S2, V6.S2
	WORD $0x6ea1b928 // FCVTZU V9.S4, V8.S4
	WORD $0x6ee1b96a // FCVTZU V11.D2, V10.D2
	RET
`

func TestTranslateARM64RawFCVTZCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawFCVTZForms, true)
	file, err := Parse(ArchARM64, arm64RawFCVTZForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawfcvtzforms": {Name: "rawfcvtzforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.fptosi.sat.v2i32.v2f32", "@llvm.fptosi.sat.v4i32.v4f32", "@llvm.fptosi.sat.v2i64.v2f64",
				"@llvm.fptoui.sat.v2i32.v2f32", "@llvm.fptoui.sat.v4i32.v4f32", "@llvm.fptoui.sat.v2i64.v2f64",
			} {
				found := false
				for _, line := range strings.Split(ll, "\n") {
					if strings.Contains(line, " = call ") && strings.Contains(line, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("ARM64 raw FCVTZS/FCVTZU lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fcvtz.ll", "arm64-raw-fcvtz.o", ll)
		})
	}
}

func TestARM64RawFCVTZRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfcvtz(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x4ea1b801 // FCVTZS V0.4S, V1.4S
	WORD $0x6ea1b802 // FCVTZU V0.4S, V2.4S
	VST1 [V1.S4, V2.S4], (R1)
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
		Sigs: map[string]FuncSig{"rawfcvtz": {
			Name: "rawfcvtz", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
#include <limits.h>
extern void rawfcvtz(const float *, uint32_t *);
int main(void) {
  const float in[4] = {-1.75f, 1.75f, 1.0e30f, -1.0e30f};
  const int32_t signed_want[4] = {-1, 1, INT32_MAX, INT32_MIN};
  const uint32_t unsigned_want[4] = {0, 1, UINT32_MAX, 0};
  uint32_t got[8] = {0};
  rawfcvtz(in, got);
  for (int i = 0; i < 4; i++) {
    if ((int32_t)got[i] != signed_want[i]) return i + 1;
    if (got[4+i] != unsigned_want[i]) return i + 11;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fcvtz", triple, ll, mainC, nil)
}

func TestARM64RawFCVTZDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{0x4e21d800, 0x1e38c000, 0x0ee1b800} { // SCVTF, scalar FCVTZS, reserved D1.
		if _, ok := decodeARM64RawFCVTZ(word); ok {
			t.Fatalf("FCVTZS/FCVTZU decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
