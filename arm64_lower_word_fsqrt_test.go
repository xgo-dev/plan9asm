package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64RawFSQRTForms = `
TEXT rawfsqrtforms(SB),$0-0
	WORD $0x2ef9f820 // FSQRT V1.H4, V0.H4
	WORD $0x6ef9f820 // FSQRT V1.H8, V0.H8
	WORD $0x2ea1f820 // FSQRT V1.S2, V0.S2
	WORD $0x6ea1f820 // FSQRT V1.S4, V0.S4
	WORD $0x6ee1f820 // FSQRT V1.D2, V0.D2
	RET
`

func TestTranslateARM64RawFSQRTCompleteAdvancedSIMDFormats(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64RawFSQRTForms, true)
	file, err := Parse(ArchARM64, arm64RawFSQRTForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawfsqrtforms": {Name: "rawfsqrtforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			for _, line := range strings.Split(ll, "\n") {
				if strings.Contains(line, " = call ") && strings.Contains(line, "@llvm.sqrt.") {
					got++
				}
			}
			if got != 5 {
				t.Fatalf("ARM64 raw FSQRT lowering for %s emitted %d sqrt operations, want 5:\n%s", triple, got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fsqrt.ll", "arm64-raw-fsqrt.o", ll)
		})
	}
}

func TestARM64RawFSQRTRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfsqrt(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V5.S4]
	WORD $0x6ea1f8a5 // FSQRT V5.S4, V5.S4
	VST1 [V5.S4], (R1)
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
		Sigs: map[string]FuncSig{"rawfsqrt": {
			Name: "rawfsqrt", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawfsqrt(const float *, float *);
int main(void) {
  const float in[4] = {4.0f, 9.0f, 16.0f, 25.0f};
  const float want[4] = {2.0f, 3.0f, 4.0f, 5.0f};
  float got[4] = {0};
  rawfsqrt(in, got);
  for (int i = 0; i < 4; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fsqrt", triple, ll, mainC, nil)
}

func TestARM64RawFSQRTDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{0x0ea1d800, 0x1e21c020, 0x2ee1f820} { // SCVTF, scalar FSQRT, reserved D1.
		if _, ok := decodeARM64RawFSQRT(word); ok {
			t.Fatalf("FSQRT decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
