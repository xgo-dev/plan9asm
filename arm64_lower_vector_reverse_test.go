package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64VectorReverseForms = `
TEXT vectorreverseforms(SB),$0-0
	VREV16 V0.B8, V1.B8
	VREV16 V2.B16, V3.B16
	VREV32 V4.B8, V5.B8
	VREV32 V6.B16, V7.B16
	VREV32 V8.H4, V9.H4
	VREV32 V10.H8, V11.H8
	VREV64 V12.B8, V13.B8
	VREV64 V14.B16, V15.B16
	VREV64 V16.H4, V17.H4
	VREV64 V18.H8, V19.H8
	VREV64 V20.S2, V21.S2
	VREV64 V22.S4, V23.S4
	RET
`

func TestTranslateARM64VectorReverseCompleteArchitecturalForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64VectorReverseForms, true)
	file, err := Parse(ArchARM64, arm64VectorReverseForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"vectorreverseforms": {Name: "vectorreverseforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			// The twelve reverse operations plus six low-half extraction shuffles
			// for the 64-bit arrangements must all survive LLVM normalization.
			if got := strings.Count(ll, "shufflevector"); got != 18 {
				t.Fatalf("ARM64 vector reverse emitted %d shuffles, want 18:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-reverse.ll", "arm64-vector-reverse.o", ll)
		})
	}
}

func TestTranslateARM64VectorReverseRejectsInvalidForms(t *testing.T) {
	for _, tc := range []struct {
		instruction string
		goAccepts   bool
	}{
		{"VREV16 V0.H4, V1.H4", false},
		{"VREV32 V0.S2, V1.S2", false},
		// Go 1.27 accepts these reserved size=3 encodings; LLVM 22 and the ARM
		// architecture reject them, so the translator must not mirror that bug.
		{"VREV32 V0.D2, V1.D2", true},
		{"VREV64 V0.D2, V1.D2", true},
		{"VREV64 V0.B8, V1.B16", false},
		{"VREV64.P V0.S4, V1.S4", false},
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(tc.instruction), func(t *testing.T) {
			source := "TEXT badvectorreverse(SB),$0-0\n\t" + tc.instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, tc.goAccepts)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64",
				Sigs: map[string]FuncSig{"badvectorreverse": {Name: "badvectorreverse", Ret: Void}},
			}); err == nil {
				t.Fatalf("Translate accepted invalid vector reverse form %q", tc.instruction)
			}
		})
	}
}

func TestARM64VectorReverseRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorreverse(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.B16]
	VREV16 V0.B16, V1.B16
	VREV32 V0.B16, V2.B16
	VREV64 V0.B16, V3.B16
	VST1 [V1.B16, V2.B16, V3.B16], (R1)
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
			"vectorreverse": {
				Name: "vectorreverse", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void vectorreverse(const uint8_t *, uint8_t *);
int main(void) {
  const uint8_t input[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
  const uint8_t want[48] = {
    1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14,
    3,2,1,0,7,6,5,4,11,10,9,8,15,14,13,12,
    7,6,5,4,3,2,1,0,15,14,13,12,11,10,9,8
  };
  uint8_t got[48] = {0};
  vectorreverse(input, got);
  for (int i = 0; i < 48; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_reverse", triple, ll, mainC, nil)
}
