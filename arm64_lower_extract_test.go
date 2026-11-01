package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64VectorExtractCompleteGoAssemblerForms(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT vectorextractforms(SB),$0-0\n")
	for _, form := range []struct {
		arrangement string
		maximum     int
	}{
		{arrangement: "B8", maximum: 7},
		{arrangement: "B16", maximum: 15},
	} {
		for _, immediate := range []int{0, 1, form.maximum} {
			fmt.Fprintf(&source, "\tVEXT $%d, V30.%s, V31.%s, V29.%s\n", immediate, form.arrangement, form.arrangement, form.arrangement)
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
				Sigs:         map[string]FuncSig{"vectorextractforms": {Name: "vectorextractforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(ll, "shufflevector") {
				t.Fatalf("ARM64 VEXT lowering for %s omitted shuffle semantics:\n%s", triple, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-extract.ll", "arm64-vector-extract.o", ll)
		})
	}
}

func TestTranslateARM64VectorExtractRejectsInvalidForms(t *testing.T) {
	for _, instruction := range []string{
		"VEXT $8, V0.B8, V1.B8, V2.B8",
		"VEXT $16, V0.B16, V1.B16, V2.B16",
		"VEXT $-1, V0.B16, V1.B16, V2.B16",
		"VEXT $4, V0.B8, V1.B16, V2.B16",
		"VEXT $4, V0.H8, V1.H8, V2.H8",
		"VEXT V0.B16, V1.B16, V2.B16",
		"VEXT.P $4, V0.B16, V1.B16, V2.B16",
	} {
		source := "TEXT badvectorextract(SB),$0-0\n\t" + instruction + "\n\tRET\n"
		requireARM64GoAssemblerResult(t, source, false)
		file, err := Parse(ArchARM64, source)
		if err != nil {
			continue
		}
		if _, err := Translate(file, Options{
			TargetTriple: "aarch64-unknown-linux-gnu",
			Goarch:       "arm64",
			Sigs:         map[string]FuncSig{"badvectorextract": {Name: "badvectorextract", Ret: Void}},
		}); err == nil {
			t.Fatalf("Translate accepted invalid VEXT form %q", instruction)
		}
	}
}

func TestARM64VectorExtractRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorextract(SB),$0-24
	MOVD left+0(FP), R0
	MOVD right+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.B16]
	VLD1 (R1), [V1.B16]
	VEXT $5, V1.B16, V0.B16, V2.B16
	VST1.P [V2.B16], 16(R2)
	VEXT $3, V1.B8, V0.B8, V3.B8
	VST1 [V3.B16], (R2)
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
		Sigs: map[string]FuncSig{"vectorextract": {
			Name: "vectorextract", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void vectorextract(const uint8_t *, const uint8_t *, uint8_t *);
int main(void) {
  uint8_t left[16], right[16], got[32];
  for (int i = 0; i < 16; i++) { left[i] = (uint8_t)i; right[i] = (uint8_t)(16+i); got[i] = got[16+i] = 0xff; }
  vectorextract(left, right, got);
  for (int i = 0; i < 16; i++) if (got[i] != (uint8_t)(i+5)) return i+1;
	for (int i = 0; i < 8; i++) {
	  int lane = i + 3;
	  uint8_t want = lane < 8 ? left[lane] : right[lane-8];
	  if (got[16+i] != want) return i+21;
	}
  for (int i = 8; i < 16; i++) if (got[16+i] != 0) return i+41;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_extract", triple, ll, mainC, nil)
}
