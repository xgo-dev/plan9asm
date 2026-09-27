package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64ScalarVectorCVTFForms = `
TEXT scalarvectorcvtf(SB),$0-0
	WORD $0x5e61db5b // SCVTFDD F26, F27
	WORD $0x7e61db8e // UCVTFDD F28, F14
	WORD $0x5e21dbc6 // SCVTFSS F30, F6
	WORD $0x7e21d8d7 // UCVTFSS F6, F23
	RET
`

func TestARM64RawScalarVectorCVTFCompleteForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64ScalarVectorCVTFForms, true)
	file, err := Parse(ArchARM64, arm64ScalarVectorCVTFForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"scalarvectorcvtf": {Name: "scalarvectorcvtf", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"sitofp i64", "uitofp i64", "sitofp i32", "uitofp i32"} {
				if !strings.Contains(ll, want) {
					t.Fatalf("missing %q in %s:\n%s", want, triple, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-scalar-cvtf.ll", "arm64-scalar-cvtf.o", ll)
		})
	}
}

func TestARM64RawScalarVectorCVTFRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT scalarvectorcvtf(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	FMOVD (R0), F0
	WORD $0x5e61d801 // SCVTFDD F0, F1
	WORD $0x7e61d802 // UCVTFDD F0, F2
	FMOVD F1, (R1)
	FMOVD F2, 8(R1)
	FMOVS 8(R0), F3
	WORD $0x5e21d864 // SCVTFSS F3, F4
	WORD $0x7e21d865 // UCVTFSS F3, F5
	FMOVS F4, 16(R1)
	FMOVS F5, 20(R1)
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
		Sigs: map[string]FuncSig{"scalarvectorcvtf": {
			Name: "scalarvectorcvtf", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
struct Input { uint64_t d; uint32_t s; };
struct Output { double signed64, unsigned64; float signed32, unsigned32; };
extern void scalarvectorcvtf(const struct Input *, struct Output *);
int main(void) {
  struct Input input = {UINT64_MAX, UINT32_MAX};
  struct Output got = {0};
  scalarvectorcvtf(&input, &got);
  if (got.signed64 != -1.0 || got.unsigned64 != (double)UINT64_MAX) return 1;
  if (got.signed32 != -1.0f || got.unsigned32 != (float)UINT32_MAX) return 2;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_scalar_vector_cvtf", triple, ll, mainC, nil)
}
