package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawFloatToIntegerRoundingCompleteBaseFormats(t *testing.T) {
	// The base A64 Advanced SIMD family has five rounding modes, signed and
	// unsigned results, and S2/S4/D2 arrangements. H4/H8 belong to the
	// optional FP16 extension and are deliberately outside this base matrix.
	bases := []uint32{
		0x0e21a800, // FCVTNS
		0x0e21b800, // FCVTMS
		0x0e21c800, // FCVTAS
		0x0ea1a800, // FCVTPS
		0x0ea1b800, // FCVTZS
	}
	modifiers := []uint32{0, 1 << 30, 1<<30 | 1<<22} // S2, S4, D2.
	var source strings.Builder
	source.WriteString("TEXT rawfcvtroundforms(SB),$0-0\n")
	for _, base := range bases {
		for _, unsigned := range []uint32{0, 1 << 29} {
			for _, modifier := range modifiers {
				fmt.Fprintf(&source, "\tWORD $%#08x\n", base|unsigned|modifier|30<<5|29)
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
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawfcvtroundforms": {Name: "rawfcvtroundforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{
				"@llvm.roundeven.", "@llvm.floor.", "@llvm.round.", "@llvm.ceil.",
				"@llvm.fptosi.sat.", "@llvm.fptoui.sat.",
			} {
				if !strings.Contains(ll, intrinsic) {
					t.Fatalf("raw FCVT rounding family omitted %s for %s:\n%s", intrinsic, triple, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fcvt-round.ll", "arm64-raw-fcvt-round.o", ll)
		})
	}
}

func TestARM64RawFloatToIntegerRoundingRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfcvtround(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x4e21a801 // FCVTNS V0.4S, V1.4S
	WORD $0x6e21a802 // FCVTNU V0.4S, V2.4S
	WORD $0x4e21b803 // FCVTMS V0.4S, V3.4S
	WORD $0x6e21b804 // FCVTMU V0.4S, V4.4S
	WORD $0x4e21c805 // FCVTAS V0.4S, V5.4S
	WORD $0x6e21c806 // FCVTAU V0.4S, V6.4S
	WORD $0x4ea1a807 // FCVTPS V0.4S, V7.4S
	WORD $0x6ea1a808 // FCVTPU V0.4S, V8.4S
	WORD $0x4ea1b809 // FCVTZS V0.4S, V9.4S
	WORD $0x6ea1b80a // FCVTZU V0.4S, V10.4S
	VST1 [V1.S4, V2.S4, V3.S4, V4.S4], (R1)
	ADD $64, R1
	VST1 [V5.S4, V6.S4, V7.S4, V8.S4], (R1)
	ADD $64, R1
	VST1 [V9.S4, V10.S4], (R1)
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
		Sigs: map[string]FuncSig{"rawfcvtround": {
			Name: "rawfcvtround", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawfcvtround(const float *, uint32_t *);
int main(void) {
  const float input[4] = {1.5f, 2.5f, -1.5f, -2.5f};
  const int32_t want[40] = {
    2,2,-2,-2, 2,2,0,0,
    1,2,-2,-3, 1,2,0,0,
    2,3,-2,-3, 2,3,0,0,
    2,3,-1,-2, 2,3,0,0,
    1,2,-1,-2, 1,2,0,0,
  };
  uint32_t got[40] = {0};
  rawfcvtround(input, got);
  for (int i = 0; i < 40; i++) {
    if ((int32_t)got[i] != want[i]) return i + 1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fcvt_round", triple, ll, mainC, nil)
}
