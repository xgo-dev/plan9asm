package plan9asm

import (
	"runtime"
	"strings"
	"testing"
)

const arm64VectorCountLeadingForms = `
TEXT vectorcountleadingforms(SB),$0-0
	VCLS V0.B8, V1.B8
	VCLS V2.B16, V3.B16
	VCLS V4.H4, V5.H4
	VCLS V6.H8, V7.H8
	VCLS V8.S2, V9.S2
	VCLS V10.S4, V11.S4
	VCLZ V12.B8, V13.B8
	VCLZ V14.B16, V15.B16
	VCLZ V16.H4, V17.H4
	VCLZ V18.H8, V19.H8
	VCLZ V20.S2, V21.S2
	VCLZ V22.S4, V23.S4
	RET
`

func TestTranslateARM64VectorCountLeadingCompleteGoAssemblerForms(t *testing.T) {
	requireARM64GoAssemblerResult(t, arm64VectorCountLeadingForms, true)
	file, err := Parse(ArchARM64, arm64VectorCountLeadingForms)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"vectorcountleadingforms": {Name: "vectorcountleadingforms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Count(ll, " = call <"); got != 12 {
				t.Fatalf("ARM64 VCLS/VCLZ emitted %d vector ctlz calls, want 12:\n%s", got, ll)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-vector-count-leading.ll", "arm64-vector-count-leading.o", ll)
		})
	}
}

func TestTranslateARM64VectorCountLeadingRejectsFormsOutsideGoAssemblerTable(t *testing.T) {
	for _, instruction := range []string{
		"VCLS V0.D1, V1.D1",
		"VCLS V0.D2, V1.D2",
		"VCLZ V0.D1, V1.D1",
		"VCLZ V0.D2, V1.D2",
		"VCLS V0.B8, V1.B16",
		"VCLZ V0.H4, V1.H8",
		"VCLS V0.B8, V1.B8, V2.B8",
		"VCLZ.P V0.S4, V1.S4",
	} {
		t.Run(strings.NewReplacer(" ", "_", ",", "", ".", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badvectorcountleading(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{
				TargetTriple: "aarch64-unknown-linux-gnu",
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"badvectorcountleading": {Name: "badvectorcountleading", Ret: Void},
				},
			}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's VCLS/VCLZ forms", instruction)
			}
		})
	}
}

func TestARM64VectorCountLeadingRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT vectorcountleading(SB),$0-16
	MOVD in+0(FP), R0
	MOVD out+8(FP), R1
	VLD1 (R0), [V0.B16]
	VCLZ V0.B16, V1.B16
	VCLS V0.B16, V2.B16
	VST1 [V1.B16, V2.B16], (R1)
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
			"vectorcountleading": {
				Name: "vectorcountleading", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void vectorcountleading(const uint8_t *, uint8_t *);
int main(void) {
  const uint8_t input[16] = {0x00,0x01,0x02,0x03,0x7f,0x80,0xff,0xfe,0xf0,0x10,0x08,0x04,0xc0,0x40,0xaa,0x55};
  const uint8_t want[32] = {
    8,7,6,6,1,0,0,0,0,3,4,5,0,1,0,1,
    7,6,5,5,0,0,7,6,3,2,3,4,1,0,0,0
  };
  uint8_t got[32] = {0};
  vectorcountleading(input, got);
  for (int i = 0; i < 32; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_vector_count_leading", triple, ll, mainC, nil)
}
