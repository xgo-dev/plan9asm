package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawVectorFloatRoundCompleteArchitecturalFormats(t *testing.T) {
	bases := []uint32{0x2e218800, 0x2e219800, 0x2ea19800} // FRINTA, FRINTX, FRINTI.
	modifiers := []uint32{0, 1 << 30, 1<<30 | 1<<22}      // S2, S4, D2.
	var source strings.Builder
	source.WriteString("TEXT rawvectorfloatroundforms(SB),$0-0\n")
	for _, base := range bases {
		for _, modifier := range modifiers {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|modifier|30<<5|29)
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
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawvectorfloatroundforms": {Name: "rawvectorfloatroundforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, intrinsic := range []string{"@llvm.round.", "@llvm.rint.", "@llvm.nearbyint."} {
				if !strings.Contains(ir, intrinsic) {
					t.Fatalf("raw vector floating round omitted %s:\n%s", intrinsic, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-vector-float-round.ll", "arm64-raw-vector-float-round.o", ir)
		})
	}
}

func TestARM64RawVectorFloatRoundDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e618800, // reserved FRINTA D1
		0x2e218000, // FRINTN
		0x2e219000, // FRINTP
		0x2e219800 | 1<<10,
	} {
		if _, ok := decodeARM64RawVectorFloatRound(word); ok {
			t.Fatalf("vector floating round decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawVectorFloatRoundRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawvectorfloatround(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x6e218801 // FRINTA V0.S4, V1.S4
	WORD $0x6e219802 // FRINTX V0.S4, V2.S4
	WORD $0x6ea19803 // FRINTI V0.S4, V3.S4
	VST1 [V1.S4, V2.S4, V3.S4], (R1)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"rawvectorfloatround": {
				Name: "rawvectorfloatround", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawvectorfloatround(const float *, float *);
int main(void) {
  const float input[4] = {1.5f, 2.5f, -1.5f, -2.5f};
  const float want[12] = {2,3,-2,-3, 2,2,-2,-2, 2,2,-2,-2};
  float got[12] = {0};
  rawvectorfloatround(input, got);
  for (int i = 0; i < 12; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_vector_float_round", triple, ir, mainC, nil)
}
