package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawFloatPairwiseMinMaxCompleteArchitecturalFormats(t *testing.T) {
	ops := []struct {
		name        string
		vectorBases []uint32
		scalarBases []uint32
		intrinsic   string
	}{
		{"fmaxp", []uint32{0x2e403400, 0x6e403400, 0x2e20f400, 0x6e20f400, 0x6e60f400}, []uint32{0x5e30f800, 0x7e30f800, 0x7e70f800}, "maximum"},
		{"fminp", []uint32{0x2ec03400, 0x6ec03400, 0x2ea0f400, 0x6ea0f400, 0x6ee0f400}, []uint32{0x5eb0f800, 0x7eb0f800, 0x7ef0f800}, "minimum"},
		{"fmaxnmp", []uint32{0x2e400400, 0x6e400400, 0x2e20c400, 0x6e20c400, 0x6e60c400}, []uint32{0x5e30c800, 0x7e30c800, 0x7e70c800}, "maxnum"},
		{"fminnmp", []uint32{0x2ec00400, 0x6ec00400, 0x2ea0c400, 0x6ea0c400, 0x6ee0c400}, []uint32{0x5eb0c800, 0x7eb0c800, 0x7ef0c800}, "minnum"},
	}
	var source strings.Builder
	source.WriteString("TEXT rawfloatpairwiseminmaxforms(SB),$0-0\n")
	for _, op := range ops {
		for _, base := range op.vectorBases {
			fmt.Fprintf(&source, "\tWORD $%#08x // %s vector\n", base|29<<16|30<<5|28, op.name)
		}
		for _, base := range op.scalarBases {
			fmt.Fprintf(&source, "\tWORD $%#08x // %s scalar\n", base|30<<5|29, op.name)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawfloatpairwiseminmaxforms": {Name: "rawfloatpairwiseminmaxforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range ops {
				for _, suffix := range []string{"f16", "f32", "f64", "v4f16", "v8f16", "v2f32", "v4f32", "v2f64"} {
					want := "@llvm." + op.intrinsic + "." + suffix
					if !strings.Contains(ir, want) {
						t.Fatalf("raw %s for %s omitted %s:\n%s", op.name, triple, want, ir)
					}
				}
			}
			compileLLVMToObject(t, llc, triple, "raw-float-pairwise-minmax.ll", "raw-float-pairwise-minmax.o", ir)
		})
	}
}

func TestARM64RawFloatPairwiseMinMaxDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e60f400, // reserved D1 vector arrangement
		0x2e20d400, // FADDP
		0x7e30d800, // scalar FADDP
		0x2e403800, // adjacent FP16 opcode bits
		0x5e70f800, // reserved scalar FP16 size combination
	} {
		if _, ok := decodeARM64RawFloatPairwiseMinMax(word); ok {
			t.Fatalf("pairwise min/max decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawFloatPairwiseMinMaxRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatpairwiseminmax(SB),$0-16
	MOVD input+0(FP), R0
	MOVD output+8(FP), R1
	VLD1 (R0), [V0.S4]
	WORD $0x6e20f401 // FMAXP V1.4S, V0.4S, V0.4S
	WORD $0x6ea0f402 // FMINP V2.4S, V0.4S, V0.4S
	WORD $0x6e20c403 // FMAXNMP V3.4S, V0.4S, V0.4S
	WORD $0x6ea0c404 // FMINNMP V4.4S, V0.4S, V0.4S
	WORD $0x7e30f805 // FMAXP S5, V0.2S
	WORD $0x7eb0f806 // FMINP S6, V0.2S
	VST1.P [V1.S4], 16(R1)
	VST1.P [V2.S4], 16(R1)
	VST1.P [V3.S4], 16(R1)
	VST1.P [V4.S4], 16(R1)
	FMOVS F5, 0(R1)
	FMOVS F6, 4(R1)
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
		Sigs: map[string]FuncSig{"rawfloatpairwiseminmax": {
			Name: "rawfloatpairwiseminmax", Args: []LLVMType{Ptr, Ptr}, Ret: Void,
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
extern void rawfloatpairwiseminmax(const float *, float *);
int main(void) {
  const float input[4] = {-2, 7, 3, 1};
  const float want[18] = {
    7,3,7,3, -2,1,-2,1, 7,3,7,3, -2,1,-2,1, 7,-2
  };
  float got[18] = {0};
  rawfloatpairwiseminmax(input, got);
  for (int i = 0; i < 18; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_pairwise_minmax", triple, ir, mainC, nil)
}
