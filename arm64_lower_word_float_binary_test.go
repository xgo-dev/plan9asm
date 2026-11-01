package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawFloatBinaryCompleteAdvancedSIMDFormats(t *testing.T) {
	bases := []uint32{
		0x0e20d400, 0x0ea0d400, 0x2e20dc00, 0x2e20fc00,
		0x0e20f400, 0x0ea0f400, 0x0e20c400, 0x0ea0c400,
		0x2ea0d400, // FABD.
		0x0e20dc00, // FMULX.
	}
	halfBases := []uint32{
		0x0e401400, 0x0ec01400, 0x2e401c00, 0x2e403c00,
		0x0e403400, 0x0ec03400, 0x0e400400, 0x0ec00400,
		0x2ec01400, // FABD.
		0x0e401c00, // FMULX.
	}
	var source strings.Builder
	source.WriteString("TEXT rawfloatbinaryforms(SB),$0-0\n")
	for _, base := range halfBases {
		for _, modifier := range []uint32{0, 1 << 30} { // H4, H8.
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|modifier|2<<16|1<<5)
		}
	}
	for _, base := range bases {
		for _, modifier := range []uint32{0, 1 << 30, 1<<30 | 1<<22} { // S2, S4, D2.
			fmt.Fprintf(&source, "\tWORD $%#08x\n", base|modifier|2<<16|1<<5)
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
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawfloatbinaryforms": {Name: "rawfloatbinaryforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"fadd <4 x half>", "fadd <8 x half>",
				"fsub <4 x half>", "fsub <8 x half>",
				"fmul <4 x half>", "fmul <8 x half>",
				"fdiv <4 x half>", "fdiv <8 x half>",
				"@llvm.maximum.v4f16", "@llvm.maximum.v8f16",
				"@llvm.minimum.v4f16", "@llvm.minimum.v8f16",
				"@llvm.maxnum.v4f16", "@llvm.maxnum.v8f16",
				"@llvm.minnum.v4f16", "@llvm.minnum.v8f16",
				"@llvm.aarch64.neon.fabd.v4f16", "@llvm.aarch64.neon.fabd.v8f16",
				"@llvm.aarch64.neon.fabd.v2f32", "@llvm.aarch64.neon.fabd.v4f32", "@llvm.aarch64.neon.fabd.v2f64",
				"@llvm.aarch64.neon.fmulx.v4f16", "@llvm.aarch64.neon.fmulx.v8f16",
				"@llvm.aarch64.neon.fmulx.v2f32", "@llvm.aarch64.neon.fmulx.v4f32", "@llvm.aarch64.neon.fmulx.v2f64",
				"fadd <", "fsub <", "fmul <", "fdiv <",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw float binary lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-binary.ll", "arm64-raw-float-binary.o", ll)
		})
	}
}

func TestARM64RawFloatBinaryRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatbinary(SB),$0-24
	MOVD a+0(FP), R0
	MOVD b+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V0.S4]
	VLD1 (R1), [V1.S4]
	WORD $0x4e21d402 // FADD   V2.4S, V0.4S, V1.4S
	WORD $0x4ea1d403 // FSUB   V3.4S, V0.4S, V1.4S
	WORD $0x6e21dc04 // FMUL   V4.4S, V0.4S, V1.4S
	WORD $0x6e21fc05 // FDIV   V5.4S, V0.4S, V1.4S
	WORD $0x4e21f406 // FMAX   V6.4S, V0.4S, V1.4S
	WORD $0x4ea1f407 // FMIN   V7.4S, V0.4S, V1.4S
	WORD $0x4e21c408 // FMAXNM V8.4S, V0.4S, V1.4S
	WORD $0x4ea1c409 // FMINNM V9.4S, V0.4S, V1.4S
	VST1.P [V2.S4, V3.S4, V4.S4, V5.S4], 64(R2)
	VST1 [V6.S4, V7.S4, V8.S4, V9.S4], (R2)
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
			"rawfloatbinary": {
				Name: "rawfloatbinary", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatbinary(const float *, const float *, float *);
int main(void) {
  const float a[4] = {8.0f, -6.0f, 1.5f, -4.0f};
  const float b[4] = {2.0f, 3.0f, -2.0f, 4.0f};
  float got[32] = {0};
  rawfloatbinary(a, b, got);
  for (int i = 0; i < 4; i++) {
    const float want[8] = {a[i]+b[i], a[i]-b[i], a[i]*b[i], a[i]/b[i], a[i]>b[i]?a[i]:b[i], a[i]<b[i]?a[i]:b[i], a[i]>b[i]?a[i]:b[i], a[i]<b[i]?a[i]:b[i]};
    for (int op = 0; op < 8; op++) if (got[op*4+i] != want[op]) return op*4+i+1;
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_binary", triple, ll, mainC, nil)
}

func TestARM64RawFloatBinaryDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{0x2e20d400, 0x1e22d420, 0x0e60d400} { // FADDP, scalar FADD, reserved D1.
		if _, ok := decodeARM64RawFloatBinary(word); ok {
			t.Fatalf("float-binary decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
