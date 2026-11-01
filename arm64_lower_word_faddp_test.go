package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawFADDPCompleteArchitecturalFormats(t *testing.T) {
	vectorBases := []uint32{
		0x2e401400, // FADDP Vd.4H, Vn.4H, Vm.4H.
		0x6e401400, // FADDP Vd.8H, Vn.8H, Vm.8H.
		0x2e20d400, // FADDP Vd.2S, Vn.2S, Vm.2S.
		0x6e20d400, // FADDP Vd.4S, Vn.4S, Vm.4S.
		0x6e60d400, // FADDP Vd.2D, Vn.2D, Vm.2D.
	}
	scalarBases := []uint32{
		0x5e30d800, // FADDP Hd, Vn.2H.
		0x7e30d800, // FADDP Sd, Vn.2S.
		0x7e70d800, // FADDP Dd, Vn.2D.
	}
	var source strings.Builder
	source.WriteString("TEXT rawfaddpforms(SB),$0-0\n")
	for _, base := range vectorBases {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", base|29<<16|30<<5|28)
	}
	for _, base := range scalarBases {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", base|30<<5|29)
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
				Sigs: map[string]FuncSig{"rawfaddpforms": {Name: "rawfaddpforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-faddp.ll", "arm64-raw-faddp.o", ir)
		})
	}
}

func TestARM64RawFADDPDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2e60d400, // reserved D1 vector arrangement.
		0x2e20f400, // FMAXP vector instruction.
		0x7e30f800, // FMAXP scalar instruction.
		0x2e401800, // adjacent opcode bits in the FP16 vector encoding.
		0x5e70d800, // reserved scalar FP16 size combination.
	} {
		if _, ok := decodeARM64RawFADDP(word); ok {
			t.Fatalf("FADDP decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawFADDPRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfaddp(SB),$0-32
	MOVD halfs+0(FP), R0
	MOVD singles+8(FP), R1
	MOVD doubles+16(FP), R2
	MOVD output+24(FP), R3
	VLD1.P 16(R0), [V0.H8]
	VLD1 (R0), [V1.H8]
	WORD $0x2e411402 // FADDP V2.4H, V0.4H, V1.4H
	WORD $0x6e411403 // FADDP V3.8H, V0.8H, V1.8H
	WORD $0x5e30d804 // FADDP H4, V0.2H
	VST1.P [V2.H4], 8(R3)
	VST1.P [V3.H8], 16(R3)
	VST1.P [V4.H4], 8(R3)
	VLD1.P 16(R1), [V5.S4]
	VLD1 (R1), [V6.S4]
	WORD $0x2e26d4a7 // FADDP V7.2S, V5.2S, V6.2S
	WORD $0x6e26d4a8 // FADDP V8.4S, V5.4S, V6.4S
	WORD $0x7e30d8a9 // FADDP S9, V5.2S
	VST1.P [V7.S2], 8(R3)
	VST1.P [V8.S4], 16(R3)
	VST1.P [V9.S2], 8(R3)
	VLD1.P 16(R2), [V10.D2]
	VLD1 (R2), [V11.D2]
	WORD $0x6e6bd54c // FADDP V12.2D, V10.2D, V11.2D
	WORD $0x7e70d94d // FADDP D13, V10.2D
	VST1.P [V12.D2], 16(R3)
	VST1 [V13.D2], (R3)
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
			"rawfaddp": {
				Name: "rawfaddp", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
					{Offset: 24, Type: Ptr, Index: 3, Field: -1},
				}},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfaddp(const uint16_t *, const float *, const double *, void *);
int main(void) {
  const uint16_t halfs[16] = {
    0x3c00,0x3c00,0x4000,0x4000,0x4200,0x4200,0x4400,0x4400,
    0x4500,0x4500,0x4600,0x4600,0x4700,0x4700,0x4800,0x4800
  };
  const float singles[8] = {1,2,3,4,10,20,30,40};
  const double doubles[4] = {1,2,10,20};
  _Alignas(16) unsigned char output[96] = {0};
  rawfaddp(halfs, singles, doubles, output);
  const uint16_t want_h4[4] = {0x4000,0x4400,0x4900,0x4a00};
  const uint16_t want_h8[8] = {0x4000,0x4400,0x4600,0x4800,0x4900,0x4a00,0x4b00,0x4c00};
  for (int i = 0; i < 4; i++) if (((uint16_t *)(output + 0))[i] != want_h4[i]) return 1 + i;
  for (int i = 0; i < 8; i++) if (((uint16_t *)(output + 8))[i] != want_h8[i]) return 10 + i;
  if (((uint16_t *)(output + 24))[0] != 0x4000) return 20;
  if (((float *)(output + 32))[0] != 3 || ((float *)(output + 32))[1] != 30) return 21;
  const float want_s4[4] = {3,7,30,70};
  for (int i = 0; i < 4; i++) if (((float *)(output + 40))[i] != want_s4[i]) return 22 + i;
  if (((float *)(output + 56))[0] != 3) return 30;
  if (((double *)(output + 64))[0] != 3 || ((double *)(output + 64))[1] != 30) return 31;
  if (((double *)(output + 80))[0] != 3) return 32;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_faddp", triple, ir, mainC, nil)
}
