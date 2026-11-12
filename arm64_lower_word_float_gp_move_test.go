package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestARM64RawFloatGPMoveDecoderCompleteRegisterFamily(t *testing.T) {
	formats := []struct {
		base    uint32
		bits    int
		toFloat bool
		upper   bool
	}{
		{base: 0x1ee70000, bits: 16, toFloat: true},
		{base: 0x1ee60000, bits: 16, toFloat: false},
		{base: 0x1e270000, bits: 32, toFloat: true},
		{base: 0x1e260000, bits: 32, toFloat: false},
		{base: 0x9e670000, bits: 64, toFloat: true},
		{base: 0x9e660000, bits: 64, toFloat: false},
		{base: 0x9eaf0000, bits: 64, toFloat: true, upper: true},
		{base: 0x9eae0000, bits: 64, toFloat: false, upper: true},
	}

	count := 0
	for _, format := range formats {
		for source := 0; source < 32; source++ {
			for destination := 0; destination < 32; destination++ {
				word := format.base | uint32(source)<<5 | uint32(destination)
				form, ok := decodeARM64RawFloatGPMove(word)
				if !ok {
					t.Fatalf("decoder rejected %#08x", word)
				}
				wantFP, wantGP := destination, source
				if !format.toFloat {
					wantFP, wantGP = source, destination
				}
				if form.bits != format.bits || form.toFloat != format.toFloat ||
					form.upper != format.upper || form.floatReg != wantFP || form.gpReg != wantGP {
					t.Fatalf("decode %#08x = %+v", word, form)
				}
				count++
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d floating/GP move encodings, want 8192", count)
	}
}

func TestTranslateARM64RawFloatGPMoveCompleteRegisterFamily(t *testing.T) {
	formats := []struct {
		name string
		base uint32
	}{
		{name: "FMOV H0, W30", base: 0x1ee70000},
		{name: "FMOV W29, H1", base: 0x1ee60000},
		{name: "FMOV S2, W30", base: 0x1e270000},
		{name: "FMOV W29, S3", base: 0x1e260000},
		{name: "FMOV D4, X30", base: 0x9e670000},
		{name: "FMOV X29, D5", base: 0x9e660000},
		{name: "FMOV V6.D[1], X30", base: 0x9eaf0000},
		{name: "FMOV X29, V7.D[1]", base: 0x9eae0000},
	}

	var source strings.Builder
	source.WriteString("TEXT rawFloatGPMoveFamily(SB),$0-0\n")
	for index, format := range formats {
		registers := uint32(30<<5 | index)
		if index%2 == 1 {
			registers = uint32(index<<5 | 29)
		}
		fmt.Fprintf(&source, "\tWORD $%#08x // %s\n", format.base|registers, format.name)
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawFloatGPMoveFamily": {Name: "rawFloatGPMoveFamily", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"trunc i64", "to i16", "to i32",
				"extractelement <2 x i64>", "i64 1",
				"insertelement <2 x i64>",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ir, want) {
					t.Fatalf("raw floating/GP move IR omitted %q:\n%s", want, ir)
				}
			}

			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-float-gp-move.ll", "arm64-raw-float-gp-move.o", ir)
		})
	}
}

func TestARM64RawFloatGPMoveRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfloatgpmove(SB),$0-24
	MOVD low+0(FP), R0
	MOVD high+8(FP), R1
	MOVD out+16(FP), R2
	WORD $0x9e670000 // FMOV D0, X0
	WORD $0x9eaf0020 // FMOV V0.D[1], X1
	WORD $0x9e660004 // FMOV X4, D0
	WORD $0x9eae0003 // FMOV X3, V0.D[1]
	WORD $0x1ee70001 // FMOV H1, W0
	WORD $0x1ee60025 // FMOV W5, H1
	WORD $0x1e270002 // FMOV S2, W0
	WORD $0x1e260046 // FMOV W6, S2
	MOVD R4, 0(R2)
	MOVD R3, 8(R2)
	MOVD R5, 16(R2)
	MOVD R6, 24(R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawfloatgpmove": {
			Name: "rawfloatgpmove", Args: []LLVMType{I64, I64, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: I64, Index: 0, Field: -1},
				{Offset: 8, Type: I64, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
extern void rawfloatgpmove(uint64_t, uint64_t, uint64_t *);
int main(void) {
  const uint64_t low = 0x8877665544332211ULL;
  const uint64_t high = 0xffeeddccbbaa0099ULL;
  uint64_t got[4] = {0};
  rawfloatgpmove(low, high, got);
  if (got[0] != low) return 1;
  if (got[1] != high) return 2;
  if (got[2] != (low & 0xffff)) return 3;
  if (got[3] != (low & 0xffffffff)) return 4;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_float_gp_move", triple, ir, mainC, nil)
}

func TestARM64RawFloatGPMoveDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1ee50000, // Adjacent unallocated opcode.
		0x9ee70000, // Invalid X-to-half combination.
		0x1e670000, // Invalid W-to-double combination.
		0x1ee01000, // Scalar floating immediate.
	} {
		if _, ok := decodeARM64RawFloatGPMove(word); ok {
			t.Fatalf("floating/GP move decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}
