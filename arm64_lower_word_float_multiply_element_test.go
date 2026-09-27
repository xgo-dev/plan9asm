package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64EncodeRawFMULByElement(vector bool, bits, vectorBits, lane, rm, rn, rd int) uint32 {
	base := uint32(0x5f009000)
	if vector {
		base = 0x0f009000
		if vectorBits == 128 {
			base |= 1 << 30
		}
	}
	if bits >= 32 {
		base |= 1 << 23
	}
	if bits == 16 {
		base |= uint32(lane&1) << 20
		base |= uint32((lane>>1)&1) << 21
		base |= uint32((lane>>2)&1) << 11
		rm &= 15
	} else if bits == 64 {
		base |= 1 << 22
		base |= uint32(lane&1) << 11
	} else {
		base |= uint32(lane&1) << 21
		base |= uint32((lane>>1)&1) << 11
	}
	return base | uint32(rm)<<16 | uint32(rn)<<5 | uint32(rd)
}

func TestTranslateARM64RawFMULByElementCompleteArchitecturalFormats(t *testing.T) {
	type format struct {
		vector     bool
		bits       int
		vectorBits int
		lanes      int
	}
	formats := []format{
		{vector: false, bits: 16, vectorBits: 16, lanes: 8},
		{vector: false, bits: 32, vectorBits: 32, lanes: 4},
		{vector: false, bits: 64, vectorBits: 64, lanes: 2},
		{vector: true, bits: 16, vectorBits: 64, lanes: 8},
		{vector: true, bits: 16, vectorBits: 128, lanes: 8},
		{vector: true, bits: 32, vectorBits: 64, lanes: 4},
		{vector: true, bits: 32, vectorBits: 128, lanes: 4},
		{vector: true, bits: 64, vectorBits: 128, lanes: 2},
	}
	var source strings.Builder
	source.WriteString("TEXT rawfmulbyelementforms(SB),$0-0\n")
	for _, form := range formats {
		for lane := 0; lane < form.lanes; lane++ {
			lastElementRegister := 31
			if form.bits == 16 {
				lastElementRegister = 15
			}
			for _, rm := range []int{0, lastElementRegister} {
				for _, extended := range []bool{false, true} {
					word := arm64EncodeRawFMULByElement(form.vector, form.bits, form.vectorBits, lane, rm, 30, 29)
					if extended {
						word |= 1 << 29
					}
					decoded, ok := decodeARM64RawFMULByElement(word)
					if !ok || decoded.vector != form.vector || decoded.extended != extended ||
						decoded.arrangement.elementBits != form.bits || decoded.arrangement.lanes != form.vectorBits/form.bits ||
						decoded.lane != lane || decoded.elementReg != rm || decoded.sourceReg != 30 || decoded.destination != 29 {
						t.Fatalf("decode FMUL/FMULX element %#08x = %#v, %v", word, decoded, ok)
					}
					fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
				}
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
			ir, err := Translate(file, Options{
				TargetTriple: triple, Goarch: "arm64",
				Sigs: map[string]FuncSig{"rawfmulbyelementforms": {Name: "rawfmulbyelementforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if got, want := strings.Count(ir, "fmul "), 80; got != want {
				t.Fatalf("raw FMUL-by-element emitted %d multiplies, want %d:\n%s", got, want, ir)
			}
			gotFMULXCalls := 0
			for _, line := range strings.Split(ir, "\n") {
				if strings.Contains(line, " = call ") && strings.Contains(line, "@llvm.aarch64.neon.fmulx.") {
					gotFMULXCalls++
				}
			}
			if got, want := gotFMULXCalls, 80; got != want {
				t.Fatalf("raw FMULX-by-element emitted %d intrinsic calls, want %d:\n%s", got, want, ir)
			}
			if !strings.Contains(ir, "+fullfp16") {
				t.Fatalf("raw half-precision FMUL-by-element for %s omitted +fullfp16:\n%s", triple, ir)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fmul-by-element.ll", "arm64-raw-fmul-by-element.o", ir)
		})
	}
}

func TestARM64RawFMULByElementDecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0fc09000, // reserved vector D1
		0x4fe09000, // reserved D2 with L=1
		0x0f801000, // FMLA by element
	} {
		if _, ok := decodeARM64RawFMULByElement(word); ok {
			t.Fatalf("FMUL-by-element decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawFMULByElementRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `
TEXT rawfmulbyelement(SB),$0-24
	MOVD input+0(FP), R0
	MOVD factors+8(FP), R1
	MOVD output+16(FP), R2
	VLD1 (R0), [V1.S4]
	VLD1 (R1), [V0.S4]
	WORD $0x4f809021 // FMUL V1.4S, V1.4S, V0.S[0]
	VST1 [V1.S4], (R2)
	RET

TEXT rawfmulbyelementhalf(SB),$0-24
	MOVD input+0(FP), R0
	MOVD factors+8(FP), R1
	MOVD output+16(FP), R2
	VLD1 (R0), [V1.H8]
	VLD1 (R1), [V0.H8]
	WORD $0x4f309821 // FMUL V1.8H, V1.8H, V0.H[7]
	VST1 [V1.H8], (R2)
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
			"rawfmulbyelement": {
				Name: "rawfmulbyelement", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
				Frame: FrameLayout{Params: []FrameSlot{
					{Offset: 0, Type: Ptr, Index: 0, Field: -1},
					{Offset: 8, Type: Ptr, Index: 1, Field: -1},
					{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				}},
			},
			"rawfmulbyelementhalf": {
				Name: "rawfmulbyelementhalf", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawfmulbyelement(const float *, const float *, float *);
extern void rawfmulbyelementhalf(const _Float16 *, const _Float16 *, _Float16 *);
int main(void) {
  const float input[4] = {1.5f, -2.0f, 3.25f, -4.5f};
  const float factors[4] = {2.0f, 7.0f, 11.0f, 13.0f};
  float got[4] = {0};
  rawfmulbyelement(input, factors, got);
  for (int i = 0; i < 4; i++) if (got[i] != input[i] * factors[0]) return i + 1;
  const _Float16 input_h[8] = {1,2,3,4,5,6,7,8};
  const _Float16 factors_h[8] = {2,3,4,5,6,7,8,9};
  _Float16 got_h[8] = {0};
  rawfmulbyelementhalf(input_h, factors_h, got_h);
  for (int i = 0; i < 8; i++) if (got_h[i] != input_h[i] * factors_h[7]) return i + 5;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fmul_by_element", triple, ir, mainC, nil)
}
