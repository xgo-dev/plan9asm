package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func arm64EncodeRawFMLAByElement(subtract, scalar bool, bits, vectorBits, lane, rm, rn, rd int) uint32 {
	base := uint32(0x0f001000)
	if scalar {
		base = 0x5f001000
	} else if vectorBits == 128 {
		base |= 1 << 30
	}
	if subtract {
		base |= 1 << 14
	}
	switch bits {
	case 16:
		base |= uint32(lane&1) << 20
		base |= uint32((lane>>1)&1) << 21
		base |= uint32((lane>>2)&1) << 11
	case 32:
		base |= 1 << 23
		base |= uint32(lane&1) << 21
		base |= uint32((lane>>1)&1) << 11
	case 64:
		base |= 3 << 22
		base |= uint32(lane&1) << 11
	default:
		panic(fmt.Sprintf("unsupported FMLA element width %d", bits))
	}
	return base | uint32(rm)<<16 | uint32(rn)<<5 | uint32(rd)
}

func TestARM64RawFMLADecoderRejectsAdjacentAndReservedEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x0e60cc00, // reserved FMLA D1 vector arrangement.
		0x0ee0cc00, // reserved FMLS D1 vector arrangement.
		0x0fc01000, // reserved indexed FMLA D1 arrangement.
		0x0fc05000, // reserved indexed FMLS D1 arrangement.
		0x4fe01000, // indexed D form with reserved L bit.
		0x4fe05000, // indexed D subtract form with reserved L bit.
		0x0f809000, // FMUL by element.
		0x0e400800, // adjacent same-vector opcode.
	} {
		if _, ok := decodeARM64RawFMLA(word); ok {
			t.Fatalf("FMLA/FMLS decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
}

func TestARM64RawFMLARuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	indexedAdd := arm64EncodeRawFMLAByElement(false, false, 16, 128, 7, 2, 1, 4)
	indexedSubtract := arm64EncodeRawFMLAByElement(true, false, 16, 128, 6, 2, 1, 5)
	scalarAdd := arm64EncodeRawFMLAByElement(false, true, 16, 16, 3, 2, 7, 6)
	source := fmt.Sprintf(`
TEXT rawfmla(SB),$0-32
	MOVD accumulator+0(FP), R0
	MOVD multiplicand+8(FP), R1
	MOVD multiplier+16(FP), R2
	MOVD output+24(FP), R3
	VLD1 (R0), [V0.H8]
	VLD1 (R0), [V3.H8]
	VLD1 (R0), [V4.H8]
	VLD1 (R0), [V5.H8]
	VLD1 (R0), [V6.H8]
	VLD1 (R1), [V1.H8]
	VLD1 (R1), [V7.H8]
	VLD1 (R2), [V2.H8]
	WORD $0x4e420c20 // FMLA V0.8H, V1.8H, V2.8H
	WORD $0x4ec20c23 // FMLS V3.8H, V1.8H, V2.8H
	WORD $%#08x // FMLA V4.8H, V1.8H, V2.H[7]
	WORD $%#08x // FMLS V5.8H, V1.8H, V2.H[6]
	WORD $%#08x // FMLA H6, H7, V2.H[3]
	VST1.P [V0.H8], 16(R3)
	VST1.P [V3.H8], 16(R3)
	VST1.P [V4.H8], 16(R3)
	VST1.P [V5.H8], 16(R3)
	VST1 [V6.H8], (R3)
	RET
`, indexedAdd, indexedSubtract, scalarAdd)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		TargetTriple: triple, Goarch: "arm64",
		Sigs: map[string]FuncSig{
			"rawfmla": {
				Name: "rawfmla", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
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
typedef _Float16 f16;
extern void rawfmla(const f16 *, const f16 *, const f16 *, f16 *);
int main(void) {
  const f16 accumulator[8] = {1,1,1,1,1,1,1,1};
  const f16 multiplicand[8] = {1,2,3,4,5,6,7,8};
  const f16 multiplier[8] = {2,3,4,5,6,7,8,9};
  const f16 same_add[8] = {3,7,13,21,31,43,57,73};
  const f16 same_sub[8] = {-1,-5,-11,-19,-29,-41,-55,-71};
  const f16 indexed_add[8] = {10,19,28,37,46,55,64,73};
  const f16 indexed_sub[8] = {-7,-15,-23,-31,-39,-47,-55,-63};
  f16 got[40] = {0};
  rawfmla(accumulator, multiplicand, multiplier, got);
  for (int lane = 0; lane < 8; lane++) {
    if (got[lane] != same_add[lane]) return 1 + lane;
    if (got[8 + lane] != same_sub[lane]) return 10 + lane;
    if (got[16 + lane] != indexed_add[lane]) return 20 + lane;
    if (got[24 + lane] != indexed_sub[lane]) return 30 + lane;
  }
  if (got[32] != 6) return 40;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_fmla", triple, ir, mainC, nil)
}

func TestTranslateARM64RawFMLACompleteArchitecturalFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawfmlaforms(SB),$0-0\n")
	for _, base := range []uint32{
		0x0e400c00, 0x4e400c00, 0x0e20cc00, 0x4e20cc00, 0x4e60cc00, // FMLA H4/H8/S2/S4/D2.
		0x0ec00c00, 0x4ec00c00, 0x0ea0cc00, 0x4ea0cc00, 0x4ee0cc00, // FMLS H4/H8/S2/S4/D2.
	} {
		fmt.Fprintf(&source, "\tWORD $%#08x\n", base|29<<16|30<<5|28)
	}
	type indexedFormat struct {
		scalar     bool
		bits       int
		vectorBits int
		lanes      int
		maxRm      int
	}
	formats := []indexedFormat{
		{scalar: true, bits: 16, vectorBits: 16, lanes: 8, maxRm: 15},
		{scalar: true, bits: 32, vectorBits: 32, lanes: 4, maxRm: 31},
		{scalar: true, bits: 64, vectorBits: 64, lanes: 2, maxRm: 31},
		{bits: 16, vectorBits: 64, lanes: 8, maxRm: 15},
		{bits: 16, vectorBits: 128, lanes: 8, maxRm: 15},
		{bits: 32, vectorBits: 64, lanes: 4, maxRm: 31},
		{bits: 32, vectorBits: 128, lanes: 4, maxRm: 31},
		{bits: 64, vectorBits: 128, lanes: 2, maxRm: 31},
	}
	for _, subtract := range []bool{false, true} {
		for _, form := range formats {
			for lane := 0; lane < form.lanes; lane++ {
				for _, rm := range []int{0, form.maxRm} {
					word := arm64EncodeRawFMLAByElement(subtract, form.scalar, form.bits, form.vectorBits, lane, rm, 30, 29)
					decoded, ok := decodeARM64RawFMLA(word)
					if !ok || !decoded.indexed || decoded.subtract != subtract || decoded.scalar != form.scalar ||
						decoded.arrangement != (arm64VectorArrangement{elementBits: form.bits, lanes: form.vectorBits / form.bits}) ||
						decoded.lane != lane || decoded.elementReg != rm || decoded.sourceReg != 30 || decoded.destination != 29 {
						t.Fatalf("decode FMLA/FMLS indexed word %#08x = %+v, ok=%v", word, decoded, ok)
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
				Sigs: map[string]FuncSig{"rawfmlaforms": {Name: "rawfmlaforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-fmla.ll", "arm64-raw-fmla.o", ir)
		})
	}
}
