package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func encodeARM64SaturatingShiftNarrow(base uint32, destinationBits, shift int, highHalf bool, source, destination int) uint32 {
	encodedImmediate := uint32(2*destinationBits - shift)
	word := base | encodedImmediate<<16 | uint32(source)<<5 | uint32(destination)
	if highHalf {
		word |= 1 << 30
	}
	return word
}

func TestTranslateARM64RawSaturatingShiftNarrowCompleteArchitectureFamily(t *testing.T) {
	type family struct {
		name       string
		vectorBase uint32
		scalarBase uint32
	}
	families := []family{
		{name: "VSQSHRN", vectorBase: 0x0f009400, scalarBase: 0x5f009400},
		{name: "VSQRSHRN", vectorBase: 0x0f009c00, scalarBase: 0x5f009c00},
		{name: "VSQSHRUN", vectorBase: 0x2f008400, scalarBase: 0x7f008400},
		{name: "VSQRSHRUN", vectorBase: 0x2f008c00, scalarBase: 0x7f008c00},
		{name: "VUQSHRN", vectorBase: 0x2f009400, scalarBase: 0x7f009400},
		{name: "VUQRSHRN", vectorBase: 0x2f009c00, scalarBase: 0x7f009c00},
	}
	letter := map[int]string{8: "B", 16: "H", 32: "S", 64: "D"}
	var source strings.Builder
	source.WriteString("TEXT saturatingShiftNarrowArchitectureForms(SB),$0-0\n")
	for _, family := range families {
		for _, destinationBits := range []int{8, 16, 32} {
			for _, highHalf := range []bool{false, true} {
				for _, shift := range []int{1, destinationBits} {
					word := encodeARM64SaturatingShiftNarrow(family.vectorBase, destinationBits, shift, highHalf, 29, 28)
					decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
					if err != nil {
						t.Fatalf("decode %s destination=%d high=%v shift=%d: %v", family.name, destinationBits, highHalf, shift, err)
					}
					wantName := family.name
					if highHalf {
						wantName += "2"
					}
					wantSource := Reg(fmt.Sprintf("V29.%s%d", letter[destinationBits*2], 128/(destinationBits*2)))
					wantDestinationLanes := 64 / destinationBits
					if highHalf {
						wantDestinationLanes *= 2
					}
					wantDestination := Reg(fmt.Sprintf("V28.%s%d", letter[destinationBits], wantDestinationLanes))
					if decoded.Op != Op(wantName) || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != int64(shift) ||
						decoded.Args[1].Reg != wantSource || decoded.Args[2].Reg != wantDestination {
						t.Fatalf("decoded %s destination=%d high=%v shift=%d %#08x as %#v", family.name, destinationBits, highHalf, shift, word, decoded)
					}
					fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
				}
			}
			for _, shift := range []int{1, destinationBits} {
				word := encodeARM64SaturatingShiftNarrow(family.scalarBase, destinationBits, shift, false, 29, 28)
				decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
				if err != nil {
					t.Fatalf("decode scalar %s destination=%d shift=%d: %v", family.name, destinationBits, shift, err)
				}
				if decoded.Op != Op(family.name) || len(decoded.Args) != 3 || decoded.Args[0].Kind != OpImm || decoded.Args[0].Imm != int64(shift) ||
					decoded.Args[1].Reg != "V29" || decoded.Args[2].Reg != "V28" {
					t.Fatalf("decoded scalar %s destination=%d shift=%d %#08x as %#v", family.name, destinationBits, shift, word, decoded)
				}
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)

	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			file, err := Parse(ArchARM64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"saturatingShiftNarrowArchitectureForms": {Name: "saturatingShiftNarrowArchitectureForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"ashr", "lshr", "icmp", "select", "trunc", "insertelement"} {
				if !strings.Contains(ll, " = "+operation+" ") {
					t.Fatalf("%s omitted %s semantics:\n%s", triple, operation, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-saturating-shift-narrow.ll", "arm64-saturating-shift-narrow.o", ll)
		})
	}
}

func TestARM64RawSaturatingShiftNarrowDecoderCoversEveryImmediate(t *testing.T) {
	families := []struct {
		vectorBase uint32
		scalarBase uint32
	}{
		{0x0f009400, 0x5f009400},
		{0x0f009c00, 0x5f009c00},
		{0x2f008400, 0x7f008400},
		{0x2f008c00, 0x7f008c00},
		{0x2f009400, 0x7f009400},
		{0x2f009c00, 0x7f009c00},
	}
	for _, family := range families {
		for _, destinationBits := range []int{8, 16, 32} {
			for shift := 1; shift <= destinationBits; shift++ {
				for _, form := range []struct {
					base     uint32
					highHalf bool
					scalar   bool
				}{
					{base: family.vectorBase},
					{base: family.vectorBase, highHalf: true},
					{base: family.scalarBase, scalar: true},
				} {
					word := encodeARM64SaturatingShiftNarrow(form.base, destinationBits, shift, form.highHalf, 31, 30)
					decoded, ok := decodeARM64RawSaturatingShiftNarrow(word)
					if !ok || decoded.shift != shift || decoded.source != 31 || decoded.destination != 30 ||
						decoded.scalar != form.scalar || decoded.highHalf != form.highHalf ||
						decoded.sourceArrangement.elementBits != destinationBits*2 || decoded.destinationArrangement.elementBits != destinationBits {
						t.Fatalf("decode base=%#08x destination=%d shift=%d high=%v scalar=%v: form=%#v ok=%v",
							form.base, destinationBits, shift, form.highHalf, form.scalar, decoded, ok)
					}
				}
			}
		}
	}
}

func TestARM64SaturatingShiftNarrowRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	families := []uint32{0x0f009400, 0x0f009c00, 0x2f008400, 0x2f008c00, 0x2f009400, 0x2f009c00}
	var source strings.Builder
	source.WriteString("TEXT saturatingShiftNarrowSemantics(SB),$0-24\n")
	source.WriteString("\tMOVD in+0(FP), R0\n\tMOVD initial+8(FP), R1\n\tMOVD out+16(FP), R2\n")
	for _, base := range families {
		for _, highHalf := range []bool{false, true} {
			source.WriteString("\tVLD1 (R0), [V0.H8]\n\tVLD1 (R1), [V1.B16]\n")
			word := encodeARM64SaturatingShiftNarrow(base, 8, 1, highHalf, 0, 1)
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			source.WriteString("\tVST1.P [V1.B16], 16(R2)\n")
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"saturatingShiftNarrowSemantics": {
			Name: "saturatingShiftNarrowSemantics", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <limits.h>
extern void saturatingShiftNarrowSemantics(const int16_t *, const uint8_t *, uint8_t *);
static int16_t signed_clamp(int32_t value) {
  if (value < INT8_MIN) return INT8_MIN;
  if (value > INT8_MAX) return INT8_MAX;
  return value;
}
static uint16_t unsigned_clamp(int32_t value) {
  if (value < 0) return 0;
  if (value > UINT8_MAX) return UINT8_MAX;
  return value;
}
int main(void) {
  const int16_t in[8] = {INT16_MIN, -1001, -255, -1, 0, 255, 1001, INT16_MAX};
  uint8_t initial[16], got[12*16] = {0};
  for (int i = 0; i < 16; i++) initial[i] = (uint8_t)(i * 13u + 7u);
  saturatingShiftNarrowSemantics(in, initial, got);
  for (int family = 0; family < 6; family++) {
    for (int high = 0; high < 2; high++) {
      const int output = (family * 2 + high) * 16;
      for (int lane = 0; lane < 16; lane++) {
        uint8_t want;
        if (high && lane < 8) {
          want = initial[lane];
        } else if (!high && lane >= 8) {
          want = 0;
        } else {
          const int input_lane = high ? lane - 8 : lane;
          const int32_t signed_value = in[input_lane];
          const uint32_t unsigned_value = (uint16_t)in[input_lane];
          const int rounding = family == 1 || family == 3 || family == 5;
          if (family < 2) {
            int32_t shifted = signed_value >> 1;
            if (rounding) shifted += signed_value & 1;
            want = (uint8_t)(int8_t)signed_clamp(shifted);
          } else if (family < 4) {
            int32_t shifted = signed_value >> 1;
            if (rounding) shifted += signed_value & 1;
            want = (uint8_t)unsigned_clamp(shifted);
          } else {
            uint32_t shifted = unsigned_value >> 1;
            if (rounding) shifted += unsigned_value & 1;
            want = (uint8_t)(shifted > UINT8_MAX ? UINT8_MAX : shifted);
          }
        }
        if (got[output+lane] != want) return output + lane + 1;
      }
    }
  }
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_saturating_shift_narrow", triple, ll, mainC, nil)
}
