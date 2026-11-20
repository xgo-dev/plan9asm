package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

type arm64RawStructureLanePost int

const (
	arm64RawStructureLaneNoPost arm64RawStructureLanePost = iota
	arm64RawStructureLaneFixedPost
	arm64RawStructureLaneRegisterPost
)

func encodeARM64RawStructureLane(load bool, count, elementBits, lane int, post arm64RawStructureLanePost, postRegister, base, firstRegister int) uint32 {
	word := uint32(0x0d000000 | base<<5 | firstRegister)
	if load {
		word |= 1 << 22
	}
	if count%2 == 0 {
		word |= 1 << 21
	}
	if count >= 3 {
		word |= 1 << 13
	}
	if post != arm64RawStructureLaneNoPost {
		word |= 1 << 23
		if post == arm64RawStructureLaneFixedPost {
			postRegister = 31
		}
		word |= uint32(postRegister) << 16
	}
	switch elementBits {
	case 8:
		word |= uint32(lane>>3) << 30
		word |= uint32(lane&7) << 10
	case 16:
		word |= 1 << 14
		word |= uint32(lane>>2) << 30
		word |= uint32(lane&3) << 11
	case 32:
		word |= 1 << 15
		word |= uint32(lane>>1) << 30
		word |= uint32(lane&1) << 12
	case 64:
		word |= 1 << 15
		word |= 1 << 10
		word |= uint32(lane) << 30
	default:
		panic("invalid ARM64 structure-lane element width")
	}
	return word
}

func TestTranslateARM64RawStructureLaneReportedEncoding(t *testing.T) {
	const source = `TEXT rawStructureLane(SB),$0-0
	WORD $0x0da14010 // ST2 {V16.H, V17.H}[0], [R0], R1
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		TargetTriple: "aarch64-unknown-linux-gnu",
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{
			"rawStructureLane": {Name: "rawStructureLane", Ret: Void},
		},
	}); err != nil {
		t.Fatal(err)
	}
}

func TestARM64RawStructureLaneDecoderCoversCompleteArchitectureFamily(t *testing.T) {
	for _, load := range []bool{false, true} {
		for count := 1; count <= 4; count++ {
			for _, elementBits := range []int{8, 16, 32, 64} {
				for lane := 0; lane < 128/elementBits; lane++ {
					for _, post := range []arm64RawStructureLanePost{
						arm64RawStructureLaneNoPost,
						arm64RawStructureLaneFixedPost,
						arm64RawStructureLaneRegisterPost,
					} {
						word := encodeARM64RawStructureLane(load, count, elementBits, lane, post, 17, 31, 31)
						form, ok := decodeARM64RawStructureLane(word)
						wantPostRegister := 0
						if post == arm64RawStructureLaneFixedPost {
							wantPostRegister = 31
						} else if post == arm64RawStructureLaneRegisterPost {
							wantPostRegister = 17
						}
						if !ok || form.load != load || form.count != count || form.elementBits != elementBits ||
							form.lane != lane || form.firstRegister != 31 || form.base != 31 ||
							form.post != (post != arm64RawStructureLaneNoPost) || form.postRegister != wantPostRegister {
							t.Fatalf("decode load=%v count=%d bits=%d lane=%d post=%d word=%#08x: form=%#v ok=%v",
								load, count, elementBits, lane, post, word, form, ok)
						}
						decoded, err := decodeARM64RawWordInstruction(Instr{Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}})
						if err != nil {
							t.Fatalf("architecture decoder rejected %#08x: %v", word, err)
						}
						wantPrefix := map[bool]string{false: "ST", true: "LD"}[load]
						if count == 1 {
							wantPrefix = "V" + wantPrefix
						}
						wantOp := fmt.Sprintf("%s%d", wantPrefix, count)
						if strings.TrimSuffix(string(decoded.Op), ".P") != wantOp {
							t.Fatalf("architecture decoder decoded %#08x as %s, want %s", word, decoded.Op, wantOp)
						}
					}
				}
			}
		}
	}
}

func TestARM64RawStructureLaneDecoderRejectsAdjacentEncodings(t *testing.T) {
	validB := encodeARM64RawStructureLane(true, 1, 8, 0, arm64RawStructureLaneNoPost, 0, 0, 0)
	validH := encodeARM64RawStructureLane(true, 2, 16, 0, arm64RawStructureLaneNoPost, 0, 0, 0)
	validS := encodeARM64RawStructureLane(false, 3, 32, 0, arm64RawStructureLaneNoPost, 0, 0, 0)
	validD := encodeARM64RawStructureLane(false, 4, 64, 0, arm64RawStructureLaneNoPost, 0, 0, 0)
	for _, word := range []uint32{
		validB | 3<<14, // load-and-replicate opcode space
		validH | 1<<10,
		validS | 1<<11,
		validD | 1<<12,
		validB | 1<<16, // Rm is reserved without post-indexing
		validB | 1<<29,
	} {
		if form, ok := decodeARM64RawStructureLane(word); ok {
			t.Fatalf("decoded reserved or adjacent encoding %#08x as %#v", word, form)
		}
	}
}

func TestTranslateARM64RawStructureLaneCompleteArchitectureFamily(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawStructureLaneArchitectureForms(SB),$0-0\n")
	for _, load := range []bool{false, true} {
		for count := 1; count <= 4; count++ {
			for _, elementBits := range []int{8, 16, 32, 64} {
				for _, lane := range []int{0, 128/elementBits - 1} {
					for _, post := range []arm64RawStructureLanePost{
						arm64RawStructureLaneNoPost,
						arm64RawStructureLaneFixedPost,
						arm64RawStructureLaneRegisterPost,
					} {
						word := encodeARM64RawStructureLane(load, count, elementBits, lane, post, 21, 20, 31)
						fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
					}
				}
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
					"rawStructureLaneArchitectureForms": {Name: "rawStructureLaneArchitectureForms", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []string{"load i", "store i", "insertelement", "extractelement", "add i64"} {
				if !strings.Contains(ll, operation) {
					t.Fatalf("%s omitted %s semantics:\n%s", triple, operation, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-structure-lane.ll", "arm64-raw-structure-lane.o", ll)
		})
	}
}

func TestARM64RawStructureLaneRuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	load4H := encodeARM64RawStructureLane(true, 4, 16, 3, arm64RawStructureLaneNoPost, 0, 0, 8)
	store4HPost := encodeARM64RawStructureLane(false, 4, 16, 3, arm64RawStructureLaneFixedPost, 0, 4, 8)
	load3SPost := encodeARM64RawStructureLane(true, 3, 32, 2, arm64RawStructureLaneRegisterPost, 5, 0, 12)
	source := fmt.Sprintf(`TEXT rawStructureLaneSemantics(SB),$0-32
	MOVD input+0(FP), R0
	MOVD initial+8(FP), R1
	MOVD output+16(FP), R2
	MOVD updates+24(FP), R3
	VLD1.P 64(R1), [V8.B16, V9.B16, V10.B16, V11.B16]
	VLD1.P 48(R1), [V12.B16, V13.B16, V14.B16]
	WORD $%#08x
	VST1 [V8.B16, V9.B16, V10.B16, V11.B16], (R2)
	ADD $64, R2, R4
	WORD $%#08x
	MOVD R4, 0(R3)
	MOVD $12, R5
	WORD $%#08x
	MOVD R0, 8(R3)
	ADD $80, R2, R6
	VST1.P [V12.B16, V13.B16, V14.B16], 48(R6)
	RET
`, load4H, store4HPost, load3SPost)
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ll, err := Translate(file, Options{
		TargetTriple: triple,
		Goarch:       "arm64",
		Sigs: map[string]FuncSig{"rawStructureLaneSemantics": {
			Name: "rawStructureLaneSemantics", Args: []LLVMType{Ptr, Ptr, Ptr, Ptr}, Ret: Void,
			Frame: FrameLayout{Params: []FrameSlot{
				{Offset: 0, Type: Ptr, Index: 0, Field: -1},
				{Offset: 8, Type: Ptr, Index: 1, Field: -1},
				{Offset: 16, Type: Ptr, Index: 2, Field: -1},
				{Offset: 24, Type: Ptr, Index: 3, Field: -1},
			}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	const mainC = `
#include <stdint.h>
#include <string.h>
extern void rawStructureLaneSemantics(const uint8_t *, const uint8_t *, uint8_t *, uintptr_t *);
int main(void) {
  uint8_t input[32], initial[112], output[128] = {0};
  uintptr_t updates[2] = {0};
  for (int i = 0; i < 32; i++) input[i] = (uint8_t)(i * 7u + 3u);
  for (int i = 0; i < 112; i++) initial[i] = (uint8_t)(i * 11u + 5u);
  rawStructureLaneSemantics(input, initial, output, updates);
  for (int reg = 0; reg < 4; reg++) {
    for (int byte = 0; byte < 16; byte++) {
      uint8_t want = initial[reg * 16 + byte];
      if (byte == 6 || byte == 7) want = input[reg * 2 + byte - 6];
      if (output[reg * 16 + byte] != want) return 1 + reg * 16 + byte;
    }
  }
  if (memcmp(output + 64, input, 8) != 0) return 70;
  for (int reg = 0; reg < 3; reg++) {
    for (int byte = 0; byte < 16; byte++) {
      uint8_t want = initial[64 + reg * 16 + byte];
      if (byte >= 8 && byte < 12) want = input[reg * 4 + byte - 8];
      if (output[80 + reg * 16 + byte] != want) return 80 + reg * 16 + byte;
    }
  }
  if (updates[0] != (uintptr_t)(output + 72)) return 201;
  if (updates[1] != (uintptr_t)(input + 12)) return 202;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_structure_lane", triple, ll, mainC, nil)
}
