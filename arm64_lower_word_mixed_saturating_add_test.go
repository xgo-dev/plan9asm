package plan9asm

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestTranslateARM64RawMixedSaturatingAddCompleteFamily(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT mixedSaturatingAdd(SB),$0-0\n")
	for _, family := range []struct {
		op         Op
		vectorBase uint32
		scalarBase uint32
	}{
		{op: "VSUQADD", vectorBase: 0x0e203800, scalarBase: 0x5e203800},
		{op: "VUSQADD", vectorBase: 0x2e203800, scalarBase: 0x7e203800},
	} {
		for size := 0; size < 4; size++ {
			for _, wide := range []bool{false, true} {
				if size == 3 && !wide {
					continue // There is no one-lane vector D arrangement.
				}
				word := family.vectorBase | uint32(size)<<22 | 5<<5 | 2
				if wide {
					word |= 1 << 30
				}
				assertARM64MixedSaturatingAddWord(t, word, family.op)
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
			word := family.scalarBase | uint32(size)<<22 | 5<<5 | 2
			assertARM64MixedSaturatingAddWord(t, word, family.op)
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
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
				Goarch:       "arm64",
				TargetTriple: triple,
				Sigs: map[string]FuncSig{
					"mixedSaturatingAdd": {Name: "mixedSaturatingAdd", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"@llvm.aarch64.neon.suqadd", "@llvm.aarch64.neon.usqadd"} {
				if !strings.Contains(ir, name) {
					t.Fatalf("missing %s in generated IR:\n%s", name, ir)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-mixed-saturating-add.ll", "arm64-mixed-saturating-add.o", ir)
		})
	}
}

func assertARM64MixedSaturatingAddWord(t *testing.T, word uint32, want Op) {
	t.Helper()
	decoded, err := decodeARM64RawWordInstruction(Instr{
		Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}},
	})
	if err != nil {
		t.Fatalf("decode %#08x: %v", word, err)
	}
	if decoded.Op != want || len(decoded.Args) != 2 {
		t.Fatalf("decode %#08x: %+v, want %s with two registers", word, decoded, want)
	}
}

func TestARM64RawMixedSaturatingAddDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x2ee038a2, // No one-lane D vector form.
		0x6e203ca2, // Adjacent opcode, not USQADD.
		0x4e203ca2, // Adjacent opcode, not SUQADD.
	} {
		if form, ok := decodeARM64RawMixedSaturatingAdd(word); ok {
			t.Fatalf("accepted invalid or adjacent encoding %#08x as %+v", word, form)
		}
	}
}

func TestARM64RawUSQADDReportedGoAV1RuntimeSemantics(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("runtime execution test requires a Darwin arm64 host")
	}
	llc, clang, ok := findLlcAndClang(t)
	if !ok {
		t.Fatal("LLVM 22 llc/clang not found")
	}
	const source = `TEXT rawusqadd(SB),$0-24
	MOVD destination+0(FP), R0
	MOVD source+8(FP), R1
	MOVD out+16(FP), R2
	VLD1 (R0), [V2.B16]
	VLD1 (R1), [V5.B16]
	WORD $0x6e2038a2 // USQADD V2.16B, V5.16B
	VST1 [V2.B16], (R2)
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	triple := testTargetTriple(runtime.GOOS, runtime.GOARCH)
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: triple,
		Sigs: map[string]FuncSig{
			"rawusqadd": {
				Name: "rawusqadd", Args: []LLVMType{Ptr, Ptr, Ptr}, Ret: Void,
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
extern void rawusqadd(const uint8_t *, const int8_t *, uint8_t *);
int main(void) {
  const uint8_t destination[16] = {250, 2, 0, 255};
  const int8_t source[16] = {10, -5, -1, 1};
  uint8_t got[16] = {0};
  const uint8_t want[16] = {255, 0, 0, 255};
  rawusqadd(destination, source, got);
  for (int i = 0; i < 16; i++) if (got[i] != want[i]) return i + 1;
  return 0;
}
`
	compileAndRunRuntimeTestForTarget(t, llc, clang, "arm64_raw_usqadd", triple, ir, mainC, nil)
}
