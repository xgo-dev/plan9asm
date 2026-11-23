package plan9asm

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestTranslateARMEndDirective(t *testing.T) {
	const source = "TEXT endDirective(SB),$0-0\n\tRET\n\tEND\n"
	requireARMGoAssemblerResult(t, source, true)
	ll := translateARMForTest(t, source, map[string]FuncSig{
		"example.endDirective": {Name: "example.endDirective", Ret: Void},
	})
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-end.ll", "arm-end.o", ll)
}

func TestTranslateARMEndDirectiveIgnoresTrailingOperandsLikeGo(t *testing.T) {
	const source = "TEXT endWithIgnoredOperand(SB),$0-0\n\tRET\n\tEND R0\n"
	requireARMGoAssemblerResult(t, source, true)
	translateARMForTest(t, source, map[string]FuncSig{
		"example.endWithIgnoredOperand": {Name: "example.endWithIgnoredOperand", Ret: Void},
	})
}

func TestProbeARMContextDependentOfficialDirectives(t *testing.T) {
	cases := []struct {
		name   string
		source string
	}{
		{name: "return-from-exception", source: "RFE"},
		{name: "pc-relative-raw-word", source: "WORD $2863311530"},
		{name: "stateful-raw-word", source: "WORD $1431655765"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			file, err := Parse(ArchARM, "TEXT probe(SB),$0-0\n\t"+test.source+"\n")
			if err != nil {
				t.Fatal(err)
			}
			instruction := file.Funcs[0].Instrs[1]
			err = ProbeInstruction(ArchARM, "arm", instruction)
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatalf("ProbeInstruction(%s) error = %v, want ErrProbeNeedsContext", test.source, err)
			}
			if !strings.Contains(err.Error(), test.source) {
				t.Fatalf("context error %q does not identify %q", err, test.source)
			}
		})
	}
}

func TestARMOfficialBoundRawWordObjects(t *testing.T) {
	const source = `TEXT rawZero(SB),4,$0-8
MOVW value+0(FP),R0
CMP $1,R0
WORD $0
MOVW R0,ret+4(FP)
RET

TEXT rawByte(SB),4,$0-12
MOVW memory+0(FP),R5
ADD $1365,R5
MOVW selector+4(FP),R0
CMP $1,R0
WORD $1431655765
MOVW $0,R1
MOVW.PL R5,R1
MOVW R1,ret+8(FP)
RET
`
	actual := goAssemblerTextBytes(t, source, "linux", "arm")
	requireARMOriginalWord(t, actual, 0)
	requireARMOriginalWord(t, actual, 0x55555555)
	ir := translateARMCompleteForms(t, source, map[string]FuncSig{
		"rawZero": armLocalCallSignature("rawZero"),
		"rawByte": {
			Name: "rawByte", Args: []LLVMType{Ptr, I32}, Ret: I32,
			Frame: FrameLayout{
				Params:  []FrameSlot{{Offset: 0, Type: Ptr, Index: 0, Field: -1}, {Offset: 4, Type: I32, Index: 1, Field: -1}},
				Results: []FrameSlot{{Offset: 8, Type: I32, Index: 0, Field: -1}},
			},
		},
	})
	if !strings.Contains(ir, "define i32 @rawZero(") || !strings.Contains(ir, "define i32 @rawByte(") ||
		!strings.Contains(ir, "load i8") || !strings.Contains(ir, "1365") {
		t.Fatal("original ARM WORD fixture lost a source function or its byte access")
	}
}

func TestARMOfficialRawWordsRetainEncodingAndLayoutBoundaries(t *testing.T) {
	for _, row := range []struct {
		source, diagnostic string
		word               uint32
	}{
		{"WORD $1234", "0x000004d2", 0x000004d2},
		{"WORD $2863311530", "PC-relative", 0xaaaaaaaa},
	} {
		t.Run(row.source, func(t *testing.T) {
			source := "TEXT word(SB),4,$0-8\nMOVW value+0(FP),R0\nMOVW $3,R1\nMOVW $7,R2\nCMP $1,R0\n" +
				row.source + "\nMOVW R0,ret+4(FP)\nRET\n"
			actual := goAssemblerTextBytes(t, source, "linux", "arm")
			offset := requireARMOriginalWord(t, actual, row.word)
			if row.word == 0xaaaaaaaa {
				// BGE uses a signed imm24 scaled by four from the A32 PC.
				displacement := int32(row.word<<8) >> 6
				destination := offset + 8 + int(displacement)
				if destination >= 0 && destination < len(actual) {
					t.Fatalf("raw BGE destination %d unexpectedly belongs to this %d-byte function", destination, len(actual))
				}
			}
			file, err := Parse(ArchARM, source)
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"word": armLocalCallSignature("word")}})
			if ir != "" || err == nil || !strings.Contains(err.Error(), row.diagnostic) {
				t.Fatalf("original raw data was accepted as an executable source instruction: %v", err)
			}
		})
	}
}

func requireARMOriginalWord(t *testing.T, code []byte, word uint32) int {
	t.Helper()
	for offset := 0; offset+4 <= len(code); offset += 4 {
		if binary.LittleEndian.Uint32(code[offset:]) == word {
			return offset
		}
	}
	t.Fatalf("original Go object is missing A32 word %#08x in %x", word, code)
	return -1
}
