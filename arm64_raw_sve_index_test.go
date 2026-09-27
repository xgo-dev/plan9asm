package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestARM64RawSVEIndexCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawindex(SB),$0-0\n")
	for size := uint32(0); size < 4; size++ {
		for form := uint32(0); form < 4; form++ {
			for _, operands := range [][3]uint32{{0, 1, 16}, {15, 16, 31}, {31, 31, 0}} {
				word := uint32(0x04204000) | size<<22 | form<<10 |
					operands[0]<<5 | operands[1]<<16 | operands[2]
				fmt.Fprintf(&source, "WORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("RET\n")
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
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawindex": {Name: "rawindex", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, bits := range []int{8, 16, 32, 64} {
				want := fmt.Sprintf("call <vscale x %d x i%d> @llvm.aarch64.sve.index", 128/bits, bits)
				if got := strings.Count(ir, want); got != 12 {
					t.Fatalf("%d-bit INDEX calls = %d, want 12", bits, got)
				}
			}
			if !strings.Contains(ir, "i32 0, i32 1)") || !strings.Contains(ir, "i8 15, i8 -16)") {
				t.Fatal("INDEX lost immediate order or sign extension")
			}
			compileLLVMToObject(t, llc, triple, "rawindex.ll", "rawindex.o", ir)
		})
	}
}

func TestARM64RawSVEIndexDecoderBoundaries(t *testing.T) {
	for _, test := range []struct {
		word        uint32
		op          Op
		step, start Operand
		dst         Reg
	}{
		{0x04a14010, "ZINDEX", Operand{Kind: OpImm, Imm: 1}, Operand{Kind: OpImm}, "Z16.S"},
		{0x04304483, "ZINDEXW", Operand{Kind: OpImm, Imm: -16}, Operand{Kind: OpReg, Reg: "R4"}, "Z3.B"},
		{0x046649e5, "ZINDEXW", Operand{Kind: OpReg, Reg: "R6"}, Operand{Kind: OpImm, Imm: 15}, "Z5.H"},
		{0x04e94d07, "ZINDEX", Operand{Kind: OpReg, Reg: "R9"}, Operand{Kind: OpReg, Reg: "R8"}, "Z7.D"},
		{0x04bf4ffe, "ZINDEXW", Operand{Kind: OpReg, Reg: ZR}, Operand{Kind: OpReg, Reg: ZR}, "Z30.S"},
	} {
		got, ok := decodeARM64RawSVEIndex(test.word)
		if !ok || got.Op != test.op || len(got.Args) != 3 {
			t.Fatalf("decode %#08x = %+v, %v", test.word, got, ok)
		}
		if !reflect.DeepEqual(got.Args[0], test.step) || !reflect.DeepEqual(got.Args[1], test.start) || got.Args[2].Reg != test.dst {
			t.Errorf("decode %#08x operands = %+v", test.word, got.Args)
		}
	}
	for _, word := range []uint32{0x04205000, 0x04004000, 0x04208000, 0x05204000} {
		if got, ok := decodeARM64RawSVEIndex(word); ok {
			t.Errorf("INDEX accepted adjacent encoding %#08x as %+v", word, got)
		}
	}
}

func TestARM64RawSVEIndexMatchesLLVM22Encoder(t *testing.T) {
	var lines []string
	var want []uint32
	for size, width := range []string{"b", "h", "s", "d"} {
		reg := "w"
		if width == "d" {
			reg = "x"
		}
		lines = append(lines,
			fmt.Sprintf("index z16.%s, #0, #1", width),
			fmt.Sprintf("index z16.%s, %s0, #1", width, reg),
			fmt.Sprintf("index z16.%s, #0, %s1", width, reg),
			fmt.Sprintf("index z16.%s, %s0, %s1", width, reg, reg))
		for form := uint32(0); form < 4; form++ {
			want = append(want, 0x04214010|uint32(size)<<22|form<<10)
		}
	}
	if got := assembleARM64LLVMWords(t, lines, "+sve"); !reflect.DeepEqual(got, want) {
		t.Fatalf("LLVM 22 INDEX encodings = %#v, want %#v", got, want)
	}
}
