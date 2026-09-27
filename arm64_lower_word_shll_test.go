package plan9asm

import (
	"strings"
	"testing"
)

func TestTranslateARM64RawSHLLForms(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	const source = `TEXT rawshll(SB),$0-0
	WORD $0x2e213ad5 // SHLL V21.8H, V22.8B, #8
	WORD $0x6e213ad5 // SHLL2 V21.8H, V22.16B, #8
	RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "arm64",
		TargetTriple: arm64LinuxGNUTriple,
		Sigs:         map[string]FuncSig{"rawshll": {Name: "rawshll", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if count := strings.Count(ir, "shl <"); count != 2 {
		t.Fatalf("SHLL lowering emitted %d vector shifts, want 2:\n%s", count, ir)
	}
	compileLLVMToObject(t, llc, arm64LinuxGNUTriple, "arm64-shll.ll", "arm64-shll.o", ir)
}

func TestARM64RawSHLLDecoderForms(t *testing.T) {
	for _, test := range []struct {
		word uint32
		op   string
		src  string
		dst  string
	}{
		{word: 0x2e213ad5, op: "VSHLL", src: "V22.B8", dst: "V21.H8"},
		{word: 0x6e213ad5, op: "VSHLL2", src: "V22.B16", dst: "V21.H8"},
	} {
		decoded, err := decodeARM64RawWordInstruction(Instr{
			Op:   OpWORD,
			Args: []Operand{{Kind: OpImm, Imm: int64(test.word)}},
		})
		if err != nil {
			t.Fatalf("decode %#x: %v", test.word, err)
		}
		if decoded.Op != Op(test.op) || decoded.Args[1].Reg != Reg(test.src) || decoded.Args[2].Reg != Reg(test.dst) {
			t.Fatalf("decode %#x = %#v, want %s %s -> %s", test.word, decoded, test.op, test.src, test.dst)
		}
	}
}
