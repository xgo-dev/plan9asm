package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawVBROADCASTF128Literal() []byte {
	code := []byte{0xc4, 0xe2, 0x7d, 0x1a, 0x15, 1, 0, 0, 0, 0xc3}
	for index := 0; index < 16; index++ {
		code = append(code, byte(index*11+1))
	}
	return code
}

func TestDecodeX86RawVBROADCASTF128CompleteMemoryFamily(t *testing.T) {
	for _, test := range []struct {
		name   string
		mode   int
		code   []byte
		source MemRef
		dest   Reg
	}{
		{name: "base", mode: 64, code: []byte{0xc4, 0xe2, 0x7d, 0x1a, 0x13}, source: MemRef{Base: BX}, dest: "Y2"},
		{name: "extended base", mode: 64, code: []byte{0xc4, 0xc2, 0x7d, 0x1a, 0x13}, source: MemRef{Base: "R11"}, dest: "Y2"},
		{name: "extended destination", mode: 64, code: []byte{0xc4, 0x62, 0x7d, 0x1a, 0x1b}, source: MemRef{Base: BX}, dest: "Y11"},
		{name: "SIB", mode: 64, code: []byte{0xc4, 0x02, 0x7d, 0x1a, 0x64, 0x88, 0x20}, source: MemRef{Base: "R8", Index: "R9", Scale: 4, Off: 32}, dest: "Y12"},
		{name: "FS", mode: 64, code: []byte{0x64, 0xc4, 0xe2, 0x7d, 0x1a, 0x13}, source: MemRef{Segment: FS, Base: BX}, dest: "Y2"},
		{name: "386 absolute", mode: 32, code: []byte{0xc4, 0xe2, 0x7d, 0x1a, 0x15, 0x78, 0x56, 0x34, 0x12}, source: MemRef{Off: 0x12345678}, dest: "Y2"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86VBROADCAST128Instruction(test.code, test.mode)
			if err != nil || !ok || length != len(test.code) || got.Op != "VBROADCASTF128" ||
				len(got.Args) != 2 || got.Args[0].Kind != OpMem || got.Args[0].Mem != test.source ||
				got.Args[1].Reg != test.dest {
				t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", test.code, got, length, ok, err)
			}
		})
	}
}

func TestDecodeX86RawVBROADCASTF128RIPData(t *testing.T) {
	code := x86RawVBROADCASTF128Literal()
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VBROADCASTF128 literal", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VBROADCASTF128" ||
		decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
		decoded[1].Op != OpRET || !bytes.Equal(decoded[0].x86RIPLiteralData, code[len(code)-16:]) {
		t.Fatalf("decoded %x as %#v", code, decoded)
	}
}

func TestDecodeX86RawVBROADCASTF128RejectsReservedAndUnsafeSources(t *testing.T) {
	for name, code := range map[string][]byte{
		"register source": {0xc4, 0xe2, 0x7d, 0x1a, 0xd1},
		"128-bit vector":  {0xc4, 0xe2, 0x79, 0x1a, 0x13},
		"nonzero vvvv":    {0xc4, 0xe2, 0x75, 0x1a, 0x13},
		"W1":              {0xc4, 0xe2, 0xfd, 0x1a, 0x13},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, ok, err := decodedX86VBROADCAST128Instruction(code, 64); ok && err == nil {
				t.Fatalf("accepted reserved VBROADCASTF128 encoding %x", code)
			}
		})
	}
	for _, displacement := range []byte{0, 127} {
		code := x86RawVBROADCASTF128Literal()
		code[5] = displacement
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "unsafe F128 literal", map[string]bool{}); err == nil {
			t.Fatalf("accepted unsafe literal displacement %#x", displacement)
		}
	}
}

func TestTranslateX86RawVBROADCASTF128Objects(t *testing.T) {
	var source strings.Builder
	for _, value := range x86RawVBROADCASTF128Literal() {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	sourceText := "TEXT rawBroadcastF128(SB),$0-0\n" + source.String()
	requireX86GoAssemblerResult(t, "amd64", sourceText, true)
	file, err := Parse(ArchAMD64, sourceText)
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin",
		"x86_64-unknown-linux-gnu",
		"x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: map[string]FuncSig{
				"rawBroadcastF128": {Name: "rawBroadcastF128", Ret: Void},
			}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "raw-vbroadcastf128.ll", "raw-vbroadcastf128.o", ir)
		})
	}
}
