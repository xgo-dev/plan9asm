package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawPackedMoveLiteral(evex bool, width int) []byte {
	var code []byte
	if evex {
		length := byte(map[int]int{16: 0, 32: 1, 64: 2}[width])
		code = []byte{0x62, 0xf1, 0x7c, length<<5 | 0x08, 0x10, 0x05}
	} else {
		p1 := byte(0x7e)
		if width == 16 {
			p1 = 0x7a
		}
		code = []byte{0xc5, p1, 0x6f, 0x05}
	}
	code = append(code, 1, 0, 0, 0, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*7+3))
	}
	return code
}

func TestDecodeX86RawPackedMoveRIPDataCompleteWidths(t *testing.T) {
	for _, test := range []struct {
		evex  bool
		width int
	}{
		{false, 16}, {false, 32},
		{true, 16}, {true, 32}, {true, 64},
	} {
		name := fmt.Sprintf("evex%t/width%d", test.evex, test.width)
		t.Run(name, func(t *testing.T) {
			code := x86RawPackedMoveLiteral(test.evex, test.width)
			decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
			if err != nil {
				t.Fatal(err)
			}
			if len(decoded) != 2 || !decoded[0].x86RIPLiteral ||
				len(decoded[0].Args) < 2 || decoded[0].Args[0].Kind != OpSym ||
				decoded[1].Op != OpRET {
				t.Fatalf("decoded %x as %#v, want source-local vector constant", code, decoded)
			}
		})
	}
}

func TestTranslateX86RawPackedMoveRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	for index, test := range []struct {
		evex  bool
		width int
	}{
		{false, 16}, {false, 32},
		{true, 16}, {true, 32}, {true, 64},
	} {
		name := fmt.Sprintf("vectorLiteral%d", index)
		code := x86RawPackedMoveLiteral(test.evex, test.width)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != len(sigs) {
		t.Fatalf("materialized %d constants, want %d", len(normalized.Data), len(sigs))
	}
	for index, datum := range normalized.Data {
		width := []int{16, 32, 16, 32, 64}[index]
		code := x86RawPackedMoveLiteral(index >= 2, width)
		want := code[len(code)-width:]
		if datum.Width != int64(width) || !bytes.Equal(datum.Payload, want) {
			t.Fatalf("constant %d = %x width %d, want %x", index, datum.Payload, datum.Width, want)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "vector-literal.ll", "vector-literal.o", ir)
		})
	}
}

func TestDecodeX86RawPackedMoveRIPDataRejectsUnsafeSources(t *testing.T) {
	// The same opcode byte is used by scalar VMOVSS/SD; this packed-move
	// decoder must leave those encodings to the scalar grammar.
	for _, code := range [][]byte{
		{0xc5, 0xfa, 0x10, 0x05, 1, 0, 0, 0},
		{0xc5, 0xfb, 0x10, 0x05, 1, 0, 0, 0},
	} {
		if _, _, _, matched, _ := decodeX86RawPackedMoveRIPData(code, 0, 64); matched {
			t.Fatalf("packed move claimed scalar encoding %x", code)
		}
	}
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "instruction_overlap", edit: func(code []byte) []byte {
			copy(code[6:10], []byte{0xfa, 0xff, 0xff, 0xff})
			return code
		}},
		{name: "missing_pool", edit: func(code []byte) []byte {
			code[6] = 0x7f
			return code
		}},
		{name: "truncated_pool", edit: func(code []byte) []byte {
			code[6] = 2
			return code
		}},
		{name: "segment_override", edit: func(code []byte) []byte {
			return append([]byte{0x64}, code...)
		}},
		{name: "address_override", edit: func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.edit(x86RawPackedMoveLiteral(true, 64))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, test.name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe RIP vector source: %x", code)
			}
		})
	}
}

func TestTranslateX86RawPackedMoveRIPDataRejectsAddressObservedText(t *testing.T) {
	code := x86RawPackedMoveLiteral(true, 64)
	var source strings.Builder
	source.WriteString("TEXT address(SB),$0-0\n\tLEAQ raw+1(SB), AX\n\tRET\n")
	source.WriteString("TEXT raw(SB),$0-0\n\tMOVQ AX, AX\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	_, err = Translate(file, Options{
		Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{
			"address": {Name: "address", Ret: Void},
			"raw":     {Name: "raw", Ret: Void},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "address-observed RIP-relative raw literal") {
		t.Fatalf("address-observed raw TEXT was silently folded: %v", err)
	}
}

func x86RawEVEXPackedIntegerMoveLiteral(pp byte, wide bool, width, mask int, zeroing bool) []byte {
	p1 := byte(0x7c) | pp
	if wide {
		p1 |= 0x80
	}
	p2 := byte(map[int]int{16: 0, 32: 1, 64: 2}[width]<<5 | 0x08 | mask)
	if zeroing {
		p2 |= 0x80
	}
	code := []byte{0x62, 0xf1, p1, p2, 0x6f, 0x05, 1, 0, 0, 0, 0xc3}
	for index := 0; index < width; index++ {
		code = append(code, byte(index*5+1))
	}
	return code
}

func TestDecodeX86RawEVEXPackedIntegerMoveRIPDataCompleteFamily(t *testing.T) {
	for _, form := range []struct {
		pp   byte
		wide bool
		op   Op
	}{
		{1, false, "VMOVDQA32"}, {1, true, "VMOVDQA64"},
		{2, false, "VMOVDQU32"}, {2, true, "VMOVDQU64"},
		{3, false, "VMOVDQU8"}, {3, true, "VMOVDQU16"},
	} {
		for _, width := range []int{16, 32, 64} {
			for _, mask := range []int{0, 3, 7} {
				zeroing := mask == 7
				name := fmt.Sprintf("%s/%d/mask%d", form.op, width, mask)
				t.Run(name, func(t *testing.T) {
					code := x86RawEVEXPackedIntegerMoveLiteral(form.pp, form.wide, width, mask, zeroing)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					op := form.op
					if zeroing {
						op += ".Z"
					}
					if len(decoded) != 2 || decoded[0].Op != op ||
						len(decoded[0].Args) < 2 || decoded[0].Args[0].Kind != OpSym ||
						!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data load", code, decoded, op)
					}
				})
			}
		}
	}
}

func TestTranslateX86RawEVEXPackedIntegerMoveRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	forms := []struct {
		pp   byte
		wide bool
	}{
		{1, false}, {1, true}, {2, false},
		{2, true}, {3, false}, {3, true},
	}
	for index, form := range forms {
		name := fmt.Sprintf("evexIntegerLiteral%d", index)
		code := x86RawEVEXPackedIntegerMoveLiteral(form.pp, form.wide, 64, 7, true)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: triple, Sigs: sigs})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "evex-integer-literal.ll", "evex-integer-literal.o", ir)
		})
	}
}

func TestDecodeX86RawEVEXPackedIntegerMoveRIPDataRejectsUnsafeSource(t *testing.T) {
	for _, displacement := range []byte{0x7f, 2} {
		code := x86RawEVEXPackedIntegerMoveLiteral(2, false, 64, 0, false)
		code[6] = displacement
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "unsafe EVEX integer source", map[string]bool{}); err == nil {
			t.Fatalf("accepted out-of-group EVEX integer source %x", code)
		}
	}
}

func x86RawVBROADCASTI128Literal() []byte {
	code := []byte{0xc4, 0xe2, 0x7d, 0x5a, 0x05, 1, 0, 0, 0, 0xc3}
	for index := 0; index < 16; index++ {
		code = append(code, byte(index*11+2))
	}
	return code
}

func TestDecodeX86RawVBROADCASTI128RIPData(t *testing.T) {
	code := x86RawVBROADCASTI128Literal()
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "VBROADCASTI128 literal", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 2 || decoded[0].Op != "VBROADCASTI128" ||
		len(decoded[0].Args) != 2 || decoded[0].Args[0].Kind != OpSym ||
		!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
		t.Fatalf("decoded %x as %#v, want VBROADCASTI128 source-local data", code, decoded)
	}
}

func TestTranslateX86RawVBROADCASTI128RIPDataObjects(t *testing.T) {
	code := x86RawVBROADCASTI128Literal()
	var source strings.Builder
	source.WriteString("TEXT blockLiteral(SB),$0-0\n")
	for _, value := range code {
		fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
	}
	requireX86GoAssemblerResult(t, "amd64", source.String(), true)
	file, err := Parse(ArchAMD64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	normalized, err := normalizeX86RawFile(file, "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.Data) != 1 || !bytes.Equal(normalized.Data[0].Payload, code[len(code)-16:]) {
		t.Fatalf("VBROADCASTI128 constant = %#v, want the exact source bytes", normalized.Data)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"x86_64-apple-darwin", "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				Goarch: "amd64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"blockLiteral": {Name: "blockLiteral", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "block-literal.ll", "block-literal.o", ir)
		})
	}
}

func TestDecodeX86RawVBROADCASTI128RIPDataRejectsUnsafeSource(t *testing.T) {
	for _, displacement := range []byte{3, 0x7f} {
		code := x86RawVBROADCASTI128Literal()
		code[5] = displacement
		if _, err := decodeX86RawDirectiveGroup(code, 64, 0, "unsafe block broadcast", map[string]bool{}); err == nil {
			t.Fatalf("accepted out-of-group VBROADCASTI128 source %x", code)
		}
	}
}
