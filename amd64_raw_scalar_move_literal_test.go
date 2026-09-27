package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawScalarMoveLiteral(double bool, encoding string, mask int, zeroing bool) []byte {
	pp := byte(2)
	width := 4
	if double {
		pp = 3
		width = 8
	}
	var code []byte
	switch encoding {
	case "VEX2":
		code = []byte{0xc5, 0xf8 | pp, 0x10, 0x05}
	case "VEX3":
		code = []byte{0xc4, 0xe1, 0x78 | pp, 0x10, 0x05}
	case "EVEX":
		p1 := byte(0x7c) | pp
		if double {
			p1 |= 0x80
		}
		p2 := byte(0x08 | mask)
		if zeroing {
			p2 |= 0x80
		}
		code = []byte{0x62, 0xf1, p1, p2, 0x10, 0x05}
	}
	code = append(code, 1, 0, 0, 0, 0xc3)
	for index := 0; index < width; index++ {
		code = append(code, byte(index*17+5))
	}
	return code
}

func TestDecodeX86RawScalarMoveRIPDataCompleteLoadForms(t *testing.T) {
	type masking struct {
		mask    int
		zeroing bool
	}
	for _, double := range []bool{false, true} {
		for _, encoding := range []string{"VEX2", "VEX3", "EVEX"} {
			maskings := []masking{{}}
			if encoding == "EVEX" {
				maskings = append(maskings, masking{mask: 3}, masking{mask: 7, zeroing: true})
			}
			for _, masking := range maskings {
				name := fmt.Sprintf("double%t/%s/mask%d/zero%t", double, encoding, masking.mask, masking.zeroing)
				t.Run(name, func(t *testing.T) {
					code := x86RawScalarMoveLiteral(double, encoding, masking.mask, masking.zeroing)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := Op("VMOVSS")
					if double {
						want = "VMOVSD"
					}
					if masking.zeroing {
						want += ".Z"
					}
					if len(decoded) != 2 || decoded[0].Op != want ||
						decoded[0].Args[0].Kind != OpSym || !decoded[0].x86RIPLiteral ||
						decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, want)
					}
				})
			}
		}
	}
}

func TestTranslateX86RawScalarMoveRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for _, double := range []bool{false, true} {
		for _, encoding := range []string{"VEX2", "VEX3", "EVEX"} {
			name := fmt.Sprintf("scalarMoveLiteral%d", len(sigs))
			mask, zeroing := 0, false
			if encoding == "EVEX" {
				mask, zeroing = 7, true
			}
			code := x86RawScalarMoveLiteral(double, encoding, mask, zeroing)
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range code {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			sigs[name] = FuncSig{Name: name, Ret: Void}
			width := 4
			if double {
				width = 8
			}
			pools = append(pools, code[len(code)-width:])
		}
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
	if len(normalized.Data) != len(pools) {
		t.Fatalf("materialized %d constants, want %d", len(normalized.Data), len(pools))
	}
	for index, datum := range normalized.Data {
		if !bytes.Equal(datum.Payload, pools[index]) {
			t.Fatalf("constant %d = %x, want %x", index, datum.Payload, pools[index])
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
			compileLLVMToObject(t, llc, triple, "scalar-move-literal.ll", "scalar-move-literal.o", ir)
		})
	}
}

func TestDecodeX86RawScalarMoveRIPDataRejectsUnsafeSources(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "missing_pool", edit: func(code []byte) []byte {
			code[6] = 0x40
			return code
		}},
		{name: "instruction_overlap", edit: func(code []byte) []byte {
			copy(code[6:10], []byte{0xfa, 0xff, 0xff, 0xff})
			return code
		}},
		{name: "segment_override", edit: func(code []byte) []byte {
			return append([]byte{0x65}, code...)
		}},
		{name: "address_override", edit: func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := test.edit(x86RawScalarMoveLiteral(true, "EVEX", 0, false))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, test.name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe scalar-move source %x", code)
			}
		})
	}
}
