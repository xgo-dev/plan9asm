package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawPackedLogicalLiteral(op Op, evex bool, width, mask int, zeroing, broadcast bool) []byte {
	var code []byte
	if evex {
		length := byte(map[int]int{16: 0, 32: 1, 64: 2}[width])
		code = encodeX86RawEVEXPackedLogical(op, length, mask, zeroing, broadcast, 0, 0, 0)
	} else {
		opcode := map[Op]byte{"VPAND": 0xdb, "VPANDN": 0xdf, "VPOR": 0xeb, "VPXOR": 0xef}[op]
		code = encodeX86VEXPackedIntegerLogical(opcode, true, width == 32, false, 0, 0, 0)
	}
	code[len(code)-1] = 0x05 // RIP+disp32 rather than X0.
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = 4
		if strings.HasSuffix(string(op), "Q") {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*9+7))
	}
	return code
}

func TestTranslateX86RawPackedLogicalRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	add := func(name string, code []byte, width int) {
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		pools = append(pools, code[len(code)-width:])
	}
	for index, op := range []Op{"VPAND", "VPANDN", "VPOR", "VPXOR"} {
		add(fmt.Sprintf("vexLogical%d", index), x86RawPackedLogicalLiteral(op, false, 32, 0, false, false), 32)
	}
	for index, op := range []Op{
		"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ",
		"VPORD", "VPORQ", "VPXORD", "VPXORQ",
	} {
		width := 4
		if strings.HasSuffix(string(op), "Q") {
			width = 8
		}
		add(fmt.Sprintf("evexLogical%d", index), x86RawPackedLogicalLiteral(op, true, 64, 7, true, true), width)
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
			compileLLVMToObject(t, llc, triple, "logical-literal.ll", "logical-literal.o", ir)
		})
	}
}

func TestDecodeX86RawPackedLogicalRIPDataRejectsUnsafeSources(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]byte) []byte
	}{
		{name: "outside_pool", edit: func(code []byte) []byte {
			code[6] = 0x7f
			return code
		}},
		{name: "overlapping_instruction", edit: func(code []byte) []byte {
			copy(code[6:10], []byte{0xfa, 0xff, 0xff, 0xff})
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
			code := test.edit(x86RawPackedLogicalLiteral("VPXORD", true, 64, 0, false, false))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, test.name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe packed logical RIP source %x", code)
			}
		})
	}
}

func TestDecodeX86RawPackedLogicalRIPDataCompleteFamily(t *testing.T) {
	for _, op := range []Op{"VPAND", "VPANDN", "VPOR", "VPXOR"} {
		for _, width := range []int{16, 32} {
			name := fmt.Sprintf("%s/%d", op, width)
			t.Run(name, func(t *testing.T) {
				code := x86RawPackedLogicalLiteral(op, false, width, 0, false, false)
				decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
				if err != nil {
					t.Fatal(err)
				}
				if len(decoded) != 2 || decoded[0].Op != op ||
					len(decoded[0].Args) != 3 || decoded[0].Args[0].Kind != OpSym ||
					!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
					t.Fatalf("decoded %x as %#v, want %s literal source", code, decoded, op)
				}
			})
		}
	}
	for _, op := range []Op{
		"VPANDD", "VPANDQ", "VPANDND", "VPANDNQ",
		"VPORD", "VPORQ", "VPXORD", "VPXORQ",
	} {
		for _, width := range []int{16, 32, 64} {
			for _, broadcast := range []bool{false, true} {
				name := fmt.Sprintf("%s/%d/bcst%t", op, width, broadcast)
				t.Run(name, func(t *testing.T) {
					code := x86RawPackedLogicalLiteral(op, true, width, 7, true, broadcast)
					decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
					if err != nil {
						t.Fatal(err)
					}
					want := op
					if broadcast {
						want += ".BCST"
					}
					want += ".Z"
					if len(decoded) != 2 || decoded[0].Op != want ||
						len(decoded[0].Args) != 4 || decoded[0].Args[0].Kind != OpSym ||
						!decoded[0].x86RIPLiteral || decoded[1].Op != OpRET {
						t.Fatalf("decoded %x as %#v, want %s literal source", code, decoded, want)
					}
				})
			}
		}
	}
}
