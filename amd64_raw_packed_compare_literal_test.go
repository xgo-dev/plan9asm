package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawPackedCompareLiteral(op string, evex bool, width int, broadcast bool) []byte {
	spec := amd64PackedIntegerCompareSpecs[Op(op)]
	code := encodeRawScalarMove(evex, 1, spec.opcode, 0, 0, 0, 0, false)
	code[1] = code[1]&0xf0 | byte(spec.mapNumber)
	code[2] &^= 0x80
	if evex && spec.laneBits == 64 {
		code[2] |= 0x80
	}
	if evex {
		code[3] |= byte(map[int]int{16: 0, 32: 1, 64: 2}[width]) << 5
		if broadcast {
			code[3] |= 0x10
		}
	} else if width == 32 {
		code[2] |= 0x04
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = spec.laneBits / 8
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*17+5))
	}
	return code
}

func TestDecodeX86RawPackedCompareRIPDataCompleteFamily(t *testing.T) {
	for _, op := range x86PackedCompareTestOps {
		for _, evex := range []bool{false, true} {
			widths := []int{16, 32}
			if evex {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				broadcasts := []bool{false}
				if evex && amd64PackedIntegerCompareSpecs[Op(op)].laneBits >= 32 {
					broadcasts = append(broadcasts, true)
				}
				for _, broadcast := range broadcasts {
					name := fmt.Sprintf("%s/evex%t/%d/bcst%t", op, evex, width, broadcast)
					t.Run(name, func(t *testing.T) {
						code := x86RawPackedCompareLiteral(op, evex, width, broadcast)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						want := Op(op)
						if broadcast {
							want += ".BCST"
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
}

func TestDecodeX86RawPackedCompareRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawPackedCompareLiteral("VPCMPEQD", true, 64, true)
	for name, mutate := range map[string]func([]byte) []byte{
		"truncated source": func(code []byte) []byte { return code[:len(code)-1] },
		"overlapping instruction": func(code []byte) []byte {
			code[6] = 0
			return code
		},
		"outside directive group": func(code []byte) []byte {
			code[6] = 127
			return code
		},
		"segment override": func(code []byte) []byte {
			return append([]byte{0x65}, code...)
		},
		"address override": func(code []byte) []byte {
			return append([]byte{0x67}, code...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			code := mutate(append([]byte(nil), valid...))
			if _, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{}); err == nil {
				t.Fatalf("accepted unsafe RIP source %x", code)
			}
		})
	}
}

func TestTranslateX86RawPackedCompareRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, op := range x86PackedCompareTestOps {
		spec := amd64PackedIntegerCompareSpecs[Op(op)]
		evex := index%2 == 0
		width := 32
		if evex {
			width = 64
		}
		broadcast := evex && spec.laneBits >= 32
		code := x86RawPackedCompareLiteral(op, evex, width, broadcast)
		name := fmt.Sprintf("packedCompareLiteral%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		dataWidth := width
		if broadcast {
			dataWidth = spec.laneBits / 8
		}
		pools = append(pools, code[len(code)-dataWidth:])
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
			compileLLVMToObject(t, llc, triple, "packed-compare-literal.ll", "packed-compare-literal.o", ir)
		})
	}
}
