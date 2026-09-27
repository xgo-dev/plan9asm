package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawMinMaxLiteral(op string, evex bool, width, mask int, zeroing, broadcast bool) []byte {
	spec := amd64PackedIntegerMinMaxSpecs[op]
	code := encodeRawScalarMove(evex, 1, spec.opcode, 0, 0, 0, mask, zeroing)
	code[1] = code[1]&0xf0 | byte(spec.mapNumber)
	code[2] &^= 0x80
	if spec.laneBits == 64 {
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
		code = append(code, byte(index*13+9))
	}
	return code
}

func TestDecodeX86RawMinMaxRIPDataCompleteFamily(t *testing.T) {
	for _, op := range x86MinMaxTestOps {
		spec := amd64PackedIntegerMinMaxSpecs[op]
		for _, evex := range []bool{false, true} {
			if !evex && spec.laneBits == 64 {
				continue
			}
			widths := []int{16, 32}
			if evex {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				broadcasts := []bool{false}
				if evex && spec.broadcast {
					broadcasts = append(broadcasts, true)
				}
				for _, broadcast := range broadcasts {
					mask, zeroing := 0, false
					if evex {
						mask, zeroing = 7, true
					}
					name := fmt.Sprintf("%s/evex%t/%d/bcst%t", op, evex, width, broadcast)
					t.Run(name, func(t *testing.T) {
						code := x86RawMinMaxLiteral(op, evex, width, mask, zeroing, broadcast)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						want := Op(op)
						if broadcast {
							want += ".BCST"
						}
						if zeroing {
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
}

func TestDecodeX86RawMinMaxRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawMinMaxLiteral("VPMINSD", true, 64, 7, true, true)
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
			return append([]byte{0x64}, code...)
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

func TestTranslateX86RawMinMaxRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, op := range x86MinMaxTestOps {
		spec := amd64PackedIntegerMinMaxSpecs[op]
		evex := spec.laneBits == 64
		width := 32
		if evex {
			width = 64
		}
		broadcast := evex && spec.broadcast
		mask, zeroing := 0, false
		if evex {
			mask, zeroing = 7, true
		}
		code := x86RawMinMaxLiteral(op, evex, width, mask, zeroing, broadcast)
		name := fmt.Sprintf("minMaxLiteral%d", index)
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
			compileLLVMToObject(t, llc, triple, "minmax-literal.ll", "minmax-literal.o", ir)
		})
	}
}
