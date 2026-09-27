package plan9asm

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
	"testing"
)

func x86FMA3Opcodes() []byte {
	opcodes := make([]byte, 0, len(decodedX86VEXFMA3Ops))
	for opcode := range decodedX86VEXFMA3Ops {
		opcodes = append(opcodes, opcode)
	}
	sort.Slice(opcodes, func(i, j int) bool { return opcodes[i] < opcodes[j] })
	return opcodes
}

func x86RawFMA3Literal(opcode byte, width64, evex bool, width int, broadcast bool) []byte {
	spec := decodedX86VEXFMA3Ops[opcode]
	var code []byte
	if evex {
		code = encodeX86EVEXFMA3(opcode, width64, byte(map[int]int{16: 0, 32: 1, 64: 2}[width]), broadcast, true, 7, 0, 0, 0)
	} else {
		code = encodeX86VEXFMA3(opcode, width64, width == 32, 0, 0, 0)
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if spec.scalar || broadcast {
		dataWidth = 4
		if width64 {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*31+13))
	}
	return code
}

func TestDecodeX86RawFMA3RIPDataCompleteFamily(t *testing.T) {
	for _, opcode := range x86FMA3Opcodes() {
		spec := decodedX86VEXFMA3Ops[opcode]
		for _, width64 := range []bool{false, true} {
			for _, evex := range []bool{false, true} {
				widths := []int{16, 32}
				if evex {
					widths = append(widths, 64)
				}
				if spec.scalar {
					widths = []int{16}
				}
				for _, width := range widths {
					broadcasts := []bool{false}
					if evex && !spec.scalar {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						name := fmt.Sprintf("%s/evex%t/%d/bcst%t", spec.op(width64), evex, width, broadcast)
						t.Run(name, func(t *testing.T) {
							code := x86RawFMA3Literal(opcode, width64, evex, width, broadcast)
							decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
							if err != nil {
								t.Fatal(err)
							}
							want := spec.op(width64)
							if broadcast {
								want += ".BCST"
							}
							if evex {
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
}

func TestDecodeX86RawFMA3RIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawFMA3Literal(0xb8, false, true, 64, true)
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

func TestTranslateX86RawFMA3RIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, opcode := range x86FMA3Opcodes() {
		spec := decodedX86VEXFMA3Ops[opcode]
		width64 := index%2 == 0
		evex := index%3 == 0
		width := 32
		if spec.scalar {
			width = 16
		} else if evex {
			width = 64
		}
		broadcast := evex && !spec.scalar
		code := x86RawFMA3Literal(opcode, width64, evex, width, broadcast)
		name := fmt.Sprintf("fma3Literal%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		dataWidth := width
		if spec.scalar || broadcast {
			dataWidth = 4
			if width64 {
				dataWidth = 8
			}
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
			compileLLVMToObject(t, llc, triple, "fma3-literal.ll", "fma3-literal.o", ir)
		})
	}
}
