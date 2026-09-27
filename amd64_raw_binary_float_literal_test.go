package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawBinaryFloatLiteral(opcode, pp byte, evex bool, width int, broadcast bool) []byte {
	var code []byte
	if evex {
		code = encodeX86EVEXBinaryFloat(opcode, pp, byte(map[int]int{16: 0, 32: 1, 64: 2}[width]), broadcast, true, 7, 0, 0, 0)
	} else {
		code = encodeX86VEXBinaryFloat(opcode, pp, true, width == 32, false, 0, 0, 0)
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if pp >= 2 || broadcast {
		dataWidth = 4
		if pp == 1 || pp == 3 {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*11+17))
	}
	return code
}

func TestDecodeX86RawBinaryFloatRIPDataCompleteFamily(t *testing.T) {
	for _, opcode := range []byte{0x51, 0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f} {
		for pp := byte(0); pp < 4; pp++ {
			if opcode == 0x51 && pp < 2 {
				continue
			}
			for _, evex := range []bool{false, true} {
				widths := []int{16, 32}
				if evex {
					widths = append(widths, 64)
				}
				if pp >= 2 {
					widths = []int{16}
				}
				for _, width := range widths {
					broadcasts := []bool{false}
					if evex && pp < 2 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						stem := map[byte]string{0x51: "VSQRT", 0x58: "VADD", 0x59: "VMUL", 0x5c: "VSUB", 0x5d: "VMIN", 0x5e: "VDIV", 0x5f: "VMAX"}[opcode]
						name := fmt.Sprintf("%s%s/evex%t/%d/bcst%t", stem, []string{"PS", "PD", "SS", "SD"}[pp], evex, width, broadcast)
						t.Run(name, func(t *testing.T) {
							code := x86RawBinaryFloatLiteral(opcode, pp, evex, width, broadcast)
							decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
							if err != nil {
								t.Fatal(err)
							}
							want := Op(stem + []string{"PS", "PD", "SS", "SD"}[pp])
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

func TestDecodeX86RawBinaryFloatRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawBinaryFloatLiteral(0x58, 0, true, 64, true)
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

func TestTranslateX86RawBinaryFloatRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	index := 0
	for _, opcode := range []byte{0x51, 0x58, 0x59, 0x5c, 0x5d, 0x5e, 0x5f} {
		for pp := byte(0); pp < 4; pp++ {
			if opcode == 0x51 && pp < 2 {
				continue
			}
			evex := index%2 == 0
			width := 32
			if evex {
				width = 64
			}
			if pp >= 2 {
				width = 16
			}
			broadcast := evex && pp < 2
			code := x86RawBinaryFloatLiteral(opcode, pp, evex, width, broadcast)
			name := fmt.Sprintf("binaryFloatLiteral%d", index)
			fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
			for _, value := range code {
				fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
			}
			sigs[name] = FuncSig{Name: name, Ret: Void}
			dataWidth := width
			if pp >= 2 || broadcast {
				dataWidth = 4
				if pp == 1 || pp == 3 {
					dataWidth = 8
				}
			}
			pools = append(pools, code[len(code)-dataWidth:])
			index++
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
			compileLLVMToObject(t, llc, triple, "binary-float-literal.ll", "binary-float-literal.o", ir)
		})
	}
}
