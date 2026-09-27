package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawVectorFloatCompareLiteral(pp byte, encoding string, width int, broadcast bool) []byte {
	var code []byte
	switch encoding {
	case "vex2":
		code = encodeX86VEX2VectorFloatCompare(pp, width == 32, 0, 0, 0, 12)
	case "vex3":
		code = encodeX86VEXVectorFloatCompare(pp, width == 32, 0, 0, 0, 12)
	case "evex":
		code = encodeX86EVEXVectorFloatCompare(
			pp, byte(map[int]int{16: 0, 32: 1, 64: 2}[width]),
			broadcast, 1, 1, 0, 0, 12,
		)
	}
	modRMIndex := len(code) - 2
	code[modRMIndex] = 0x05
	immediate := code[len(code)-1]
	code = append(code[:modRMIndex+1], 1, 0, 0, 0, immediate, 0xc3)
	dataWidth := width
	if pp >= 2 || broadcast {
		dataWidth = 4
		if pp == 1 || pp == 3 {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*41+15))
	}
	return code
}

func TestDecodeX86RawVectorFloatCompareRIPDataCompleteFamily(t *testing.T) {
	for pp := byte(0); pp < 4; pp++ {
		for _, encoding := range []string{"vex2", "vex3", "evex"} {
			widths := []int{16, 32}
			if encoding == "evex" {
				widths = append(widths, 64)
			}
			if pp >= 2 {
				widths = []int{16}
			}
			for _, width := range widths {
				broadcasts := []bool{false}
				if encoding == "evex" && pp < 2 {
					broadcasts = append(broadcasts, true)
				}
				for _, broadcast := range broadcasts {
					name := fmt.Sprintf("%s/%s/%d/bcst%t", vectorFloatCompareRawOp(pp), encoding, width, broadcast)
					t.Run(name, func(t *testing.T) {
						code := x86RawVectorFloatCompareLiteral(pp, encoding, width, broadcast)
						decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
						if err != nil {
							t.Fatal(err)
						}
						want := vectorFloatCompareRawOp(pp)
						if broadcast {
							want += ".BCST"
						}
						if len(decoded) != 2 || decoded[0].Op != want ||
							decoded[0].Args[0].Kind != OpImm || decoded[0].Args[0].Imm != 12 ||
							decoded[0].Args[1].Kind != OpSym || !decoded[0].x86RIPLiteral ||
							decoded[1].Op != OpRET {
							t.Fatalf("decoded %x as %#v, want %s source-local data", code, decoded, want)
						}
					})
				}
			}
		}
	}
}

func TestDecodeX86RawVectorFloatCompareRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawVectorFloatCompareLiteral(1, "evex", 64, true)
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
		"EVEX zeroing": func(code []byte) []byte {
			code[3] |= 0x80
			return code
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

func TestTranslateX86RawVectorFloatCompareRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	index := 0
	for pp := byte(0); pp < 4; pp++ {
		for _, encoding := range []string{"vex2", "vex3", "evex"} {
			width := 16
			if pp < 2 {
				width = 32
				if encoding == "evex" {
					width = 64
				}
			}
			broadcast := encoding == "evex" && pp < 2
			code := x86RawVectorFloatCompareLiteral(pp, encoding, width, broadcast)
			name := fmt.Sprintf("vectorCompareLiteral%d", index)
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
			compileLLVMToObject(t, llc, triple, "vector-compare-literal.ll", "vector-compare-literal.o", ir)
		})
	}
}
