package plan9asm

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func x86RawPackedMultiplyLiteral(form x86PackedMultiplyForm, encoding string, width int, w, broadcast bool) []byte {
	var code []byte
	switch encoding {
	case "vex2":
		code = encodeX86VEX2PackedWordMultiply(form.opcode, width == 32, 0, 0, 0)
	case "vex3":
		code = encodeX86VEXPackedWordMultiply(form.mapID, form.opcode, width == 32, w, 0, 0, 0)
	case "evex":
		code = encodeX86EVEXPackedWordMultiply(
			form.mapID, form.opcode, map[int]int{16: 0, 32: 1, 64: 2}[width],
			7, w, true, 0, 0, 0,
		)
		if broadcast {
			code[3] |= 0x10
		}
	}
	code[len(code)-1] = 0x05
	code = append(code, 1, 0, 0, 0, 0xc3)
	dataWidth := width
	if broadcast {
		dataWidth = form.broadcastByte
		if w {
			dataWidth = 8
		}
	}
	for index := 0; index < dataWidth; index++ {
		code = append(code, byte(index*43+19))
	}
	return code
}

func TestDecodeX86RawPackedMultiplyRIPDataCompleteFamily(t *testing.T) {
	for _, form := range x86PackedMultiplyForms {
		encodings := []string{"vex3", "evex"}
		if form.mapID == 1 {
			encodings = append(encodings, "vex2")
		}
		for _, encoding := range encodings {
			widths := []int{16, 32}
			if encoding == "evex" {
				widths = append(widths, 64)
			}
			for _, width := range widths {
				wBits := []bool{false, true}
				if encoding == "vex2" || encoding == "vex3" && form.opcode == 0x40 {
					wBits = []bool{false}
				}
				for _, w := range wBits {
					broadcasts := []bool{false}
					if encoding == "evex" && form.broadcastByte != 0 {
						broadcasts = append(broadcasts, true)
					}
					for _, broadcast := range broadcasts {
						name := fmt.Sprintf("%x/%x/%s/%d/w%t/bcst%t", form.mapID, form.opcode, encoding, width, w, broadcast)
						t.Run(name, func(t *testing.T) {
							code := x86RawPackedMultiplyLiteral(form, encoding, width, w, broadcast)
							decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, name, map[string]bool{})
							if err != nil {
								t.Fatal(err)
							}
							want := form.vexOp
							if encoding == "evex" {
								want = form.evexW0Op
								if w {
									want = form.evexW1Op
								}
								if broadcast {
									want += ".BCST"
								}
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

func TestDecodeX86RawPackedMultiplyRIPDataRejectsUnsafeSources(t *testing.T) {
	valid := x86RawPackedMultiplyLiteral(x86PackedMultiplyForms[4], "evex", 64, true, true)
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

func TestTranslateX86RawPackedMultiplyRIPDataObjects(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var pools [][]byte
	for index, form := range x86PackedMultiplyForms {
		encoding := "vex3"
		width, w, broadcast := 32, false, false
		if index%2 == 0 {
			encoding, width = "evex", 64
			broadcast = form.broadcastByte != 0
		}
		code := x86RawPackedMultiplyLiteral(form, encoding, width, w, broadcast)
		name := fmt.Sprintf("packedMultiplyLiteral%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),$0-0\n", name)
		for _, value := range code {
			fmt.Fprintf(&source, "\tBYTE $%#02x\n", value)
		}
		sigs[name] = FuncSig{Name: name, Ret: Void}
		dataWidth := width
		if broadcast {
			dataWidth = form.broadcastByte
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
			compileLLVMToObject(t, llc, triple, "packed-multiply-literal.ll", "packed-multiply-literal.o", ir)
		})
	}
}
