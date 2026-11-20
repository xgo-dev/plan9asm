package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawMaskShift(opcode byte, w bool, source, destination int, count byte) []byte {
	p1 := byte(0x79)
	if w {
		p1 |= 0x80
	}
	return []byte{0xc4, 0xe3, p1, opcode, byte(0xc0 | destination<<3 | source), count}
}

func TestTranslateRawMaskShiftGorseRegression(t *testing.T) {
	const source = `TEXT rawMaskShift(SB), $0-0
	LONG $0x3179e3c4
	WORD $0x10d1
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawMaskShift": {Name: "rawMaskShift", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "lshr i64") {
		t.Fatalf("raw KSHIFTRD omitted mask shift:\n%s", ir)
	}
}

func TestDecodedX86RawMaskShiftCompleteGoRows(t *testing.T) {
	if len(x86RawMaskShiftOps) != 4 {
		t.Fatal("Go 1.27 KSHIFT opcode family should have four direction/width rows")
	}
	seen := make(map[Op]bool)
	for row, widths := range x86RawMaskShiftOps {
		for width, op := range widths {
			spec, ok := amd64MaskArithmeticSpecs[op]
			if !ok || seen[op] || spec.shift == "" {
				t.Fatalf("KSHIFT row %d/%d = %s, spec %+v", row, width, op, spec)
			}
			seen[op] = true
			for source := 0; source < 8; source++ {
				for destination := 0; destination < 8; destination++ {
					for _, count := range []byte{0, 7, 8, 16, 32, 64, 255} {
						code := encodeX86RawMaskShift(byte(0x30+row), width != 0, source, destination, count)
						got, length, recognized, err := decodedX86RawMaskShiftInstruction(code, 64)
						if err != nil || !recognized || length != len(code) || got.Op != op {
							t.Fatalf("decode %x = %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
						}
						if len(got.Args) != 3 || got.Args[0].Imm != int64(count) ||
							got.Args[1].String() != fmt.Sprintf("K%d", source) ||
							got.Args[2].String() != fmt.Sprintf("K%d", destination) {
							t.Fatalf("decode %x = %+v, want $%d, K%d, K%d", code, got, count, source, destination)
						}
						if _, _, recognized, err := decodedX86RawMaskShiftInstruction(code, 32); !recognized || err != nil {
							t.Fatalf("386 decode %x: recognized=%v err=%v", code, recognized, err)
						}
					}
				}
			}
		}
	}
	if len(seen) != 8 {
		t.Fatalf("covered %d KSHIFT opcodes, want eight", len(seen))
	}
}

func TestDecodedX86RawMaskShiftRejectsInvalidForms(t *testing.T) {
	base := encodeX86RawMaskShift(0x31, false, 1, 2, 16)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"VEX length", []byte{base[0], base[1], base[2] | 4, base[3], base[4], base[5]}},
		{"vvvv", []byte{base[0], base[1], base[2] &^ 8, base[3], base[4], base[5]}},
		{"extended register", []byte{base[0], base[1] &^ 0x20, base[2], base[3], base[4], base[5]}},
		{"memory source", []byte{base[0], base[1], base[2], base[3], base[4] &^ 0xc0, base[5]}},
		{"missing immediate", base[:5]},
		{"missing ModRM", base[:4]},
		{"address override", append([]byte{0x67}, base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawMaskShiftInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted invalid encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
}

func TestTranslateRawMaskShiftLLVM22Targets(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, target := range []struct {
		name   string
		goarch string
		triple string
	}{
		{"darwin-amd64", "amd64", "x86_64-apple-darwin"},
		{"linux-amd64", "amd64", "x86_64-unknown-linux-gnu"},
		{"windows-amd64", "amd64", "x86_64-pc-windows-msvc"},
		{"linux-386", "386", "i386-unknown-linux-gnu"},
		{"windows-386", "386", "i686-pc-windows-msvc"},
	} {
		t.Run(target.name, func(t *testing.T) {
			var source strings.Builder
			source.WriteString("TEXT rawMaskShiftFamily(SB), $0-0\n")
			for row, widths := range x86RawMaskShiftOps {
				for width := range widths {
					for _, count := range []byte{0, 16, 255} {
						code := encodeX86RawMaskShift(byte(0x30+row), width != 0, 1, 2, count)
						for _, value := range code {
							fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
						}
					}
				}
			}
			source.WriteString("\tRET\n")
			file, err := Parse(ArchAMD64, source.String())
			if err != nil {
				t.Fatal(err)
			}
			ir, err := Translate(file, Options{
				Goarch:       target.goarch,
				TargetTriple: target.triple,
				Sigs:         map[string]FuncSig{"rawMaskShiftFamily": {Name: "rawMaskShiftFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-mask-shift.ll", "raw-mask-shift.o", ir)
		})
	}
}
