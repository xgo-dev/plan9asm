package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86RawVectorHighLowMove(opcode byte, encoding string, first, second, destination int, wig bool) []byte {
	modRM := byte(0xc0 | (destination&7)<<3 | first&7)
	switch encoding {
	case "VEX2":
		p1 := byte((1-destination/8)<<7 | (^second&15)<<3)
		return []byte{0xc5, p1, opcode, modRM}
	case "VEX3":
		p0 := byte((1-destination/8)<<7 | 1<<6 | (1-first/8)<<5 | 1)
		p1 := byte((^second & 15) << 3)
		if wig {
			p1 |= 0x80
		}
		return []byte{0xc4, p0, p1, opcode, modRM}
	case "EVEX":
		p0 := byte((1-destination/8&1)<<7 | (1-first/16)<<6 |
			(1-first/8&1)<<5 | (1-destination/16)<<4 | 1)
		p1 := byte(4 | (^second&15)<<3)
		p2 := byte((1 - second/16) << 3)
		return []byte{0x62, p0, p1, p2, opcode, modRM}
	default:
		panic("unknown high/low move encoding")
	}
}

func TestTranslateRawVectorHighLowMoveGorseRegression(t *testing.T) {
	const source = `TEXT rawMoveLowToHigh(SB), $0-0
	LONG $0xc016f0c5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawMoveLowToHigh": {Name: "rawMoveLowToHigh", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "shufflevector <2 x i64>") {
		t.Fatalf("raw VMOVLHPS omitted half-lane move:\n%s", ir)
	}
}

func TestDecodedX86RawVectorHighLowMoveGoRowsAndEncodings(t *testing.T) {
	if len(x86RawVectorHighLowMoveOps) != 2 ||
		x86RawVectorHighLowMoveOps[0x12] != "VMOVHLPS" ||
		x86RawVectorHighLowMoveOps[0x16] != "VMOVLHPS" {
		t.Fatal("Go 1.27 _yvmovhlps raw opcode grammar changed")
	}
	for opcode, op := range x86RawVectorHighLowMoveOps {
		for _, test := range []struct {
			encoding            string
			first, second, dest int
			wig                 bool
		}{
			{"VEX2", 1, 2, 3, false},
			{"VEX3", 12, 13, 14, false},
			{"VEX3", 12, 13, 14, true}, // VEX.W is ignored by the hardware.
			{"EVEX", 20, 21, 22, false},
		} {
			code := encodeX86RawVectorHighLowMove(byte(opcode), test.encoding, test.first, test.second, test.dest, test.wig)
			got, length, recognized, err := decodedX86RawVectorHighLowMoveInstruction(code, 64)
			if err != nil || !recognized || length != len(code) || got.Op != op {
				t.Fatalf("decode %x = %+v length=%d recognized=%v err=%v", code, got, length, recognized, err)
			}
			want := []string{
				fmt.Sprintf("X%d", test.first),
				fmt.Sprintf("X%d", test.second),
				fmt.Sprintf("X%d", test.dest),
			}
			if len(got.Args) != len(want) {
				t.Fatalf("decode %x = %+v, want %v", code, got, want)
			}
			for index, operand := range got.Args {
				if operand.String() != want[index] {
					t.Fatalf("decode %x = %+v, want %v", code, got, want)
				}
			}
		}
	}
}

func TestDecodedX86RawVectorHighLowMoveRejectsNonGoForms(t *testing.T) {
	base := encodeX86RawVectorHighLowMove(0x16, "EVEX", 1, 2, 3, false)
	for _, test := range []struct {
		name string
		code []byte
	}{
		{"fixed bit", []byte{base[0], base[1], base[2] &^ 4, base[3], base[4], base[5]}},
		{"EVEX W", []byte{base[0], base[1], base[2] | 0x80, base[3], base[4], base[5]}},
		{"vector length", []byte{base[0], base[1], base[2], base[3] | 0x20, base[4], base[5]}},
		{"mask", []byte{base[0], base[1], base[2], base[3] | 1, base[4], base[5]}},
		{"zero", []byte{base[0], base[1], base[2], base[3] | 0x80, base[4], base[5]}},
		{"broadcast", []byte{base[0], base[1], base[2], base[3] | 0x10, base[4], base[5]}},
		{"missing ModRM", base[:5]},
		{"address override", append([]byte{0x67}, base...)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, _, recognized, err := decodedX86RawVectorHighLowMoveInstruction(test.code, 64); !recognized || err == nil {
				t.Fatalf("accepted invalid encoding %x: recognized=%v err=%v", test.code, recognized, err)
			}
		})
	}
	memory := append([]byte(nil), base...)
	memory[5] = 0x43
	if _, _, recognized, err := decodedX86RawVectorHighLowMoveInstruction(memory, 64); recognized || err != nil {
		t.Fatalf("claimed VMOVHPS memory encoding %x: recognized=%v err=%v", memory, recognized, err)
	}
}

func TestTranslateRawVectorHighLowMoveLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawHighLowMoveFamily(SB), $0-0\n")
			for opcode := range x86RawVectorHighLowMoveOps {
				for _, code := range [][]byte{
					encodeX86RawVectorHighLowMove(byte(opcode), "VEX2", 1, 2, 3, false),
					encodeX86RawVectorHighLowMove(byte(opcode), "VEX3", 4, 5, 6, true),
					encodeX86RawVectorHighLowMove(byte(opcode), "EVEX", 20, 21, 22, false),
				} {
					for _, value := range code {
						fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
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
				Sigs:         map[string]FuncSig{"rawHighLowMoveFamily": {Name: "rawHighLowMoveFamily", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-high-low-move.ll", "raw-high-low-move.o", ir)
		})
	}
}
