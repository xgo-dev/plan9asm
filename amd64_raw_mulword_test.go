package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var x86PackedWordMultiplyGoRows = []struct {
	mapID  byte
	opcode byte
	op     Op
}{
	{1, 0xd5, "VPMULLW"},
	{1, 0xe5, "VPMULHW"},
	{1, 0xe4, "VPMULHUW"},
	{2, 0x0b, "VPMULHRSW"},
}

func encodeX86VEXPackedWordMultiply(mapID, opcode byte, width256, w bool, destination, source1, source2 int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	p0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | int(mapID))
	p1 := byte(((^source1)&15)<<3 | int(l)<<2 | 1)
	if w {
		p1 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0xc4, p0, p1, opcode, modRM}
}

func encodeX86VEX2PackedWordMultiply(opcode byte, width256 bool, destination, source1, source2 int) []byte {
	vectorBit := 0
	if width256 {
		vectorBit = 1
	}
	prefix := byte((1-destination/8)<<7 | (^source1&15)<<3 | vectorBit<<2 | 1)
	modRM := byte(0xc0 | destination&7<<3 | source2&7)
	return []byte{0xc5, prefix, opcode, modRM}
}

func encodeX86EVEXPackedWordMultiply(mapID, opcode byte, vectorBits, mask int, w, zeroing bool, destination, source1, source2 int) []byte {
	p0 := byte((1-destination/8&1)<<7 | (1-source2/16)<<6 | (1-source2/8&1)<<5 | (1-destination/16)<<4 | int(mapID))
	p1 := byte(((^source1)&15)<<3 | 5)
	if w {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | ((^source1>>4)&1)<<3 | mask)
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func TestTranslateRawVPMULHWOldCorpusRegression(t *testing.T) {
	const source = `TEXT rawVPMULHW(SB), $0-0
	LONG $0xe57161c4
	BYTE $0xc6
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawVPMULHW": {Name: "rawVPMULHW", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mul <8 x i32>") || !strings.Contains(ir, "ashr <8 x i32>") {
		t.Fatalf("raw VPMULHW omitted packed word multiply:\n%s", ir)
	}
}

func TestTranslateRawVEX2PackedWordMultiplyGoccRegression(t *testing.T) {
	const source = `TEXT rawVEX2WordMultiply(SB), $0-0
	LONG $0xdbd5cdc5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{
		Goarch:       "amd64",
		TargetTriple: "x86_64-unknown-linux-gnu",
		Sigs:         map[string]FuncSig{"rawVEX2WordMultiply": {Name: "rawVEX2WordMultiply", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mul <16 x i16>") {
		t.Fatalf("raw VEX2 VPMULLW omitted packed multiplication:\n%s", ir)
	}
}

func TestDecodedX86PackedWordMultiplyCompleteGoRows(t *testing.T) {
	if len(x86PackedMultiplyForms) != len(x86PackedWordMultiplyGoRows)+1 {
		t.Fatalf("packed multiply grammar has %d rows, want four word rows plus D/Q", len(x86PackedMultiplyForms))
	}
	for _, row := range x86PackedWordMultiplyGoRows {
		form, ok := x86PackedMultiplyFormFor(row.mapID, row.opcode)
		if !ok || form.vexOp != row.op || form.evexW0Op != row.op || form.evexW1Op != row.op || form.broadcastByte != 0 {
			t.Fatalf("Go word-multiply row %s/%02x is not modeled completely: %+v", row.op, row.opcode, form)
		}
		for _, width256 := range []bool{false, true} {
			prefix := "X"
			if width256 {
				prefix = "Y"
			}
			for _, w := range []bool{false, true} {
				code := encodeX86VEXPackedWordMultiply(row.mapID, row.opcode, width256, w, 8, 1, 6)
				got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 64)
				want := fmt.Sprintf("%s %s6, %s1, %s8", row.op, prefix, prefix, prefix)
				if err != nil || !matched || length != len(code) || got.Raw != want {
					t.Fatalf("VEX %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
				}
			}
			if row.mapID == 1 {
				code := encodeX86VEX2PackedWordMultiply(row.opcode, width256, 8, 1, 6)
				got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 64)
				want := fmt.Sprintf("%s %s6, %s1, %s8", row.op, prefix, prefix, prefix)
				if err != nil || !matched || length != len(code) || got.Raw != want {
					t.Fatalf("VEX2 %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
				}
			}
		}
		for vectorBits, prefix := range []string{"X", "Y", "Z"} {
			for _, w := range []bool{false, true} {
				for _, masked := range []bool{false, true} {
					mask := 0
					if masked {
						mask = 2
					}
					code := encodeX86EVEXPackedWordMultiply(row.mapID, row.opcode, vectorBits, mask, w, masked, 21, 20, 22)
					got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 64)
					wantOp := string(row.op)
					wantArgs := fmt.Sprintf("%s22, %s20, %s21", prefix, prefix, prefix)
					if masked {
						wantOp += ".Z"
						wantArgs = fmt.Sprintf("%s22, %s20, K2, %s21", prefix, prefix, prefix)
					}
					want := wantOp + " " + wantArgs
					if err != nil || !matched || length != len(code) || got.Raw != want {
						t.Fatalf("EVEX %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
					}
				}
			}
		}
	}
}

func TestDecodedX86PackedWordMultiplyMemoryAndRejectedForms(t *testing.T) {
	for _, row := range x86PackedWordMultiplyGoRows {
		if row.mapID == 1 {
			code := encodeX86VEX2PackedWordMultiply(row.opcode, true, 2, 1, 0)
			code[3] = 0x50
			code = append(code, 0x20)
			got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 64)
			want := fmt.Sprintf("%s 32(AX), Y1, Y2", row.op)
			if err != nil || !matched || length != len(code) || got.Raw != want {
				t.Fatalf("VEX2 memory %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
			}
		}
		code := encodeX86EVEXPackedWordMultiply(row.mapID, row.opcode, 2, 0, false, false, 21, 20, 0)
		code[5] = 0x68
		code = append(code, 0x7f)
		got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 64)
		want := fmt.Sprintf("%s 8128(AX), Z20, Z21", row.op)
		if err != nil || !matched || length != len(code) || got.Raw != want {
			t.Fatalf("memory %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
		}
		broadcast := append([]byte(nil), code...)
		broadcast[3] |= 0x10
		if _, _, matched, err := decodedX86PackedMultiplyInstruction(broadcast, 64); !matched || err == nil {
			t.Fatalf("word multiply incorrectly accepted EVEX broadcast %x", broadcast)
		}
		for vectorBits, prefix := range []string{"X", "Y"} {
			code := encodeX86EVEXPackedWordMultiply(row.mapID, row.opcode, vectorBits, 0, false, false, 21, 20, 22)
			got, length, matched, err := decodedX86PackedMultiplyInstruction(code, 32)
			want := fmt.Sprintf("%s %s22, %s20, %s21", row.op, prefix, prefix, prefix)
			if err != nil || !matched || length != len(code) || got.Raw != want {
				t.Fatalf("386 high-register %x = %+v, length=%d matched=%v err=%v; want %s", code, got, length, matched, err, want)
			}
		}
	}
	invalidZeroing := encodeX86EVEXPackedWordMultiply(1, 0xe5, 0, 0, false, true, 0, 1, 2)
	if _, _, matched, err := decodedX86PackedMultiplyInstruction(invalidZeroing, 64); !matched || err == nil {
		t.Fatalf("zero without mask accepted: %x", invalidZeroing)
	}
	invalidLength := encodeX86EVEXPackedWordMultiply(1, 0xe5, 3, 0, false, false, 0, 1, 2)
	if _, _, matched, err := decodedX86PackedMultiplyInstruction(invalidLength, 64); !matched || err == nil {
		t.Fatalf("reserved vector length accepted: %x", invalidLength)
	}
	for _, code := range [][]byte{
		{0xc4, 0xe3, 0x79, 0xe5, 0xc0},
		{0xc4, 0xe1, 0x78, 0xe5, 0xc0},
		{0xc4, 0xe1, 0x79, 0xe6, 0xc0},
	} {
		if got, _, matched, err := decodedX86PackedMultiplyInstruction(code, 64); matched || err != nil {
			t.Fatalf("invalid opcode form %x decoded as %+v, matched=%v err=%v", code, got, matched, err)
		}
	}
}

func TestTranslateRawPackedWordMultiplyLLVM22Targets(t *testing.T) {
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
			source.WriteString("TEXT rawPackedWordMultiply(SB), $0-0\n")
			appendBytes := func(code []byte) {
				for _, value := range code {
					fmt.Fprintf(&source, "\tBYTE $0x%02x\n", value)
				}
			}
			for _, row := range x86PackedWordMultiplyGoRows {
				for _, width256 := range []bool{false, true} {
					appendBytes(encodeX86VEXPackedWordMultiply(row.mapID, row.opcode, width256, false, 2, 1, 0))
					if row.mapID == 1 {
						appendBytes(encodeX86VEX2PackedWordMultiply(row.opcode, width256, 2, 1, 0))
					}
				}
				for vectorBits := 0; vectorBits < 3; vectorBits++ {
					if target.goarch == "386" && vectorBits == 2 {
						continue
					}
					mask := 3
					zeroing := true
					if target.goarch == "386" {
						mask = 0
						zeroing = false
					}
					appendBytes(encodeX86EVEXPackedWordMultiply(row.mapID, row.opcode, vectorBits, mask, false, zeroing, 21, 20, 22))
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
				Sigs:         map[string]FuncSig{"rawPackedWordMultiply": {Name: "rawPackedWordMultiply", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, target.triple, "raw-packed-word-multiply.ll", "raw-packed-word-multiply.o", ir)
		})
	}
}
