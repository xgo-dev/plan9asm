package plan9asm

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func encodeX86VINSERT128(opcode, immediate byte, firstSource, secondSource, destination int) []byte {
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-firstSource/8)<<5 | 3)
	vexBits := byte((^secondSource&15)<<3 | 1<<2 | 1)
	modRM := byte(0xc0 | (destination&7)<<3 | firstSource&7)
	return []byte{0xc4, vex0, vexBits, opcode, modRM, immediate}
}

func encodeX86VEXPackedBroadcast(opcode byte, wide bool, source, destination int) []byte {
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source/8)<<5 | 2)
	vexBits := byte(0x79)
	if wide {
		vexBits |= 1 << 2
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	return []byte{0xc4, vex0, vexBits, opcode, modRM}
}

func TestDecodeX86RawDirectiveGroupReportedInfectiousVINSERTI128(t *testing.T) {
	code := []byte{
		0xc4, 0xe3, 0x4d, 0x38, 0xf6, 0x01,
		0xc4, 0xe3, 0x45, 0x38, 0xff, 0x01,
		0xc4, 0x62, 0x7d, 0x78, 0xc5,
	}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "infectious VINSERTI128 sequence", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"VINSERTI128 $1, X6, Y6, Y6",
		"VINSERTI128 $1, X7, Y7, Y7",
		"VPBROADCASTB X5, Y8",
	}
	if len(decoded) != len(want) {
		t.Fatalf("decoded %d instructions as %#v, want %d", len(decoded), decoded, len(want))
	}
	for index := range want {
		if !strings.HasPrefix(decoded[index].Raw, want[index]+" ") {
			t.Fatalf("instruction %d decoded as %q, want %q", index, decoded[index].Raw, want[index])
		}
	}
}

func TestDecodedX86RawVINSERTI128Go127OracleCases(t *testing.T) {
	for _, test := range []struct {
		code []byte
		want string
	}{
		{code: []byte{0xc4, 0xe3, 0x05, 0x38, 0x13, 0x07}, want: "VINSERTI128 $7, 0(BX), Y15, Y2"},
		{code: []byte{0xc4, 0xc3, 0x05, 0x38, 0x13, 0x07}, want: "VINSERTI128 $7, 0(R11), Y15, Y2"},
		{code: []byte{0xc4, 0xe3, 0x05, 0x38, 0xd2, 0x07}, want: "VINSERTI128 $7, X2, Y15, Y2"},
		{code: []byte{0xc4, 0x43, 0x05, 0x38, 0xdb, 0x07}, want: "VINSERTI128 $7, X11, Y15, Y11"},
	} {
		instruction, length, ok, err := decodedX86VINSERT128Instruction(test.code, 64)
		if !ok || err != nil || length != len(test.code) || instruction.Raw != test.want {
			t.Fatalf("decoded %x as (%#v, %d, %v, %v), want %q", test.code, instruction, length, ok, err, test.want)
		}
	}
}

func TestDecodedX86RawVINSERT128CompleteRegisterFamily(t *testing.T) {
	count := 0
	for opcode, wantOp := range map[byte]Op{0x18: "VINSERTF128", 0x38: "VINSERTI128"} {
		for firstSource := 0; firstSource < 16; firstSource++ {
			for secondSource := 0; secondSource < 16; secondSource++ {
				for destination := 0; destination < 16; destination++ {
					immediate := byte(firstSource*16 + destination)
					code := encodeX86VINSERT128(opcode, immediate, firstSource, secondSource, destination)
					got, length, ok, err := decodedX86VINSERT128Instruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantArgs := []string{
						fmt.Sprintf("$%d", immediate),
						fmt.Sprintf("X%d", firstSource),
						fmt.Sprintf("Y%d", secondSource),
						fmt.Sprintf("Y%d", destination),
					}
					if got.Op != wantOp || len(got.Args) != len(wantArgs) {
						t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
					}
					for index := range wantArgs {
						if got.Args[index].String() != wantArgs[index] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
						}
					}
					count++
				}
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d VINSERT128 register encodings, want 8192", count)
	}
}

func TestDecodedX86RawVINSERT128MemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x03, 0x15, 0x38, 0x64, 0x8b, 0x20, 0xff}
	got, length, ok, err := decodedX86VINSERT128Instruction(code, 64)
	wantMemory := MemRef{Segment: FS, Base: "R11", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VINSERTI128" || len(got.Args) != 4 || got.Args[0].Imm != 0xff || got.Args[1].Kind != OpMem || !reflect.DeepEqual(got.Args[1].Mem, wantMemory) || got.Args[2].String() != "Y13" || got.Args[3].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VINSERT128(0x38, 1, 0, 0, 0)
	for _, invalid := range [][]byte{
		{0xc4},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4], valid[5]},
		encodeX86VINSERT128(0x39, 1, 0, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VINSERT128Instruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"wrong pp":         func(code []byte) { code[2] &^= 1 },
		"VEX.W":            func(code []byte) { code[2] |= 0x80 },
		"VEX.128":          func(code []byte) { code[2] &^= 4 },
		"address override": func(code []byte) { copy(code[1:], code); code[0] = 0x67 },
	} {
		code := append([]byte(nil), valid...)
		if name == "address override" {
			code = append(code, 0)
		}
		mutate(code)
		if _, _, matched, decodeErr := decodedX86VINSERT128Instruction(code, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x returned ok=%v err=%v", name, code, matched, decodeErr)
		}
	}
	truncatedImmediate := valid[:len(valid)-1]
	if _, _, matched, decodeErr := decodedX86VINSERT128Instruction(truncatedImmediate, 64); !matched || decodeErr == nil {
		t.Fatalf("truncated immediate returned ok=%v err=%v", matched, decodeErr)
	}
	if _, _, matched, decodeErr := decodedX86VINSERT128Instruction(valid, 32); !matched || decodeErr == nil {
		t.Fatalf("386 VINSERT128 returned ok=%v err=%v", matched, decodeErr)
	}
}

func TestDecodedX86RawVEXPackedBroadcastCompleteRegisterFamily(t *testing.T) {
	operations := map[byte]Op{
		0x78: "VPBROADCASTB",
		0x79: "VPBROADCASTW",
		0x58: "VPBROADCASTD",
		0x59: "VPBROADCASTQ",
	}
	count := 0
	for opcode, wantOp := range operations {
		for _, wide := range []bool{false, true} {
			for source := 0; source < 16; source++ {
				for destination := 0; destination < 16; destination++ {
					code := encodeX86VEXPackedBroadcast(opcode, wide, source, destination)
					got, length, ok, err := decodedX86VEXPackedBroadcastInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					prefix := "X"
					if wide {
						prefix = "Y"
					}
					wantArgs := []string{fmt.Sprintf("X%d", source), fmt.Sprintf("%s%d", prefix, destination)}
					if got.Op != wantOp || len(got.Args) != 2 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] {
						t.Fatalf("decode %x = %+v, want %s %s", code, got, wantOp, strings.Join(wantArgs, ", "))
					}
					count++
				}
			}
		}
	}
	if count != 2048 {
		t.Fatalf("covered %d VEX packed-broadcast register encodings, want 2048", count)
	}
}

func TestDecodedX86RawVEXPackedBroadcastMemoryAndInvalidForms(t *testing.T) {
	for opcode, wantOp := range map[byte]Op{0x78: "VPBROADCASTB", 0x79: "VPBROADCASTW", 0x58: "VPBROADCASTD", 0x59: "VPBROADCASTQ"} {
		code := []byte{0x65, 0xc4, 0x02, 0x7d, opcode, 0x64, 0x8b, 0x20}
		got, length, ok, err := decodedX86VEXPackedBroadcastInstruction(code, 64)
		wantMemory := MemRef{Segment: GS, Base: "R11", Index: "R9", Scale: 4, Off: 32}
		if err != nil || !ok || length != len(code) || got.Op != wantOp || len(got.Args) != 2 || got.Args[0].Kind != OpMem || !reflect.DeepEqual(got.Args[0].Mem, wantMemory) || got.Args[1].String() != "Y12" {
			t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
		}
	}

	valid := encodeX86VEXPackedBroadcast(0x78, true, 0, 0)
	for _, invalid := range [][]byte{
		{0xc4},
		{valid[0], valid[1] ^ 1, valid[2], valid[3], valid[4]},
		encodeX86VEXPackedBroadcast(0x77, true, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"wrong pp":  func(code []byte) { code[2] &^= 1 },
		"VEX.W":     func(code []byte) { code[2] |= 0x80 },
		"used vvvv": func(code []byte) { code[2] &^= 0x08 },
	} {
		code := append([]byte(nil), valid...)
		mutate(code)
		if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(code, 64); !matched || decodeErr == nil {
			t.Fatalf("%s encoding %x returned ok=%v err=%v", name, code, matched, decodeErr)
		}
	}
	ripRelative := []byte{0xc4, 0xe2, 0x7d, 0x78, 0x05, 0, 0, 0, 0}
	if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(ripRelative, 64); !matched || decodeErr == nil {
		t.Fatalf("RIP-relative encoding returned ok=%v err=%v", matched, decodeErr)
	}
	extended := encodeX86VEXPackedBroadcast(0x78, true, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("386 extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
	valid386 := encodeX86VEXPackedBroadcast(0x78, true, 7, 7)
	got, length, matched, decodeErr := decodedX86VEXPackedBroadcastInstruction(valid386, 32)
	if decodeErr != nil || !matched || length != len(valid386) || got.Raw != "VPBROADCASTB X7, Y7" {
		t.Fatalf("386 base-register form decoded as %+v, length=%d ok=%v err=%v", got, length, matched, decodeErr)
	}
}
