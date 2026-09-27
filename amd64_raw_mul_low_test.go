package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXPackedMultiplyLow(width256 bool, destination, source1, source2 int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	p0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | 2)
	p1 := byte(((^source1)&15)<<3 | int(l)<<2 | 1)
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0xc4, p0, p1, 0x40, modRM}
}

func encodeX86EVEXPackedMultiplyLow(width64 bool, vectorBits byte, mask int, zeroing bool, destination, source1, source2 int) []byte {
	p0 := byte((1-destination/8&1)<<7 | (1-source2/16)<<6 | (1-source2/8&1)<<5 | (1-destination/16)<<4 | 2)
	p1 := byte(((^source1)&15)<<3 | 5)
	if width64 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | byte((^source1>>4)&1)<<3 | byte(mask))
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	return []byte{0x62, p0, p1, p2, 0x40, modRM}
}

func TestTranslateRawEVEXVPMULLDWeaviateRegression(t *testing.T) {
	const source = `TEXT rawVPMULLD(SB), $0-0
	LONG $0x483df262
	WORD $0xe440
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawVPMULLD": {Name: "rawVPMULLD", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mul <16 x i32>") {
		t.Fatalf("raw VPMULLD lowering omitted packed multiply:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-evex-vpmulld.ll", "amd64-raw-evex-vpmulld.o", ir)
}

func TestDecodedX86PackedMultiplyLowCompleteVEXRegisterFamily(t *testing.T) {
	count := 0
	for _, width256 := range []bool{false, true} {
		prefix := "X"
		if width256 {
			prefix = "Y"
		}
		for destination := 0; destination < 16; destination++ {
			for source1 := 0; source1 < 16; source1++ {
				for source2 := 0; source2 < 16; source2++ {
					code := encodeX86VEXPackedMultiplyLow(width256, destination, source1, source2)
					got, length, ok, err := decodedX86PackedMultiplyLowInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), fmt.Sprintf("%s%d", prefix, destination)}
					if got.Op != "VPMULLD" || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
						t.Fatalf("decode %x = %+v, want VPMULLD %s", code, got, strings.Join(wantArgs, ", "))
					}
					count++
				}
			}
		}
	}
	if count != 8192 {
		t.Fatalf("covered %d VEX packed multiply-low register encodings, want 8192", count)
	}
}

func TestDecodedX86PackedMultiplyLowCompleteEVEXRegisterFamily(t *testing.T) {
	count := 0
	for _, width := range []struct {
		width64 bool
		op      Op
	}{
		{op: "VPMULLD"},
		{width64: true, op: "VPMULLQ"},
	} {
		for vectorBits, prefix := range []string{"X", "Y", "Z"} {
			for destination := 0; destination < 32; destination++ {
				for source1 := 0; source1 < 32; source1++ {
					for source2 := 0; source2 < 32; source2++ {
						code := encodeX86EVEXPackedMultiplyLow(width.width64, byte(vectorBits), 1, false, destination, source1, source2)
						got, length, ok, err := decodedX86PackedMultiplyLowInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), "K1", fmt.Sprintf("%s%d", prefix, destination)}
						if got.Op != width.op || len(got.Args) != 4 {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, width.op, strings.Join(wantArgs, ", "))
						}
						for index := range wantArgs {
							if got.Args[index].String() != wantArgs[index] {
								t.Fatalf("decode %x = %+v, want %s %s", code, got, width.op, strings.Join(wantArgs, ", "))
							}
						}
						count++
					}
				}
			}
		}
	}
	if count != 196608 {
		t.Fatalf("covered %d EVEX packed multiply-low register encodings, want 196608", count)
	}
}

func TestDecodedX86PackedMultiplyLowMemoryAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		name       string
		width64    bool
		vectorBits byte
		op         Op
		laneBytes  int
	}{
		{name: "dword", vectorBits: 2, op: "VPMULLD.BCST.Z", laneBytes: 4},
		{name: "qword", width64: true, vectorBits: 2, op: "VPMULLQ.BCST.Z", laneBytes: 8},
	} {
		t.Run(test.name, func(t *testing.T) {
			code := encodeX86EVEXPackedMultiplyLow(test.width64, test.vectorBits, 3, true, 21, 20, 0)
			code[3] |= 0x10
			code[5] = 0x68
			code = append(code, 0x7f)
			got, length, ok, err := decodedX86PackedMultiplyLowInstruction(code, 64)
			wantSource := fmt.Sprintf("%d(AX)", test.laneBytes*127)
			if err != nil || !ok || length != len(code) || got.Op != test.op || len(got.Args) != 4 || got.Args[0].String() != wantSource || got.Args[1].String() != "Z20" || got.Args[2].String() != "K3" || got.Args[3].String() != "Z21" {
				t.Fatalf("decode %x = %+v, length=%d ok=%v err=%v; want %s %s, Z20, K3, Z21", code, got, length, ok, err, test.op, wantSource)
			}
		})
	}

	for name, code := range map[string][]byte{
		"truncated":    {0xc4, 0xe2},
		"wrong map":    {0xc4, 0xe1, 0x79, 0x40, 0xc0},
		"wrong pp":     {0xc4, 0xe2, 0x78, 0x40, 0xc0},
		"VEX qword":    {0xc4, 0xe2, 0xf9, 0x40, 0xc0},
		"wrong opcode": {0xc4, 0xe2, 0x79, 0x41, 0xc0},
	} {
		if instruction, _, matched, decodeErr := decodedX86PackedMultiplyLowInstruction(code, 64); matched || decodeErr != nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, code, instruction, matched, decodeErr)
		}
	}
	invalidBroadcast := encodeX86EVEXPackedMultiplyLow(false, 2, 1, false, 0, 0, 0)
	invalidBroadcast[3] |= 0x10
	if _, _, matched, decodeErr := decodedX86PackedMultiplyLowInstruction(invalidBroadcast, 64); !matched || decodeErr == nil {
		t.Fatalf("register broadcast returned ok=%v err=%v", matched, decodeErr)
	}
	zeroWithoutMask := encodeX86EVEXPackedMultiplyLow(false, 2, 0, true, 0, 0, 0)
	if _, _, matched, decodeErr := decodedX86PackedMultiplyLowInstruction(zeroWithoutMask, 64); !matched || decodeErr == nil {
		t.Fatalf("zero without mask returned ok=%v err=%v", matched, decodeErr)
	}
}
