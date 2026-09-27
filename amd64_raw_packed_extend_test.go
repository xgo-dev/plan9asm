package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type rawPackedExtendTestSpec struct {
	opcode     byte
	op         Op
	inputBits  int
	outputBits int
}

var rawPackedExtendTestSpecs = []rawPackedExtendTestSpec{
	{opcode: 0x20, op: "VPMOVSXBW", inputBits: 8, outputBits: 16},
	{opcode: 0x21, op: "VPMOVSXBD", inputBits: 8, outputBits: 32},
	{opcode: 0x22, op: "VPMOVSXBQ", inputBits: 8, outputBits: 64},
	{opcode: 0x23, op: "VPMOVSXWD", inputBits: 16, outputBits: 32},
	{opcode: 0x24, op: "VPMOVSXWQ", inputBits: 16, outputBits: 64},
	{opcode: 0x25, op: "VPMOVSXDQ", inputBits: 32, outputBits: 64},
	{opcode: 0x30, op: "VPMOVZXBW", inputBits: 8, outputBits: 16},
	{opcode: 0x31, op: "VPMOVZXBD", inputBits: 8, outputBits: 32},
	{opcode: 0x32, op: "VPMOVZXBQ", inputBits: 8, outputBits: 64},
	{opcode: 0x33, op: "VPMOVZXWD", inputBits: 16, outputBits: 32},
	{opcode: 0x34, op: "VPMOVZXWQ", inputBits: 16, outputBits: 64},
	{opcode: 0x35, op: "VPMOVZXDQ", inputBits: 32, outputBits: 64},
}

func encodeX86VEXPackedExtend(opcode byte, width256 bool, destination, source int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source/8)<<5 | 2)
	vex1 := byte(15<<3 | int(l)<<2 | 1)
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func encodeX86EVEXPackedExtend(opcode byte, vectorBits byte, mask int, zeroing bool, destination, source int) []byte {
	p0 := byte((1-destination/8&1)<<7 | (1-source/16)<<6 | (1-source/8&1)<<5 | (1-destination/16)<<4 | 2)
	p1 := byte(0x7d)
	p2 := byte(vectorBits<<5 | 1<<3 | byte(mask))
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func TestTranslateRawEVEXPackedExtendWeaviateRegression(t *testing.T) {
	const source = `TEXT rawPackedExtend(SB), $0-0
	LONG $0x487df262
	WORD $0x2432
	BYTE $0x07
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawPackedExtend": {Name: "rawPackedExtend", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "zext i8") || !strings.Contains(ir, "to i64") {
		t.Fatalf("raw VPMOVZXBQ lowering omitted byte-to-qword zero extension:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-evex-packed-extend.ll", "amd64-raw-evex-packed-extend.o", ir)
}

func TestTranslateRawVEXPackedExtendWeaviateBlockRegression(t *testing.T) {
	lastExtend := []byte{0xc4, 0xe2, 0x7d, 0x31, 0x7e, 0x18}
	if got, length, ok, err := decodedX86PackedExtendInstruction(lastExtend, 64); err != nil || !ok || length != len(lastExtend) || got.Op != "VPMOVZXBD" {
		t.Fatalf("direct decode %x = %+v, length=%d, ok=%v, err=%v", lastExtend, got, length, ok, err)
	}
	const source = `TEXT rawPackedExtendBlock(SB), $0-0
	LONG $0x317de2c4; BYTE $0x26
	LONG $0x317de2c4; WORD $0x086e
	LONG $0xe45bfcc5
	LONG $0xed5bfcc5
	LONG $0x317de2c4; WORD $0x1076
	LONG $0xf65bfcc5
	LONG $0x317de2c4; WORD $0x187e
	LONG $0xff5bfcc5
	LONG $0xb85de2c4; BYTE $0x1f
	LONG $0xb855e2c4; WORD $0x2057
	LONG $0xb84de2c4; WORD $0x404f
	LONG $0xb845e2c4; WORD $0x6047
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawPackedExtendBlock": {Name: "rawPackedExtendBlock", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ir, "zext i8") < 4 || strings.Count(ir, "sitofp <8 x i32>") < 4 {
		t.Fatalf("raw VPMOVZXBD/VCVTDQ2PS block omitted conversions:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-packed-extend-block.ll", "amd64-raw-packed-extend-block.o", ir)
}

func TestDecodedX86PackedExtendCompleteVEXRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawPackedExtendTestSpecs {
		for _, width256 := range []bool{false, true} {
			destinationPrefix := "X"
			if width256 {
				destinationPrefix = "Y"
			}
			for destination := 0; destination < 16; destination++ {
				for source := 0; source < 16; source++ {
					code := encodeX86VEXPackedExtend(spec.opcode, width256, destination, source)
					got, length, ok, err := decodedX86PackedExtendInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantSource := fmt.Sprintf("X%d", source)
					wantDestination := fmt.Sprintf("%s%d", destinationPrefix, destination)
					if got.Op != spec.op || len(got.Args) != 2 || got.Args[0].String() != wantSource || got.Args[1].String() != wantDestination {
						t.Fatalf("decode %x = %+v, want %s %s, %s", code, got, spec.op, wantSource, wantDestination)
					}
					count++
				}
			}
		}
	}
	if count != 6144 {
		t.Fatalf("covered %d VEX packed-extend register encodings, want 6144", count)
	}
}

func TestDecodedX86PackedExtendCompleteEVEXRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawPackedExtendTestSpecs {
		for vectorBits, destinationPrefix := range []string{"X", "Y", "Z"} {
			destinationBytes := 16 << vectorBits
			sourcePrefix := "X"
			if destinationBytes*spec.inputBits/spec.outputBits > 16 {
				sourcePrefix = "Y"
			}
			for _, masking := range []struct {
				mask    int
				zeroing bool
				suffix  string
			}{
				{},
				{mask: 3},
				{mask: 7, zeroing: true, suffix: ".Z"},
			} {
				for destination := 0; destination < 32; destination++ {
					for source := 0; source < 32; source++ {
						code := encodeX86EVEXPackedExtend(spec.opcode, byte(vectorBits), masking.mask, masking.zeroing, destination, source)
						got, length, ok, err := decodedX86PackedExtendInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{fmt.Sprintf("%s%d", sourcePrefix, source)}
						if masking.mask != 0 {
							wantArgs = append(wantArgs, fmt.Sprintf("K%d", masking.mask))
						}
						wantArgs = append(wantArgs, fmt.Sprintf("%s%d", destinationPrefix, destination))
						if got.Op != spec.op+Op(masking.suffix) || len(got.Args) != len(wantArgs) {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, spec.op+Op(masking.suffix), strings.Join(wantArgs, ", "))
						}
						for index := range wantArgs {
							if got.Args[index].String() != wantArgs[index] {
								t.Fatalf("decode %x = %+v, want %s %s", code, got, spec.op+Op(masking.suffix), strings.Join(wantArgs, ", "))
							}
						}
						count++
					}
				}
			}
		}
	}
	if count != 110592 {
		t.Fatalf("covered %d EVEX packed-extend register encodings, want 110592", count)
	}
}

func TestDecodedX86PackedExtendCompressedMemoryAndInvalidForms(t *testing.T) {
	for _, spec := range rawPackedExtendTestSpecs {
		for vectorBits, destinationPrefix := range []string{"X", "Y", "Z"} {
			destinationBytes := 16 << vectorBits
			sourceBytes := destinationBytes * spec.inputBits / spec.outputBits
			code := encodeX86EVEXPackedExtend(spec.opcode, byte(vectorBits), 2, true, 21, 0)
			code[5] = 0x68
			code = append(code, 0x7f)
			got, length, ok, err := decodedX86PackedExtendInstruction(code, 64)
			wantSource := fmt.Sprintf("%d(AX)", sourceBytes*127)
			wantDestination := fmt.Sprintf("%s21", destinationPrefix)
			if err != nil || !ok || length != len(code) || got.Op != spec.op+".Z" || len(got.Args) != 3 || got.Args[0].String() != wantSource || got.Args[1].String() != "K2" || got.Args[2].String() != wantDestination {
				t.Fatalf("decode %x = %+v, length=%d ok=%v err=%v; want %s.Z %s, K2, %s", code, got, length, ok, err, spec.op, wantSource, wantDestination)
			}
		}
	}

	valid := encodeX86VEXPackedExtend(0x32, false, 0, 0)
	invalidVVVV := append([]byte(nil), valid...)
	invalidVVVV[2] &^= 0x08
	for name, code := range map[string][]byte{
		"truncated":        {0xc4, 0xe2},
		"wrong map":        {0xc4, 0xe1, 0x79, 0x32, 0xc0},
		"wrong pp":         {0xc4, 0xe2, 0x78, 0x32, 0xc0},
		"wrong W":          {0xc4, 0xe2, 0xf9, 0x32, 0xc0},
		"unrelated opcode": {0xc4, 0xe2, 0x79, 0x2f, 0xc0},
	} {
		if instruction, _, matched, decodeErr := decodedX86PackedExtendInstruction(code, 64); matched || decodeErr != nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, code, instruction, matched, decodeErr)
		}
	}
	if _, _, matched, decodeErr := decodedX86PackedExtendInstruction(invalidVVVV, 64); !matched || decodeErr == nil {
		t.Fatalf("non-reserved VEX.vvvv encoding %x returned ok=%v err=%v", invalidVVVV, matched, decodeErr)
	}
	invalidBroadcast := encodeX86EVEXPackedExtend(0x32, 2, 1, false, 0, 0)
	invalidBroadcast[3] |= 0x10
	invalidBroadcast[5] = 0x40
	invalidBroadcast = append(invalidBroadcast, 1)
	if _, _, matched, decodeErr := decodedX86PackedExtendInstruction(invalidBroadcast, 64); !matched || decodeErr == nil {
		t.Fatalf("EVEX broadcast returned ok=%v err=%v", matched, decodeErr)
	}
}
