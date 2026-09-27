package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type rawMaskVectorMoveSpec struct {
	opcode       byte
	width64      bool
	op           Op
	laneBits     int
	maskToVector bool
}

var rawMaskVectorMoveSpecs = []rawMaskVectorMoveSpec{
	{opcode: 0x28, op: "VPMOVM2B", laneBits: 8, maskToVector: true},
	{opcode: 0x28, width64: true, op: "VPMOVM2W", laneBits: 16, maskToVector: true},
	{opcode: 0x38, op: "VPMOVM2D", laneBits: 32, maskToVector: true},
	{opcode: 0x38, width64: true, op: "VPMOVM2Q", laneBits: 64, maskToVector: true},
	{opcode: 0x29, op: "VPMOVB2M", laneBits: 8},
	{opcode: 0x29, width64: true, op: "VPMOVW2M", laneBits: 16},
	{opcode: 0x39, op: "VPMOVD2M", laneBits: 32},
	{opcode: 0x39, width64: true, op: "VPMOVQ2M", laneBits: 64},
}

func encodeX86EVEXMaskVectorMove(spec rawMaskVectorMoveSpec, vectorBits byte, vector, mask int) []byte {
	p0 := byte(2)
	regField, rmField := vector, mask
	if spec.maskToVector {
		p0 |= byte((1-(vector>>3)&1)<<7 | 1<<6 | 1<<5 | (1-(vector>>4)&1)<<4)
	} else {
		regField, rmField = mask, vector
		p0 |= byte(1<<7 | (1-(vector>>4)&1)<<6 | (1-(vector>>3)&1)<<5 | 1<<4)
	}
	p1 := byte(15<<3 | 1<<2 | 2)
	if spec.width64 {
		p1 |= 0x80
	}
	p2 := byte(vectorBits<<5 | 1<<3)
	modRM := byte(0xc0 | (regField&7)<<3 | rmField&7)
	return []byte{0x62, p0, p1, p2, spec.opcode, modRM}
}

func TestDecodedX86EVEXMaskVectorMoveCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawMaskVectorMoveSpecs {
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			prefix := [...]string{"X", "Y", "Z"}[vectorBits]
			for vector := 0; vector < 32; vector++ {
				for mask := 0; mask < 8; mask++ {
					code := encodeX86EVEXMaskVectorMove(spec, vectorBits, vector, mask)
					got, length, ok, err := decodedX86MaskVectorMoveInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantArgs := []string{fmt.Sprintf("%s%d", prefix, vector), fmt.Sprintf("K%d", mask)}
					if spec.maskToVector {
						wantArgs[0], wantArgs[1] = wantArgs[1], wantArgs[0]
					}
					if got.Op != spec.op || len(got.Args) != 2 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] {
						t.Fatalf("decode %x = %+v, want %s %s", code, got, spec.op, strings.Join(wantArgs, ", "))
					}
					count++
				}
			}
		}
	}
	if count != 6144 {
		t.Fatalf("covered %d EVEX mask/vector move encodings, want 6144", count)
	}
}

func TestDecodedX86EVEXMaskVectorMoveGoAndWeaviateEncodings(t *testing.T) {
	tests := []struct {
		code []byte
		op   Op
		args []string
	}{
		{code: []byte{0x62, 0x72, 0x7e, 0x48, 0x38, 0xc0}, op: "VPMOVM2D", args: []string{"K0", "Z8"}},
		{code: []byte{0x62, 0x62, 0x7e, 0x08, 0x28, 0xd4}, op: "VPMOVM2B", args: []string{"K4", "X26"}},
		{code: []byte{0x62, 0xd2, 0x7e, 0x48, 0x29, 0xc9}, op: "VPMOVB2M", args: []string{"Z9", "K1"}},
		{code: []byte{0x62, 0x92, 0xfe, 0x28, 0x29, 0xe3}, op: "VPMOVW2M", args: []string{"Y27", "K4"}},
	}
	for _, test := range tests {
		got, length, ok, err := decodedX86MaskVectorMoveInstruction(test.code, 64)
		if err != nil || !ok || length != len(test.code) {
			t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", test.code, got, length, ok, err)
		}
		if got.Op != test.op || len(got.Args) != 2 || got.Args[0].String() != test.args[0] || got.Args[1].String() != test.args[1] {
			t.Fatalf("decode %x = %+v, want %s %s", test.code, got, test.op, strings.Join(test.args, ", "))
		}
	}
}

func TestDecodedX86EVEXMaskVectorMoveInvalidForms(t *testing.T) {
	spec := rawMaskVectorMoveSpecs[0]
	base := encodeX86EVEXMaskVectorMove(spec, 0, 0, 0)
	invalid := make([][]byte, 0, 9)
	reservedVVVV := append([]byte(nil), base...)
	reservedVVVV[2] &^= 0x08
	reservedHighV := append([]byte(nil), base...)
	reservedHighV[3] &^= 0x08
	reservedLength := append([]byte(nil), base...)
	reservedLength[3] |= 0x60
	masking := append([]byte(nil), base...)
	masking[3] |= 0x01
	zeroing := append([]byte(nil), base...)
	zeroing[3] |= 0x80
	broadcast := append([]byte(nil), base...)
	broadcast[3] |= 0x10
	memory := append([]byte(nil), base...)
	memory[5] &^= 0xc0
	extendedKSource := append([]byte(nil), base...)
	extendedKSource[1] &^= 0x20
	vectorToMask := encodeX86EVEXMaskVectorMove(rawMaskVectorMoveSpecs[4], 0, 0, 0)
	extendedKDestination := append([]byte(nil), vectorToMask...)
	extendedKDestination[1] &^= 0x80
	invalid = append(invalid, reservedVVVV, reservedHighV, reservedLength, masking, zeroing, broadcast, memory, extendedKSource, extendedKDestination)
	for _, code := range invalid {
		if _, _, ok, err := decodedX86MaskVectorMoveInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}

func TestTranslateRawEVEXMaskToVectorWeaviateBlockRegression(t *testing.T) {
	const source = `TEXT rawMaskToVectorBlock(SB), $0-0
	LONG $0x487e7262; WORD $0xc038
	LONG $0x4875d162; WORD $0xc8fa
	LONG $0x487e7262; WORD $0xc738
	LONG $0x4875d162; WORD $0xc8fa
	LONG $0x487e7262; WORD $0xc138
	LONG $0x486dd162; WORD $0xd0fa
	LONG $0x487e7262; WORD $0xc238
	LONG $0x4865d162; WORD $0xd8fa
	LONG $0x487e7262; WORD $0xc338
	LONG $0x485dd162; WORD $0xe0fa
	LONG $0x487e7262; WORD $0xc438
	LONG $0x4855d162; WORD $0xe8fa
	LONG $0x487e7262; WORD $0xc538
	LONG $0x484dd162; WORD $0xf0fa
	LONG $0x487e7262; WORD $0xc638
	LONG $0x4845d162; WORD $0xf8fa
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawMaskToVectorBlock": {Name: "rawMaskToVectorBlock", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ir, "select i1") < 8*16 {
		t.Fatalf("raw VPMOVM2D block omitted mask expansion:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-mask-to-vector.ll", "amd64-raw-mask-to-vector.o", ir)
}
