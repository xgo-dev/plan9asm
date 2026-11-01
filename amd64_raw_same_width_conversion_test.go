package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type rawSameWidthConversionSpec struct {
	opcode    byte
	pp        byte
	evexW     bool
	op        Op
	laneBytes int
	sae       bool
}

var rawSameWidthConversionSpecs = []rawSameWidthConversionSpec{
	{opcode: 0x5b, pp: 0, op: "VCVTDQ2PS", laneBytes: 4},
	{opcode: 0x5b, pp: 1, op: "VCVTPS2DQ", laneBytes: 4},
	{opcode: 0x5b, pp: 2, op: "VCVTTPS2DQ", laneBytes: 4, sae: true},
	{opcode: 0x51, pp: 1, evexW: true, op: "VSQRTPD", laneBytes: 8},
	{opcode: 0x51, pp: 0, op: "VSQRTPS", laneBytes: 4},
}

func encodeX86VEXSameWidthConversion(spec rawSameWidthConversionSpec, vex3, width256 bool, destination, source int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	if !vex3 {
		vex1 := byte((1-(destination>>3)&1)<<7 | 15<<3 | int(l)<<2 | int(spec.pp))
		return []byte{0xc5, vex1, spec.opcode, modRM}
	}
	vex0 := byte((1-(destination>>3)&1)<<7 | 1<<6 | (1-(source>>3)&1)<<5 | 1)
	vex1 := byte(15<<3 | int(l)<<2 | int(spec.pp))
	return []byte{0xc4, vex0, vex1, spec.opcode, modRM}
}

func encodeX86EVEXSameWidthConversion(spec rawSameWidthConversionSpec, vectorBits byte, broadcastOrControl, zeroing bool, mask, destination, source int) []byte {
	p0 := byte((1-(destination>>3)&1)<<7 | (1-(source>>4)&1)<<6 | (1-(source>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 1)
	p1 := byte(15<<3 | 1<<2 | int(spec.pp))
	if spec.evexW {
		p1 |= 0x80
	}
	p2 := byte(int(vectorBits)<<5 | 1<<3 | mask)
	if broadcastOrControl {
		p2 |= 0x10
	}
	if zeroing {
		p2 |= 0x80
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	return []byte{0x62, p0, p1, p2, spec.opcode, modRM}
}

func TestDecodedX86VEXSameWidthConversionCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawSameWidthConversionSpecs {
		for _, vex3 := range []bool{false, true} {
			for _, width256 := range []bool{false, true} {
				prefix := "X"
				if width256 {
					prefix = "Y"
				}
				sourceLimit := 16
				if !vex3 {
					sourceLimit = 8
				}
				for destination := 0; destination < 16; destination++ {
					for source := 0; source < sourceLimit; source++ {
						code := encodeX86VEXSameWidthConversion(spec, vex3, width256, destination, source)
						got, length, ok, err := decodedX86SameWidthConversionInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{fmt.Sprintf("%s%d", prefix, source), fmt.Sprintf("%s%d", prefix, destination)}
						if got.Op != spec.op || len(got.Args) != 2 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, spec.op, strings.Join(wantArgs, ", "))
						}
						count++
					}
				}
			}
		}
	}
	if count != 3840 {
		t.Fatalf("covered %d VEX same-width conversion encodings, want 3840", count)
	}
}

func TestDecodedX86EVEXSameWidthConversionCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, spec := range rawSameWidthConversionSpecs {
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			prefix := [...]string{"X", "Y", "Z"}[vectorBits]
			for destination := 0; destination < 32; destination++ {
				for source := 0; source < 32; source++ {
					code := encodeX86EVEXSameWidthConversion(spec, vectorBits, false, false, 1, destination, source)
					got, length, ok, err := decodedX86SameWidthConversionInstruction(code, 64)
					if err != nil || !ok || length != len(code) {
						t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
					}
					wantArgs := []string{fmt.Sprintf("%s%d", prefix, source), "K1", fmt.Sprintf("%s%d", prefix, destination)}
					if got.Op != spec.op || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
						t.Fatalf("decode %x = %+v, want %s %s", code, got, spec.op, strings.Join(wantArgs, ", "))
					}
					count++
				}
			}
		}
	}
	if count != 15360 {
		t.Fatalf("covered %d EVEX same-width conversion encodings, want 15360", count)
	}
}

func TestDecodedX86EVEXSameWidthConversionModifiersMemoryAndInvalid(t *testing.T) {
	find := func(op Op) rawSameWidthConversionSpec {
		t.Helper()
		for _, spec := range rawSameWidthConversionSpecs {
			if spec.op == op {
				return spec
			}
		}
		t.Fatalf("missing raw same-width spec %s", op)
		return rawSameWidthConversionSpec{}
	}
	convert := find("VCVTDQ2PS")
	truncate := find("VCVTTPS2DQ")
	sqrt := find("VSQRTPD")
	tests := []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{name: "vex weaviate", code: []byte{0xc5, 0xfc, 0x5b, 0xe4}, op: "VCVTDQ2PS", args: []string{"Y4", "Y4"}},
		{name: "broadcast zeroing", code: []byte{0x62, 0xf1, 0x7c, 0xdb, 0x5b, 0x50, 0x7f}, op: "VCVTDQ2PS.BCST.Z", args: []string{"508(AX)", "K3", "Z2"}},
		{name: "round up", code: encodeX86EVEXSameWidthConversion(convert, 2, true, false, 2, 4, 5), op: "VCVTDQ2PS.RU_SAE", args: []string{"Z5", "K2", "Z4"}},
		{name: "truncate sae zeroing", code: encodeX86EVEXSameWidthConversion(truncate, 0, true, true, 3, 6, 7), op: "VCVTTPS2DQ.SAE.Z", args: []string{"Z7", "K3", "Z6"}},
		{name: "sqrt round zero", code: encodeX86EVEXSameWidthConversion(sqrt, 3, true, false, 0, 8, 9), op: "VSQRTPD.RZ_SAE", args: []string{"Z9", "Z8"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86SameWidthConversionInstruction(test.code, 64)
			if err != nil || !ok || length != len(test.code) {
				t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", test.code, got, length, ok, err)
			}
			if got.Op != test.op || len(got.Args) != len(test.args) {
				t.Fatalf("decode %x = %+v, want %s %s", test.code, got, test.op, strings.Join(test.args, ", "))
			}
			for index := range test.args {
				if got.Args[index].String() != test.args[index] {
					t.Fatalf("decode %x = %+v, want %s %s", test.code, got, test.op, strings.Join(test.args, ", "))
				}
			}
		})
	}

	zeroWithoutMask := encodeX86EVEXSameWidthConversion(convert, 0, false, true, 0, 0, 0)
	reservedLength := encodeX86EVEXSameWidthConversion(convert, 3, false, false, 0, 0, 0)
	wrongW := encodeX86EVEXSameWidthConversion(convert, 0, false, false, 0, 0, 0)
	wrongW[2] |= 0x80
	for _, code := range [][]byte{zeroWithoutMask, reservedLength, wrongW} {
		if _, _, ok, err := decodedX86SameWidthConversionInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}
