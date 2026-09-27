package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXVectorFloatCompare(pp byte, width256 bool, destination, secondSource, firstSource int, immediate byte) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	vex0 := byte((1-(destination>>3)&1)<<7 | 1<<6 | (1-(firstSource>>3)&1)<<5 | 1)
	vex1 := byte((^secondSource&15)<<3 | int(l)<<2 | int(pp))
	modRM := byte(0xc0 | (destination&7)<<3 | firstSource&7)
	return []byte{0xc4, vex0, vex1, 0xc2, modRM, immediate}
}

func encodeX86VEX2VectorFloatCompare(pp byte, width256 bool, destination, secondSource, firstSource int, immediate byte) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	vex1 := byte((1-(destination>>3)&1)<<7 | (^secondSource&15)<<3 | int(l)<<2 | int(pp))
	modRM := byte(0xc0 | (destination&7)<<3 | firstSource&7)
	return []byte{0xc5, vex1, 0xc2, modRM, immediate}
}

func encodeX86EVEXVectorFloatCompare(pp, vectorBits byte, broadcastOrSAE bool, writeMask, destinationMask, secondSource, firstSource int, immediate byte) []byte {
	p0 := byte(1<<7 | (1-(firstSource>>4)&1)<<6 | (1-(firstSource>>3)&1)<<5 | 1<<4 | 1)
	p1 := byte((^secondSource&15)<<3 | 1<<2 | int(pp))
	if pp == 1 || pp == 3 {
		p1 |= 0x80
	}
	p2 := byte(int(vectorBits)<<5 | (^secondSource>>4&1)<<3 | writeMask)
	if broadcastOrSAE {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | (destinationMask&7)<<3 | firstSource&7)
	return []byte{0x62, p0, p1, p2, 0xc2, modRM, immediate}
}

func vectorFloatCompareRawOp(pp byte) Op {
	return [...]Op{"VCMPPS", "VCMPPD", "VCMPSS", "VCMPSD"}[pp]
}

func TestTranslateRawEVEXVectorFloatCompareWeaviateRegression(t *testing.T) {
	const source = `TEXT rawVectorFloatCompare(SB), $0-0
	LONG $0x483cf162; WORD $0x06c2; BYTE $0x0c
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawVectorFloatCompare": {Name: "rawVectorFloatCompare", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "fcmp") {
		t.Fatalf("raw EVEX VCMPPS lowering omitted floating compare:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vector-float-compare.ll", "amd64-raw-vector-float-compare.o", ir)
}

func TestDecodedX86VEXVectorFloatCompareCompleteRegisterFamily(t *testing.T) {
	count := 0
	for pp := byte(0); pp < 4; pp++ {
		widths := []bool{false, true}
		if pp >= 2 {
			widths = []bool{false}
		}
		for _, width256 := range widths {
			prefix := "X"
			if width256 {
				prefix = "Y"
			}
			for destination := 0; destination < 16; destination++ {
				for secondSource := 0; secondSource < 16; secondSource++ {
					for firstSource := 0; firstSource < 16; firstSource++ {
						code := encodeX86VEXVectorFloatCompare(pp, width256, destination, secondSource, firstSource, 0xa5)
						got, length, ok, err := decodedX86VectorFloatCompareInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{"$165", fmt.Sprintf("%s%d", prefix, firstSource), fmt.Sprintf("%s%d", prefix, secondSource), fmt.Sprintf("%s%d", prefix, destination)}
						if got.Op != vectorFloatCompareRawOp(pp) || len(got.Args) != 4 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] || got.Args[3].String() != wantArgs[3] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, vectorFloatCompareRawOp(pp), strings.Join(wantArgs, ", "))
						}
						count++
					}
					for firstSource := 0; firstSource < 8; firstSource++ {
						code := encodeX86VEX2VectorFloatCompare(pp, width256, destination, secondSource, firstSource, 0xa5)
						got, length, ok, err := decodedX86VectorFloatCompareInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{"$165", fmt.Sprintf("%s%d", prefix, firstSource), fmt.Sprintf("%s%d", prefix, secondSource), fmt.Sprintf("%s%d", prefix, destination)}
						if got.Op != vectorFloatCompareRawOp(pp) || len(got.Args) != 4 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] || got.Args[3].String() != wantArgs[3] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, vectorFloatCompareRawOp(pp), strings.Join(wantArgs, ", "))
						}
						count++
					}
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("covered %d VEX vector floating compare encodings, want 36864", count)
	}
}

func TestDecodedX86EVEXVectorFloatCompareCompleteRegisterFamily(t *testing.T) {
	count := 0
	for pp := byte(0); pp < 4; pp++ {
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			prefix := [...]string{"X", "Y", "Z"}[vectorBits]
			if pp >= 2 {
				prefix = "X"
			}
			for destinationMask := 0; destinationMask < 8; destinationMask++ {
				for secondSource := 0; secondSource < 32; secondSource++ {
					for firstSource := 0; firstSource < 32; firstSource++ {
						code := encodeX86EVEXVectorFloatCompare(pp, vectorBits, false, 1, destinationMask, secondSource, firstSource, 0x5a)
						got, length, ok, err := decodedX86VectorFloatCompareInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{"$90", fmt.Sprintf("%s%d", prefix, firstSource), fmt.Sprintf("%s%d", prefix, secondSource), "K1", fmt.Sprintf("K%d", destinationMask)}
						if got.Op != vectorFloatCompareRawOp(pp) || len(got.Args) != 5 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] || got.Args[3].String() != wantArgs[3] || got.Args[4].String() != wantArgs[4] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, vectorFloatCompareRawOp(pp), strings.Join(wantArgs, ", "))
						}
						count++
					}
				}
			}
		}
	}
	if count != 98304 {
		t.Fatalf("covered %d EVEX vector floating compare encodings, want 98304", count)
	}
}

func TestDecodedX86EVEXVectorFloatCompareModifiersMemoryAndInvalid(t *testing.T) {
	tests := []struct {
		name string
		code []byte
		op   Op
		args []string
	}{
		{name: "weaviate memory", code: []byte{0x62, 0xf1, 0x3c, 0x48, 0xc2, 0x06, 0x0c}, op: "VCMPPS", args: []string{"$12", "0(SI)", "Z8", "K0"}},
		{name: "packed broadcast", code: []byte{0x62, 0xf1, 0xfd, 0x59, 0xc2, 0x48, 0x02, 0x7f}, op: "VCMPPD.BCST", args: []string{"$127", "16(AX)", "Z0", "K1", "K1"}},
		{name: "packed sae", code: encodeX86EVEXVectorFloatCompare(0, 2, true, 2, 7, 20, 21, 31), op: "VCMPPS.SAE", args: []string{"$31", "Z21", "Z20", "K2", "K7"}},
		{name: "scalar lig", code: encodeX86EVEXVectorFloatCompare(3, 1, false, 0, 4, 3, 21, 27), op: "VCMPSD", args: []string{"$27", "X21", "X3", "K4"}},
		{name: "scalar sae", code: encodeX86EVEXVectorFloatCompare(2, 3, true, 3, 5, 1, 11, 47), op: "VCMPSS.SAE", args: []string{"$47", "X11", "X1", "K3", "K5"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, length, ok, err := decodedX86VectorFloatCompareInstruction(test.code, 64)
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

	scalarBroadcast := encodeX86EVEXVectorFloatCompare(2, 0, true, 0, 0, 0, 0, 0)
	scalarBroadcast[len(scalarBroadcast)-2] = 0
	invalid := [][]byte{
		encodeX86VEXVectorFloatCompare(2, true, 0, 0, 0, 0),
		encodeX86EVEXVectorFloatCompare(0, 3, false, 0, 0, 0, 0, 0),
		scalarBroadcast,
	}
	for _, code := range invalid {
		if _, _, ok, err := decodedX86VectorFloatCompareInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}
