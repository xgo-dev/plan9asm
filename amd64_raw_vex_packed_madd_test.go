package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXPackedMADD(opcode byte, opcodeMap int, vex3, width256, widthIgnored bool, destination, source1, source2 int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	if !vex3 {
		vex1 := byte((1-destination/8)<<7 | ((^source1)&15)<<3 | int(l)<<2 | 1)
		return []byte{0xc5, vex1, opcode, modRM}
	}
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | opcodeMap)
	vex1 := byte(((^source1)&15)<<3 | int(l)<<2 | 1)
	if widthIgnored {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func TestTranslateRawVEXPackedMADDWeaviateRegression(t *testing.T) {
	const source = `TEXT rawMADD(SB), $0-0
	LONG $0xd4f5edc5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawMADD": {Name: "rawMADD", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "mul <16 x i32>") {
		t.Fatalf("raw VPMADDWD lowering omitted packed multiplication:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-packed-madd.ll", "amd64-raw-vex-packed-madd.o", ir)
}

func TestDecodedX86VEXPackedMADDCompleteRegisterFamily(t *testing.T) {
	tests := []struct {
		opcode    byte
		opcodeMap int
		op        Op
		vex2      bool
	}{
		{opcode: 0xf5, opcodeMap: 1, op: "VPMADDWD", vex2: true},
		{opcode: 0x04, opcodeMap: 2, op: "VPMADDUBSW"},
	}
	count := 0
	for _, test := range tests {
		for _, vex3 := range []bool{false, true} {
			if !vex3 && !test.vex2 {
				continue
			}
			for _, width256 := range []bool{false, true} {
				prefix := "X"
				if width256 {
					prefix = "Y"
				}
				for _, widthIgnored := range []bool{false, true} {
					if !vex3 && widthIgnored {
						continue
					}
					source2Limit := 16
					if !vex3 {
						source2Limit = 8
					}
					for destination := 0; destination < 16; destination++ {
						for source1 := 0; source1 < 16; source1++ {
							for source2 := 0; source2 < source2Limit; source2++ {
								code := encodeX86VEXPackedMADD(test.opcode, test.opcodeMap, vex3, width256, widthIgnored, destination, source1, source2)
								got, length, ok, err := decodedX86VEXPackedMADDInstruction(code, 64)
								if err != nil || !ok || length != len(code) {
									t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
								}
								wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), fmt.Sprintf("%s%d", prefix, destination)}
								if got.Op != test.op || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
									t.Fatalf("decode %x = %+v, want %s %s", code, got, test.op, strings.Join(wantArgs, ", "))
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 36864 {
		t.Fatalf("covered %d VEX packed multiply-add register encodings, want 36864", count)
	}
}

func TestDecodedX86VEXPackedMADDMemoryAndInvalidForms(t *testing.T) {
	code := []byte{0x64, 0xc4, 0x02, 0xe5, 0x04, 0x64, 0x88, 0x20}
	got, length, ok, err := decodedX86VEXPackedMADDInstruction(code, 64)
	wantSource := MemRef{Segment: FS, Base: "R8", Index: "R9", Scale: 4, Off: 32}
	if err != nil || !ok || length != len(code) || got.Op != "VPMADDUBSW" || len(got.Args) != 3 || got.Args[0].Kind != OpMem || got.Args[0].Mem != wantSource || got.Args[1].String() != "Y3" || got.Args[2].String() != "Y12" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}

	valid := encodeX86VEXPackedMADD(0xf5, 1, true, false, false, 0, 0, 0)
	for _, invalid := range [][]byte{
		{0xc5},
		encodeX86VEXPackedMADD(0xf4, 1, true, false, false, 0, 0, 0),
		encodeX86VEXPackedMADD(0x04, 1, true, false, false, 0, 0, 0),
	} {
		if instruction, _, matched, decodeErr := decodedX86VEXPackedMADDInstruction(invalid, 64); matched || decodeErr != nil {
			t.Fatalf("invalid encoding %x decoded as %+v, ok=%v, err=%v", invalid, instruction, matched, decodeErr)
		}
	}
	invalidPP := []byte{valid[0], valid[1], valid[2] &^ 1, valid[3], valid[4]}
	if _, _, matched, decodeErr := decodedX86VEXPackedMADDInstruction(invalidPP, 64); !matched || decodeErr == nil {
		t.Fatalf("invalid pp encoding %x returned ok=%v err=%v", invalidPP, matched, decodeErr)
	}
	extended := encodeX86VEXPackedMADD(0xf5, 1, true, false, false, 8, 8, 8)
	if _, _, matched, decodeErr := decodedX86VEXPackedMADDInstruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
}
