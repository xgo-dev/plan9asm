package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXPackedShuffle(pp byte, vex3, width256, widthIgnored bool, destination, source int, immediate byte) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	if !vex3 {
		vex1 := byte((1-destination/8)<<7 | 15<<3 | int(l)<<2 | int(pp))
		return []byte{0xc5, vex1, 0x70, modRM, immediate}
	}
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source/8)<<5 | 1)
	vex1 := byte(15<<3 | int(l)<<2 | int(pp))
	if widthIgnored {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, 0x70, modRM, immediate}
}

func TestTranslateRawVEXPackedShuffleWeaviateRegression(t *testing.T) {
	const source = `TEXT rawShuffle(SB), $0-0
	LONG $0xc870f9c5
	BYTE $0x1b
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawShuffle": {Name: "rawShuffle", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "shufflevector <4 x i32>") {
		t.Fatalf("raw VPSHUFD lowering omitted packed shuffle:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-vex-packed-shuffle.ll", "amd64-raw-vex-packed-shuffle.o", ir)
}

func TestDecodedX86PackedShuffleCompleteVEXRegisterFamily(t *testing.T) {
	tests := []struct {
		pp byte
		op Op
	}{
		{pp: 1, op: "VPSHUFD"},
		{pp: 2, op: "VPSHUFHW"},
		{pp: 3, op: "VPSHUFLW"},
	}
	count := 0
	for _, test := range tests {
		for _, vex3 := range []bool{false, true} {
			for _, width256 := range []bool{false, true} {
				prefix := "X"
				if width256 {
					prefix = "Y"
				}
				for _, widthIgnored := range []bool{false, true} {
					if !vex3 && widthIgnored {
						continue
					}
					sourceLimit := 16
					if !vex3 {
						sourceLimit = 8
					}
					for destination := 0; destination < 16; destination++ {
						for source := 0; source < sourceLimit; source++ {
							immediate := byte(destination<<4 | source)
							code := encodeX86VEXPackedShuffle(test.pp, vex3, width256, widthIgnored, destination, source, immediate)
							got, length, ok, err := decodedX86PackedShuffleInstruction(code, 64)
							if err != nil || !ok || length != len(code) {
								t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
							}
							wantArgs := []string{fmt.Sprintf("$%d", immediate), fmt.Sprintf("%s%d", prefix, source), fmt.Sprintf("%s%d", prefix, destination)}
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
	if count != 3840 {
		t.Fatalf("covered %d VEX packed shuffle register encodings, want 3840", count)
	}
}

func TestDecodedX86PackedShuffleCompleteGo127Family(t *testing.T) {
	// Go 1.27 assigns these three instructions the shared _yvpshufd table.
	// The cases cover VEX/EVEX X/Y/Z, WIG, high registers, memory, masks,
	// zeroing, the VPSHUFD-only broadcast, and compressed disp8.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "vex d reported weaviate", code: []byte{0xc5, 0xf9, 0x70, 0xc8, 0x1b}, want: "VPSHUFD $27, X0, X1"},
		{name: "vex hw y WIG memory", code: []byte{0x64, 0xc4, 0x01, 0xfe, 0x70, 0x64, 0x88, 0x20, 0x5a}, want: "VPSHUFHW $90, 32(R8)(R9*4)(FS), Y12"},
		{name: "evex d x high masked", code: []byte{0x62, 0x71, 0x7d, 0x0c, 0x70, 0xca, 0x7e}, want: "VPSHUFD $126, X2, K4, X9"},
		{name: "evex hw x high masked WIG", code: []byte{0x62, 0x41, 0xfe, 0x0a, 0x70, 0xfb, 0x0d}, want: "VPSHUFHW $13, X11, K2, X31"},
		{name: "evex lw y high masked", code: []byte{0x62, 0xe1, 0x7f, 0x2a, 0x70, 0xdf, 0x00}, want: "VPSHUFLW $0, Y7, K2, Y19"},
		{name: "evex d z broadcast zeroing", code: []byte{0x62, 0xf1, 0x7d, 0xdb, 0x70, 0x50, 0x7f, 0x09}, want: "VPSHUFD.BCST.Z $9, 508(AX), K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86PackedShuffleInstruction(test.code, 64)
			if !ok {
				t.Fatal("packed shuffle encoding was not recognized")
			}
			if err != nil {
				t.Fatal(err)
			}
			if length != len(test.code) || instruction.Raw != test.want {
				t.Fatalf("decoded %x as length=%d raw=%q, want length=%d raw=%q", test.code, length, instruction.Raw, len(test.code), test.want)
			}
		})
	}
}

func TestDecodedX86PackedShuffleRejectsInvalidForms(t *testing.T) {
	valid := encodeX86VEXPackedShuffle(1, true, false, false, 0, 0, 1)
	invalidVVVV := append([]byte(nil), valid...)
	invalidVVVV[2] &^= 0x08
	for name, code := range map[string][]byte{
		"truncated":      {0xc5},
		"wrong opcode":   {0xc5, 0xf9, 0x71, 0xc0, 1},
		"wrong map":      {0xc4, 0xe2, 0x79, 0x70, 0xc0, 1},
		"unrelated pp":   {0xc5, 0xf8, 0x70, 0xc0, 1},
		"EVEX D with W1": {0x62, 0xf1, 0xfd, 0x08, 0x70, 0xc0, 1},
	} {
		if instruction, _, matched, decodeErr := decodedX86PackedShuffleInstruction(code, 64); matched || decodeErr != nil {
			t.Fatalf("%s encoding %x decoded as %+v, ok=%v, err=%v", name, code, instruction, matched, decodeErr)
		}
	}
	if _, _, matched, decodeErr := decodedX86PackedShuffleInstruction(invalidVVVV, 64); !matched || decodeErr == nil {
		t.Fatalf("non-reserved VEX.vvvv encoding %x returned ok=%v err=%v", invalidVVVV, matched, decodeErr)
	}
	extended := encodeX86VEXPackedShuffle(1, true, false, false, 8, 8, 1)
	if _, _, matched, decodeErr := decodedX86PackedShuffleInstruction(extended, 32); !matched || decodeErr == nil {
		t.Fatalf("32-bit extended-register form returned ok=%v err=%v", matched, decodeErr)
	}
	invalidBroadcast := []byte{0x62, 0xf1, 0x7e, 0x5b, 0x70, 0x50, 0x7f, 1}
	if _, _, matched, decodeErr := decodedX86PackedShuffleInstruction(invalidBroadcast, 64); !matched || decodeErr == nil {
		t.Fatalf("VPSHUFHW broadcast returned ok=%v err=%v", matched, decodeErr)
	}
}
