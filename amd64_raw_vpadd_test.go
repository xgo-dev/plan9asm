package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXPackedIntegerArithmetic(opcode byte, vex3, width256, widthIgnored bool, destination, source1, source2 int) []byte {
	l := byte(0)
	if width256 {
		l = 1
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
	if !vex3 {
		vex1 := byte((1-destination/8)<<7 | ((^source1)&15)<<3 | int(l)<<2 | 1)
		return []byte{0xc5, vex1, opcode, modRM}
	}
	vex0 := byte((1-destination/8)<<7 | 1<<6 | (1-source2/8)<<5 | 1)
	vex1 := byte(((^source1)&15)<<3 | int(l)<<2 | 1)
	if widthIgnored {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, opcode, modRM}
}

func TestDecodedX86PackedIntegerAddCompleteVEXRegisterFamily(t *testing.T) {
	count := 0
	for opcode, properties := range decodedX86PackedIntegerArithmeticOps {
		if !strings.HasPrefix(string(properties.op), "VPADD") {
			continue
		}
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
					source2Limit := 16
					if !vex3 {
						source2Limit = 8
					}
					for destination := 0; destination < 16; destination++ {
						for source1 := 0; source1 < 16; source1++ {
							for source2 := 0; source2 < source2Limit; source2++ {
								code := encodeX86VEXPackedIntegerArithmetic(opcode, vex3, width256, widthIgnored, destination, source1, source2)
								got, length, ok, err := decodedX86PackedIntegerArithmeticInstruction(code, 64)
								if err != nil || !ok || length != len(code) {
									t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
								}
								wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), fmt.Sprintf("%s%d", prefix, destination)}
								if got.Op != properties.op || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
									t.Fatalf("decode %x = %+v, want %s %s", code, got, properties.op, strings.Join(wantArgs, ", "))
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 163840 {
		t.Fatalf("covered %d VEX packed integer add register encodings, want 163840", count)
	}
}

func TestDecodedX86PackedIntegerSubtractCompleteVEXRegisterFamily(t *testing.T) {
	subtractOps := map[byte]struct {
		op        Op
		laneBytes int
	}{
		0xf8: {op: "VPSUBB", laneBytes: 1},
		0xf9: {op: "VPSUBW", laneBytes: 2},
		0xfa: {op: "VPSUBD", laneBytes: 4},
		0xfb: {op: "VPSUBQ", laneBytes: 8},
		0xe8: {op: "VPSUBSB", laneBytes: 1},
		0xe9: {op: "VPSUBSW", laneBytes: 2},
		0xd8: {op: "VPSUBUSB", laneBytes: 1},
		0xd9: {op: "VPSUBUSW", laneBytes: 2},
	}
	count := 0
	for opcode, properties := range subtractOps {
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
					source2Limit := 16
					if !vex3 {
						source2Limit = 8
					}
					for destination := 0; destination < 16; destination++ {
						for source1 := 0; source1 < 16; source1++ {
							for source2 := 0; source2 < source2Limit; source2++ {
								code := encodeX86VEXPackedIntegerArithmetic(opcode, vex3, width256, widthIgnored, destination, source1, source2)
								got, length, ok, err := decodedX86PackedIntegerArithmeticInstruction(code, 64)
								if err != nil || !ok || length != len(code) {
									t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
								}
								wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), fmt.Sprintf("%s%d", prefix, destination)}
								if got.Op != properties.op || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
									t.Fatalf("decode %x = %+v, want %s %s", code, got, properties.op, strings.Join(wantArgs, ", "))
								}
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 163840 {
		t.Fatalf("covered %d VEX packed integer subtract register encodings, want 163840", count)
	}
}

func TestDecodedX86PackedIntegerArithmeticCompleteEVEXRegisterFamily(t *testing.T) {
	count := 0
	for opcode, properties := range decodedX86PackedIntegerArithmeticOps {
		for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
			prefix := [...]string{"X", "Y", "Z"}[vectorBits]
			for destination := 0; destination < 32; destination++ {
				for source1 := 0; source1 < 32; source1++ {
					for source2 := 0; source2 < 32; source2++ {
						p0 := byte((1-(destination>>3)&1)<<7 | (1-(source2>>4)&1)<<6 | (1-(source2>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 1)
						p1 := byte((^source1&15)<<3 | 1<<2 | 1)
						if properties.laneBytes == 8 {
							p1 |= 0x80
						}
						p2 := byte(int(vectorBits)<<5 | (^source1>>4&1)<<3 | 1)
						modRM := byte(0xc0 | (destination&7)<<3 | source2&7)
						code := []byte{0x62, p0, p1, p2, opcode, modRM}
						got, length, ok, err := decodedX86PackedIntegerArithmeticInstruction(code, 64)
						if err != nil || !ok || length != len(code) {
							t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
						}
						wantArgs := []string{fmt.Sprintf("%s%d", prefix, source2), fmt.Sprintf("%s%d", prefix, source1), "K1", fmt.Sprintf("%s%d", prefix, destination)}
						if got.Op != properties.op || len(got.Args) != 4 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] || got.Args[3].String() != wantArgs[3] {
							t.Fatalf("decode %x = %+v, want %s %s", code, got, properties.op, strings.Join(wantArgs, ", "))
						}
						count++
					}
				}
			}
		}
	}
	if count != 1572864 {
		t.Fatalf("covered %d EVEX packed integer arithmetic encodings, want 1572864", count)
	}
}

func TestTranslateRawVPSUBDWeaviateRegression(t *testing.T) {
	const source = `TEXT rawPackedSubtract(SB), $0-0
	LONG $0xd5faedc5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawPackedSubtract": {Name: "rawPackedSubtract", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(ir, "sub <8 x i32>") {
		t.Fatalf("raw VPSUBD lowering omitted vector subtraction:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-packed-subtract.ll", "amd64-raw-packed-subtract.o", ir)
}

func TestDecodedX86PackedIntegerArithmeticCompleteGo127Family(t *testing.T) {
	// Go 1.27 uses _yvandnpd for all sixteen VPADD/VPSUB variants. These LLVM 22
	// encodings cover every opcode plus VEX/EVEX X/Y/Z, high registers,
	// memory, masking, zeroing, D/Q broadcast, and compressed disp8.
	tests := []struct {
		name string
		code []byte
		want string
	}{
		{name: "vex byte x high", code: []byte{0xc5, 0x79, 0xfc, 0xc1}, want: "VPADDB X1, X0, X8"},
		{name: "vex qword y high memory", code: []byte{0xc4, 0x41, 0x6d, 0xd4, 0x4c, 0x24, 0x20}, want: "VPADDQ 32(R12), Y2, Y9"},
		{name: "byte x high masked", code: []byte{0x62, 0xa1, 0x55, 0x01, 0xfc, 0xf4}, want: "VPADDB X20, X21, K1, X22"},
		{name: "word y memory zeroing", code: []byte{0x62, 0xd1, 0x75, 0xaa, 0xfd, 0x50, 0x03}, want: "VPADDW.Z 96(R8), Y1, K2, Y2"},
		{name: "dword reported minio", code: []byte{0x62, 0x51, 0x45, 0x48, 0xfe, 0xc4}, want: "VPADDD Z12, Z7, Z8"},
		{name: "qword z broadcast zeroing", code: []byte{0x62, 0xf1, 0xf5, 0xdb, 0xd4, 0x50, 0x7f}, want: "VPADDQ.BCST.Z 1016(AX), Z1, K3, Z2"},
		{name: "signed byte z high", code: []byte{0x62, 0x31, 0x7d, 0x40, 0xec, 0xc9}, want: "VPADDSB Z17, Z16, Z9"},
		{name: "signed word x high memory masked", code: []byte{0x62, 0x41, 0x3d, 0x04, 0xed, 0x4c, 0x24, 0x02}, want: "VPADDSW 32(R12), X24, K4, X25"},
		{name: "unsigned byte y high masked", code: []byte{0x62, 0xa1, 0x55, 0x21, 0xdc, 0xf4}, want: "VPADDUSB Y20, Y21, K1, Y22"},
		{name: "unsigned word z memory zeroing", code: []byte{0x62, 0xf1, 0x75, 0xcb, 0xdd, 0x50, 0x7f}, want: "VPADDUSW.Z 8128(AX), Z1, K3, Z2"},
		{name: "subtract dword weaviate", code: []byte{0xc5, 0xed, 0xfa, 0xd5}, want: "VPSUBD Y5, Y2, Y2"},
		{name: "subtract qword broadcast zeroing", code: []byte{0x62, 0xf1, 0xf5, 0xdb, 0xfb, 0x50, 0x7f}, want: "VPSUBQ.BCST.Z 1016(AX), Z1, K3, Z2"},
		{name: "subtract unsigned word z memory zeroing", code: []byte{0x62, 0xf1, 0x75, 0xcb, 0xd9, 0x50, 0x7f}, want: "VPSUBUSW.Z 8128(AX), Z1, K3, Z2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			instruction, length, ok, err := decodedX86PackedIntegerArithmeticInstruction(test.code, 64)
			if !ok {
				t.Fatal("VPADD encoding was not recognized")
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

func TestDecodeX86RawDirectiveGroupReportedMinioVPADDD(t *testing.T) {
	code := []byte{0x62, 0x51, 0x45, 0x48, 0xfe, 0xc4}
	decoded, err := decodeX86RawDirectiveGroup(code, 64, 0, "minio VPADDD", map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || decoded[0].Op != "VPADDD" || !strings.HasPrefix(decoded[0].Raw, "VPADDD Z12, Z7, Z8 ") {
		t.Fatalf("decoded reported minio bytes as %#v", decoded)
	}
}
