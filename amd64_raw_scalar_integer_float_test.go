package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeX86VEXScalarIntegerFloat(pp byte, width64, vex3 bool, destination, passthrough, source int) []byte {
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	if !vex3 {
		vex1 := byte((1-(destination>>3)&1)<<7 | (^passthrough&15)<<3 | int(pp))
		return []byte{0xc5, vex1, 0x2a, modRM}
	}
	vex0 := byte((1-(destination>>3)&1)<<7 | 1<<6 | (1-(source>>3)&1)<<5 | 1)
	vex1 := byte((^passthrough&15)<<3 | int(pp))
	if width64 {
		vex1 |= 0x80
	}
	return []byte{0xc4, vex0, vex1, 0x2a, modRM}
}

func encodeX86EVEXScalarIntegerFloat(unsigned bool, pp byte, width64 bool, vectorBits byte, rounding bool, destination, passthrough, source int) []byte {
	opcode := byte(0x2a)
	if unsigned {
		opcode = 0x7b
	}
	p0 := byte((1-(destination>>3)&1)<<7 | 1<<6 | (1-(source>>3)&1)<<5 | (1-(destination>>4)&1)<<4 | 1)
	p1 := byte((^passthrough&15)<<3 | 1<<2 | int(pp))
	if width64 {
		p1 |= 0x80
	}
	p2 := byte(int(vectorBits)<<5 | (^passthrough>>4&1)<<3)
	if rounding {
		p2 |= 0x10
	}
	modRM := byte(0xc0 | (destination&7)<<3 | source&7)
	return []byte{0x62, p0, p1, p2, opcode, modRM}
}

func scalarIntegerFloatRawOp(unsigned bool, pp byte, width64 bool) Op {
	prefix := "VCVTSI2"
	if unsigned {
		prefix = "VCVTUSI2"
	}
	result := "SS"
	if pp == 3 {
		result = "SD"
	}
	source := "L"
	if width64 {
		source = "Q"
	}
	return Op(prefix + result + source)
}

func TestTranslateRawVEXScalarIntegerFloatWeaviateRegression(t *testing.T) {
	const source = `TEXT rawScalarIntegerFloat(SB), $0-0
	LONG $0xc82aeac5
	LONG $0xc02a9ac5
	RET
`
	file, err := Parse(ArchAMD64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu", Sigs: map[string]FuncSig{"rawScalarIntegerFloat": {Name: "rawScalarIntegerFloat", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(ir, "sitofp i32") != 2 {
		t.Fatalf("raw VCVTSI2SSL lowering omitted signed conversions:\n%s", ir)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "x86_64-unknown-linux-gnu", "amd64-raw-scalar-integer-float.ll", "amd64-raw-scalar-integer-float.o", ir)
}

func TestDecodedX86VEXScalarIntegerFloatCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, pp := range []byte{2, 3} {
		for destination := 0; destination < 16; destination++ {
			for passthrough := 0; passthrough < 16; passthrough++ {
				for source := 0; source < 8; source++ {
					code := encodeX86VEXScalarIntegerFloat(pp, false, false, destination, passthrough, source)
					assertDecodedX86ScalarIntegerFloat(t, code, scalarIntegerFloatRawOp(false, pp, false), destination, passthrough, source, "")
					count++
				}
			}
		}
		for _, width64 := range []bool{false, true} {
			for destination := 0; destination < 16; destination++ {
				for passthrough := 0; passthrough < 16; passthrough++ {
					for source := 0; source < 16; source++ {
						code := encodeX86VEXScalarIntegerFloat(pp, width64, true, destination, passthrough, source)
						assertDecodedX86ScalarIntegerFloat(t, code, scalarIntegerFloatRawOp(false, pp, width64), destination, passthrough, source, "")
						count++
					}
				}
			}
		}
	}
	if count != 20480 {
		t.Fatalf("covered %d VEX scalar integer-to-float encodings, want 20480", count)
	}
}

func TestDecodedX86EVEXScalarIntegerFloatCompleteRegisterFamily(t *testing.T) {
	count := 0
	for _, unsigned := range []bool{false, true} {
		for _, pp := range []byte{2, 3} {
			for _, width64 := range []bool{false, true} {
				for vectorBits := byte(0); vectorBits < 3; vectorBits++ {
					for destination := 0; destination < 32; destination++ {
						for passthrough := 0; passthrough < 32; passthrough++ {
							for source := 0; source < 16; source++ {
								code := encodeX86EVEXScalarIntegerFloat(unsigned, pp, width64, vectorBits, false, destination, passthrough, source)
								assertDecodedX86ScalarIntegerFloat(t, code, scalarIntegerFloatRawOp(unsigned, pp, width64), destination, passthrough, source, "")
								count++
							}
						}
					}
				}
			}
		}
	}
	if count != 393216 {
		t.Fatalf("covered %d EVEX scalar integer-to-float encodings, want 393216", count)
	}
}

func TestDecodedX86EVEXScalarIntegerFloatRoundingMemoryAndInvalid(t *testing.T) {
	for vectorBits, suffix := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
		code := encodeX86EVEXScalarIntegerFloat(false, 2, true, byte(vectorBits), true, 17, 18, 9)
		assertDecodedX86ScalarIntegerFloat(t, code, "VCVTSI2SSQ."+Op(suffix), 17, 18, 9, "")
	}
	memory := []byte{0x62, 0xe1, 0xff, 0x00, 0x2a, 0x60, 0x02}
	got, length, ok, err := decodedX86ScalarIntegerFloatInstruction(memory, 64)
	if err != nil || !ok || length != len(memory) || got.Op != "VCVTSI2SDQ" || len(got.Args) != 3 || got.Args[0].String() != "16(AX)" || got.Args[1].String() != "X16" || got.Args[2].String() != "X20" {
		t.Fatalf("decode %x = %+v, length=%d, ok=%v, err=%v", memory, got, length, ok, err)
	}

	roundingMemory := encodeX86EVEXScalarIntegerFloat(false, 2, true, 0, true, 0, 0, 0)
	roundingMemory[len(roundingMemory)-1] = 0
	nonRounding := encodeX86EVEXScalarIntegerFloat(false, 3, false, 0, true, 0, 0, 0)
	invalid := [][]byte{
		encodeX86VEXScalarIntegerFloat(1, false, false, 0, 0, 0),
		encodeX86EVEXScalarIntegerFloat(false, 2, false, 3, false, 0, 0, 0),
		roundingMemory,
		nonRounding,
	}
	for _, code := range invalid {
		if _, _, ok, err := decodedX86ScalarIntegerFloatInstruction(code, 64); !ok || err == nil {
			t.Fatalf("invalid encoding %x returned ok=%v err=%v", code, ok, err)
		}
	}
}

func assertDecodedX86ScalarIntegerFloat(t *testing.T, code []byte, op Op, destination, passthrough, source int, sourceText string) {
	t.Helper()
	got, length, ok, err := decodedX86ScalarIntegerFloatInstruction(code, 64)
	if err != nil || !ok || length != len(code) {
		t.Fatalf("decode %x returned %+v, length=%d, ok=%v, err=%v", code, got, length, ok, err)
	}
	if sourceText == "" {
		sourceText = decodedX86ScalarIntegerFloatTestRegister(source)
	}
	wantArgs := []string{sourceText, fmt.Sprintf("X%d", passthrough), fmt.Sprintf("X%d", destination)}
	if got.Op != op || len(got.Args) != 3 || got.Args[0].String() != wantArgs[0] || got.Args[1].String() != wantArgs[1] || got.Args[2].String() != wantArgs[2] {
		t.Fatalf("decode %x = %+v, want %s %s", code, got, op, strings.Join(wantArgs, ", "))
	}
}

func decodedX86ScalarIntegerFloatTestRegister(number int) string {
	register, ok := decodedX86GeneralRegister(number)
	if !ok {
		return fmt.Sprintf("invalid%d", number)
	}
	return string(register)
}
