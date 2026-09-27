package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var armRawVFPScalarArithmeticTestBases = map[string]uint32{
	"add":   0x0e300a00,
	"sub":   0x0e300a40,
	"mul":   0x0e200a00,
	"nmul":  0x0e200a40,
	"div":   0x0e800a00,
	"madd":  0x0e000a00,
	"msub":  0x0e000a40,
	"nmadd": 0x0e100a40,
	"nmsub": 0x0e100a00,
}

func encodeARMRawVFPScalarArithmetic(kind string, condition, bits, destination, lhs, rhs int) uint32 {
	word := uint32(condition)<<28 | armRawVFPScalarArithmeticTestBases[kind]
	if bits == 64 {
		word |= 1 << 8
		word |= uint32(destination&15) << 12
		word |= uint32(destination/16) << 22
		word |= uint32(lhs&15) << 16
		word |= uint32(lhs/16) << 7
		word |= uint32(rhs & 15)
		word |= uint32(rhs/16) << 5
		return word
	}
	word |= uint32(destination/2) << 12
	word |= uint32(destination&1) << 22
	word |= uint32(lhs/2) << 16
	word |= uint32(lhs&1) << 7
	word |= uint32(rhs / 2)
	word |= uint32(rhs&1) << 5
	return word
}

func TestTranslateARMRawVFPScalarArithmeticGoDSPRegression(t *testing.T) {
	const source = `TEXT rawScalarArithmetic(SB), $0-0
	WORD $0xee611a80 // vmul.f32 s3, s3, s0
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawScalarArithmetic": {Name: "rawScalarArithmetic", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fmul float", "lshr i64", "and i64", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP scalar arithmetic omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-scalar-arithmetic.ll", "arm-raw-vfp-scalar-arithmetic.o", ir)
}

func TestARMRawVFPScalarArithmeticDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for kind := range armRawVFPScalarArithmeticTestBases {
		for condition := 0; condition < 15; condition++ {
			for _, bits := range []int{32, 64} {
				for destination := 0; destination < 32; destination++ {
					for lhs := 0; lhs < 32; lhs++ {
						for rhs := 0; rhs < 32; rhs++ {
							word := encodeARMRawVFPScalarArithmetic(kind, condition, bits, destination, lhs, rhs)
							got, ok := decodeARMRawVFPScalarArithmetic(word)
							if !ok || got.kind != kind || got.condition != armConditionName(condition) || got.bits != bits || got.destination != destination || got.lhs != lhs || got.rhs != rhs {
								t.Fatalf("decoded scalar VFP arithmetic %#08x as %+v, ok=%v", word, got, ok)
							}
							count++
						}
					}
				}
			}
		}
	}
	if count != 8847360 {
		t.Fatalf("covered %d scalar VFP arithmetic encodings, want 8847360", count)
	}
}

func TestTranslateARMRawVFPScalarArithmeticAllOperations(t *testing.T) {
	source := "TEXT rawScalarArithmeticAll(SB), $0-0\n\tCMP R0, R1\n"
	for kind := range armRawVFPScalarArithmeticTestBases {
		for _, bits := range []int{32, 64} {
			for _, condition := range []int{1, 14} {
				word := encodeARMRawVFPScalarArithmetic(kind, condition, bits, 3, 5, 7)
				source += fmt.Sprintf("\tWORD $%#08x\n", word)
			}
		}
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawScalarArithmeticAll": {Name: "rawScalarArithmeticAll", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"fadd float", "fsub double", "fmul float", "fdiv double", "fneg float", "cond_effect_taken", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP scalar arithmetic family omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-scalar-arithmetic-all.ll", "arm-raw-vfp-scalar-arithmetic-all.o", ir)
}

func TestARMRawVFPScalarArithmeticRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawVFPScalarArithmetic("mul", 15, 32, 0, 0, 0),
		encodeARMRawVFPScalarArithmetic("mul", 14, 32, 0, 0, 0) ^ 1<<9,
	} {
		if _, ok := decodeARMRawVFPScalarArithmetic(word); ok {
			t.Fatalf("scalar VFP arithmetic decoder accepted reserved encoding %#08x", word)
		}
	}
}
