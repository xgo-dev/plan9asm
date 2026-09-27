package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawVMOVPair(toFloat bool, condition, firstCore, secondCore, firstSingle int) uint32 {
	word := uint32(condition)<<28 | 0x0c400a10 | uint32(secondCore)<<16 | uint32(firstCore)<<12 | uint32(firstSingle/2)
	if !toFloat {
		word |= 1 << 20
	}
	if firstSingle&1 != 0 {
		word |= 1 << 5
	}
	return word
}

func encodeARMRawVMOVDoublePair(toFloat bool, condition, firstCore, secondCore, double int) uint32 {
	word := uint32(condition)<<28 | 0x0c400b10 | uint32(secondCore)<<16 | uint32(firstCore)<<12 | uint32(double&15)
	if !toFloat {
		word |= 1 << 20
	}
	if double&16 != 0 {
		word |= 1 << 5
	}
	return word
}

func TestTranslateARMRawVMOVDoublePairCompleteDirections(t *testing.T) {
	const source = `TEXT rawVMOVDoublePair(SB), $0-0
	WORD $0xec454b38 // vmov d24, r4, r5
	WORD $0xec554b38 // vmov r4, r5, d24
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawVMOVDoublePair": {Name: "rawVMOVDoublePair", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"shl i64", "lshr i64", "trunc i64", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("double-register VMOV pair IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vmov-double-pair.ll", "arm-raw-vmov-double-pair.o", ir)
}

func TestARMRawVMOVDoublePairDecoderCoversEveryEncodingField(t *testing.T) {
	for _, toFloat := range []bool{false, true} {
		for condition := 0; condition < 15; condition++ {
			for firstCore := 0; firstCore < 16; firstCore++ {
				for secondCore := 0; secondCore < 16; secondCore++ {
					for double := 0; double < 32; double++ {
						word := encodeARMRawVMOVDoublePair(toFloat, condition, firstCore, secondCore, double)
						got, ok := decodeARMRawVMOVPair(word)
						if !ok || !got.double || got.toFloat != toFloat || got.condition != armConditionName(condition) || got.firstCore != firstCore || got.secondCore != secondCore || got.firstDouble != double {
							t.Fatalf("decoded double-register VMOV pair %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}

func TestTranslateARMRawVMOVPairCompleteDirections(t *testing.T) {
	const source = `TEXT rawVMOVPair(SB), $0-0
	WORD $0xec454a1e // vmov s28, s29, r4, r5
	WORD $0xec476a1f // vmov s30, s31, r6, r7
	WORD $0xec540a11 // vmov r0, r4, s2, s3
	WORD $0xec5b8a12 // vmov r8, r11, s4, s5
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawVMOVPair": {Name: "rawVMOVPair", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"zext i32", "trunc i64", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("VMOV pair IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vmov-pair.ll", "arm-raw-vmov-pair.o", ir)
}

func TestARMRawVMOVPairDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, toFloat := range []bool{false, true} {
		for condition := 0; condition < 15; condition++ {
			for firstCore := 0; firstCore < 16; firstCore++ {
				for secondCore := 0; secondCore < 16; secondCore++ {
					for firstSingle := 0; firstSingle < 31; firstSingle++ {
						word := encodeARMRawVMOVPair(toFloat, condition, firstCore, secondCore, firstSingle)
						got, ok := decodeARMRawVMOVPair(word)
						if !ok || got.toFloat != toFloat || got.condition != armConditionName(condition) || got.firstCore != firstCore || got.secondCore != secondCore || got.firstSingle != firstSingle {
							t.Fatalf("decoded VMOV pair %#08x as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 2*15*16*16*31 {
		t.Fatalf("covered %d VMOV pair encodings", count)
	}
}

func TestARMRawVMOVPairRejectsReservedAndUnsafeForms(t *testing.T) {
	if _, ok := decodeARMRawVMOVPair(encodeARMRawVMOVPair(true, 15, 0, 1, 0)); ok {
		t.Fatal("VMOV pair decoder accepted condition 0xf")
	}
	if _, ok := decodeARMRawVMOVPair(encodeARMRawVMOVDoublePair(true, 15, 0, 1, 0)); ok {
		t.Fatal("double-register VMOV pair decoder accepted condition 0xf")
	}
	for _, word := range []uint32{
		encodeARMRawVMOVPair(true, 14, 15, 1, 0),
		encodeARMRawVMOVPair(false, 14, 0, 15, 0),
		encodeARMRawVMOVDoublePair(true, 14, 15, 1, 0),
		encodeARMRawVMOVDoublePair(false, 14, 0, 15, 0),
	} {
		file, err := Parse(ArchARM, fmt.Sprintf("TEXT badVMOVPair(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"badVMOVPair": {Name: "badVMOVPair", Ret: Void}}}); err == nil {
			t.Fatalf("Translate accepted PC in VMOV pair %#08x", word)
		}
	}
}
