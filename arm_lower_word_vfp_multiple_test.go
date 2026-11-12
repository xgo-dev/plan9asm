package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawVFPMultiple(load, decrement, writeback bool, condition, base, bits, first, count int) uint32 {
	word := uint32(condition)<<28 | 0x0c000a00 | uint32(base)<<16
	if decrement {
		word |= 1 << 24
	} else {
		word |= 1 << 23
	}
	if writeback {
		word |= 1 << 21
	}
	if load {
		word |= 1 << 20
	}
	if bits == 32 {
		word |= uint32(first/2) << 12
		word |= uint32(first&1) << 22
		word |= uint32(count)
	} else {
		word |= 1 << 8
		word |= uint32(first&15) << 12
		word |= uint32(first/16) << 22
		word |= uint32(count * 2)
	}
	return word
}

func TestTranslateARMRawVFPMultipleCompleteModes(t *testing.T) {
	const source = `TEXT rawMultiple(SB), $0-0
	WORD $0xeca30a04 // vstmia r3!, {s0-s3}
	WORD $0xecb11a04 // vldmia r1!, {s2-s5}
	WORD $0xecb02b10 // vldmia r0!, {d2-d9}
	WORD $0xeca12b10 // vstmia r1!, {d2-d9}
	WORD $0xed324a04 // vldmdb r2!, {s8-s11}
	WORD $0xed630b20 // vstmdb r3!, {d16-d31}
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMultiple": {Name: "rawMultiple", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"load i32, ptr", "load i64, ptr", "store i32", "store i64", "sub i32", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP multiple IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-multiple.ll", "arm-raw-vfp-multiple.o", ir)
}

func TestARMRawVFPMultipleDecoderCoversEveryValidField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for _, load := range []bool{false, true} {
			for _, decrement := range []bool{false, true} {
				for _, writeback := range []bool{false, true} {
					if decrement && !writeback {
						continue
					}
					for base := 0; base < 16; base++ {
						for _, bits := range []int{32, 64} {
							for first := 0; first < 32; first++ {
								for registers := 1; registers <= 32-first; registers++ {
									word := encodeARMRawVFPMultiple(load, decrement, writeback, condition, base, bits, first, registers)
									got, ok := decodeARMRawVFPMultiple(word)
									if !ok || got.load != load || got.decrement != decrement || got.writeback != writeback || got.condition != armConditionName(condition) || got.base != base || got.bits != bits || got.first != first || got.count != registers {
										t.Fatalf("decoded VFP multiple %#08x as %+v, ok=%v", word, got, ok)
									}
									count++
								}
							}
						}
					}
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("covered no VFP multiple encodings")
	}
}

func TestARMRawVFPMultipleRejectsReservedAndUnsafeForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawVFPMultiple(true, false, true, 15, 0, 32, 0, 1),
		encodeARMRawVFPMultiple(true, true, false, 14, 0, 32, 0, 1),
		encodeARMRawVFPMultiple(true, false, true, 14, 0, 32, 31, 2),
	} {
		if _, ok := decodeARMRawVFPMultiple(word); ok {
			t.Fatalf("VFP multiple decoder accepted reserved encoding %#08x", word)
		}
	}
	word := encodeARMRawVFPMultiple(true, false, true, 14, 15, 32, 0, 1)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badMultiple(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"badMultiple": {Name: "badMultiple", Ret: Void}}}); err == nil {
		t.Fatal("Translate accepted PC as VFP multiple base")
	}
}
