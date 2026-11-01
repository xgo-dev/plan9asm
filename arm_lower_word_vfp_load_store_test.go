package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawVFPLoadStore(load, add bool, condition, base, bits, register, offset int) uint32 {
	word := uint32(condition)<<28 | 0x0d000a00 | uint32(base)<<16 | uint32(offset/4)
	if load {
		word |= 1 << 20
	}
	if add {
		word |= 1 << 23
	}
	if bits == 32 {
		word |= uint32(register/2) << 12
		word |= uint32(register&1) << 22
	} else {
		word |= 1 << 8
		word |= uint32(register&15) << 12
		word |= uint32(register/16) << 22
	}
	return word
}

func TestARMRawVFPLoadStoreLLVM22Forms(t *testing.T) {
	for _, test := range []struct {
		word     uint32
		load     bool
		add      bool
		base     int
		bits     int
		register int
		offset   int
	}{
		{0xed841a01, false, true, 4, 32, 2, 4},
		{0xed4dfaff, false, false, 13, 32, 31, 1020},
		{0xedcd8b11, false, true, 13, 64, 24, 68},
		{0xed941a01, true, true, 4, 32, 2, 4},
		{0xed5d8b11, true, false, 13, 64, 24, 68},
		{0xedd1fbff, true, true, 1, 64, 31, 1020},
	} {
		got, ok := decodeARMRawVFPLoadStore(test.word)
		if !ok || got.load != test.load || got.add != test.add ||
			got.base != test.base || got.bits != test.bits ||
			got.register != test.register || got.offset != test.offset {
			t.Fatalf("LLVM 22 encoding %#08x decoded as %+v, ok=%v", test.word, got, ok)
		}
		if word := encodeARMRawVFPLoadStore(
			test.load, test.add, 14, test.base, test.bits, test.register, test.offset,
		); word != test.word {
			t.Fatalf("encoded %+v as %#08x, want %#08x", test, word, test.word)
		}
	}
}

func TestARMRawVFPLoadStoreAllFields(t *testing.T) {
	for condition := 0; condition < 15; condition++ {
		for _, load := range []bool{false, true} {
			for _, add := range []bool{false, true} {
				for _, bits := range []int{32, 64} {
					for register := 0; register < 32; register++ {
						for _, offset := range []int{0, 4, 68, 1020} {
							word := encodeARMRawVFPLoadStore(load, add, condition, 13, bits, register, offset)
							got, ok := decodeARMRawVFPLoadStore(word)
							if !ok || got.load != load || got.add != add || got.bits != bits ||
								got.register != register || got.offset != offset ||
								got.condition != armConditionName(condition) {
								t.Fatalf("encoding %#08x decoded as %+v, ok=%v", word, got, ok)
							}
						}
					}
				}
			}
		}
	}
}

func TestTranslateARMRawVFPLoadStoreAllFormatsLLVM22(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawVFPLoadStore(SB), $0-0\n")
	for _, load := range []bool{false, true} {
		for _, add := range []bool{false, true} {
			for _, bits := range []int{32, 64} {
				word := encodeARMRawVFPLoadStore(load, add, 14, 13, bits, 24, 68)
				fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			}
		}
	}
	source.WriteString("\tRET\n")
	file, err := Parse(ArchARM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	const triple = "armv7-unknown-linux-gnueabihf"
	ir, err := Translate(file, Options{
		Goarch:       "arm",
		TargetTriple: triple,
		Sigs:         map[string]FuncSig{"rawVFPLoadStore": {Name: "rawVFPLoadStore", Ret: Void}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range []string{"load i32, ptr", "load i64, ptr", "store i32", "store i64"} {
		if !strings.Contains(ir, fragment) {
			t.Fatalf("raw VFP load/store family omitted %q:\n%s", fragment, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, triple, "arm-raw-vfp-load-store.ll", "arm-raw-vfp-load-store.o", ir)
}

func TestARMRawVFPLoadStoreRejectsReservedAndUnsafeForms(t *testing.T) {
	base := encodeARMRawVFPLoadStore(true, true, 14, 13, 64, 24, 68)
	for _, word := range []uint32{base | 1<<21, base &^ 1 << 24, base &^ 1 << 9, base | 0xf0000000} {
		if _, ok := decodeARMRawVFPLoadStore(word); ok {
			t.Fatalf("accepted reserved VFP load/store encoding %#08x", word)
		}
	}
	word := encodeARMRawVFPLoadStore(true, true, 14, 15, 64, 24, 68)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT badVFPLoad(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{
		Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
		Sigs: map[string]FuncSig{"badVFPLoad": {Name: "badVFPLoad", Ret: Void}},
	}); err == nil {
		t.Fatal("accepted unsafe PC-relative raw VFP load")
	}
}
