package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestTranslateARMRawVFPConditionalMoveGoDSPRegression(t *testing.T) {
	const source = `TEXT rawConditionalMove(SB), $0-0
	CMP R0, R1
	WORD $0xceb04a60 // vmovgt.f32 s8, s1
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawConditionalMove": {Name: "rawConditionalMove", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lshr i64", "trunc i64", "cond_effect_taken", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw conditional VFP move IR omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-move.ll", "arm-raw-vfp-move.o", ir)
}

func encodeARMRawVFPMove(condition, bits, destination, source int) uint32 {
	word := uint32(condition)<<28 | 0x0eb00a40
	if bits == 32 {
		word |= uint32(destination/2) << 12
		word |= uint32(destination&1) << 22
		word |= uint32(source / 2)
		word |= uint32(source&1) << 5
	} else {
		word |= 1 << 8
		word |= uint32(destination&15) << 12
		word |= uint32(destination/16) << 22
		word |= uint32(source & 15)
		word |= uint32(source/16) << 5
	}
	return word
}

func TestARMRawVFPMoveDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for _, bits := range []int{32, 64} {
			for destination := 0; destination < 32; destination++ {
				for source := 0; source < 32; source++ {
					word := encodeARMRawVFPMove(condition, bits, destination, source)
					got, ok := decodeARMRawVFPMove(word)
					if !ok || got.condition != armConditionName(condition) || got.bits != bits || got.destination != destination || got.source != source {
						t.Fatalf("decoded VFP VMOV %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != 30720 {
		t.Fatalf("covered %d scalar VFP VMOV encodings, want 30720", count)
	}
}

func TestTranslateARMRawVFPMoveCompleteFormats(t *testing.T) {
	source := "TEXT rawMoveAll(SB), $0-0\n\tCMP R0, R1\n"
	for condition := 0; condition < 15; condition++ {
		for _, test := range []struct {
			bits        int
			destination int
			source      int
		}{{32, 0, 31}, {32, 31, 0}, {64, 0, 31}, {64, 31, 0}} {
			source += fmt.Sprintf("\tWORD $%#08x\n", encodeARMRawVFPMove(condition, test.bits, test.destination, test.source))
		}
	}
	source += "\tRET\n"
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawMoveAll": {Name: "rawMoveAll", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"lshr i64", "shl i64", "cond_effect_taken", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP VMOV complete formats omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-move-all.ll", "arm-raw-vfp-move-all.o", ir)
}

func TestARMRawVFPMoveRejectsReservedConditionAndDifferentFamilies(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawVFPMove(15, 32, 0, 0),
		encodeARMRawVFPMove(14, 32, 0, 0) | 1<<16,
		encodeARMRawVFPMove(14, 32, 0, 0) | 1<<4,
	} {
		if _, ok := decodeARMRawVFPMove(word); ok {
			t.Fatalf("scalar VFP VMOV decoder accepted reserved encoding %#08x", word)
		}
	}
}
