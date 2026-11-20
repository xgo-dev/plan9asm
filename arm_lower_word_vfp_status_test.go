package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARMRawVFPStatusTransfer(toCore bool, condition, core int) uint32 {
	word := uint32(condition)<<28 | 0x0ee10a10 | uint32(core)<<12
	if toCore {
		word |= 1 << 20
	}
	return word
}

func TestTranslateARMRawVFPStatusGoDSPRegression(t *testing.T) {
	const source = `TEXT rawStatus(SB), $0-0
	WORD $0xeef13a10 // vmrs r3, fpscr
	WORD $0xeee13a10 // vmsr fpscr, r3
	RET
`
	file, err := Parse(ArchARM, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"rawStatus": {Name: "rawStatus", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"vmrs $0, fpscr", "vmsr fpscr, $0", `"target-features"="+vfp2"`} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw VFP status transfer omitted %q:\n%s", want, ir)
		}
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	compileLLVMToObject(t, llc, "armv7-unknown-linux-gnueabihf", "arm-raw-vfp-status.ll", "arm-raw-vfp-status.o", ir)
}

func TestARMRawVFPStatusDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for condition := 0; condition < 15; condition++ {
		for core := 0; core < 15; core++ {
			for _, toCore := range []bool{false, true} {
				word := encodeARMRawVFPStatusTransfer(toCore, condition, core)
				got, ok := decodeARMRawVFPStatusTransfer(word)
				if !ok || got.toCore != toCore || got.toFlags || got.condition != armConditionName(condition) || got.core != core {
					t.Fatalf("decoded VFP status transfer %#08x as %+v, ok=%v", word, got, ok)
				}
				count++
			}
		}
		word := encodeARMRawVFPStatusTransfer(true, condition, 15)
		got, ok := decodeARMRawVFPStatusTransfer(word)
		if !ok || !got.toCore || !got.toFlags || got.condition != armConditionName(condition) {
			t.Fatalf("decoded VFP flag transfer %#08x as %+v, ok=%v", word, got, ok)
		}
		count++
	}
	if count != 465 {
		t.Fatalf("covered %d VFP status transfers, want 465", count)
	}
}

func TestARMRawVFPStatusRejectsReservedForms(t *testing.T) {
	for _, word := range []uint32{
		encodeARMRawVFPStatusTransfer(false, 14, 15),
		encodeARMRawVFPStatusTransfer(true, 15, 0),
		encodeARMRawVFPStatusTransfer(true, 14, 0) ^ 1<<8,
	} {
		if got, ok := decodeARMRawVFPStatusTransfer(word); ok {
			t.Fatalf("VFP status decoder accepted reserved encoding %#08x as %+v", word, got)
		}
	}

	word := encodeARMRawVFPStatusTransfer(true, 14, 15)
	file, err := Parse(ArchARM, fmt.Sprintf("TEXT missingCompare(SB), $0-0\n\tWORD $%#08x\n\tRET\n", word))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf", Sigs: map[string]FuncSig{"missingCompare": {Name: "missingCompare", Ret: Void}}}); err == nil || !strings.Contains(err.Error(), ErrProbeNeedsContext.Error()) {
		t.Fatalf("flag transfer without comparison returned %v, want context error", err)
	}
}
