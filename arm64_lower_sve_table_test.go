package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVETable(elementBits, tableCount, index, firstTable, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	base := uint32(0x05203000)
	if tableCount == 2 {
		base = 0x05202800
	}
	return base | size<<22 | uint32(index)<<16 | uint32(firstTable)<<5 | uint32(destination)
}

func TestTranslateARM64SVETableCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT svetblnamed(SB),$0-0
	ZTBL Z31.B, [Z0.B], Z1.B
	ZTBL Z30.H, [Z2.H], Z3.H
	ZTBL Z29.S, [Z4.S], Z5.S
	ZTBL Z28.D, [Z6.D], Z7.D
	ZTBL Z27.B, [Z8.B, Z9.B], Z10.B
	ZTBL Z26.H, [Z11.H, Z12.H], Z13.H
	ZTBL Z25.S, [Z14.S, Z15.S], Z16.S
	ZTBL Z24.D, [Z30.D, Z31.D], Z17.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT svetblraw(SB),$0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVETable(elementBits, 1, 1, 2, 3))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVETable(elementBits, 2, 4, 31, 5))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svetbl" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.tbl.nxv", "@llvm.aarch64.sve.tbl2.nxv"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE TBL lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-table.ll", "arm64-sve-table.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVETableDecoderCoversEveryEncodingField(t *testing.T) {
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, tableCount := range []int{1, 2} {
			for index := 0; index < 32; index++ {
				for firstTable := 0; firstTable < 32; firstTable++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVETable(elementBits, tableCount, index, firstTable, destination)
						got, ok := decodeARM64RawSVETable(word)
						if !ok || got.elementBits != elementBits || got.tableCount != tableCount || got.index != index || got.firstTable != firstTable || got.destination != destination {
							t.Fatalf("decoded SVE TBL %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}

func TestARM64SVETableRejectsAdjacentAndGoRejectsWrappingNamedPair(t *testing.T) {
	for _, word := range []uint32{0x05202c00, 0x05202000, 0x05203800} {
		if _, ok := decodeARM64RawSVETable(word); ok {
			t.Fatalf("SVE TBL decoder accepted adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsvetbl(SB),$0-0
	ZTBL Z0.B, [Z31.B, Z0.B], Z1.B
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvetbl": {Name: "badsvetbl", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted the wrapping named SVE TBL pair rejected by Go 1.27")
	}

	// The machine encoding and LLVM accept the architectural Z31,Z0 wrap even
	// though Go's named reglist encoder rejects it.
	if got, ok := decodeARM64RawSVETable(encodeARM64RawSVETable(8, 2, 0, 31, 1)); !ok || got.firstTable != 31 {
		t.Fatalf("raw SVE TBL pair wrap was not preserved: %+v, ok=%v", got, ok)
	}
}
