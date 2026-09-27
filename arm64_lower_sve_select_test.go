package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVESelect(elementBits, falseValue, trueValue, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x0520c000 | size<<22 | uint32(falseValue)<<16 | uint32(trueValue)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func TestTranslateARM64SVESelectCompleteGo127Form(t *testing.T) {
	const named = `
TEXT sveselnamed(SB),$0-0
	ZSEL Z31.B, Z30.B, P0, Z29.B
	ZSEL Z28.H, Z27.H, P5, Z26.H
	ZSEL Z25.S, Z24.S, P10, Z23.S
	ZSEL Z22.D, Z21.D, P15, Z20.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT sveselraw(SB),$0-0\n")
	for i, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVESelect(elementBits, i, i+4, i*5, i+8))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svesel" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve"`, " select <vscale x 16 x i1>", " select <vscale x 8 x i1>", " select <vscale x 4 x i1>", " select <vscale x 2 x i1>"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE SEL lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-select.ll", "arm64-sve-select.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVESelectDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, elementBits := range []int{8, 16, 32, 64} {
		for falseValue := 0; falseValue < 32; falseValue++ {
			for trueValue := 0; trueValue < 32; trueValue++ {
				for predicate := 0; predicate < 16; predicate++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVESelect(elementBits, falseValue, trueValue, predicate, destination)
						got, ok := decodeARM64RawSVESelect(word)
						if !ok || got.elementBits != elementBits || got.falseValue != falseValue || got.trueValue != trueValue || got.predicate != predicate || got.destination != destination {
							t.Fatalf("decoded SVE SEL %#08x as %+v, ok=%v", word, got, ok)
						}
						count++
					}
				}
			}
		}
	}
	if count != 4*32*32*16*32 {
		t.Fatalf("covered %d SVE SEL encodings, want %d", count, 4*32*32*16*32)
	}
}

func TestARM64SVESelectRejectsAdjacentAndPredicateSuffix(t *testing.T) {
	for _, word := range []uint32{0x05208000, 0x0520a000, 0x05204000} {
		if _, ok := decodeARM64RawSVESelect(word); ok {
			t.Fatalf("SVE SEL decoder accepted adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsvesel(SB),$0-0
	ZSEL Z1.S, Z2.S, P3.M, Z4.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvesel": {Name: "badsvesel", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted SVE SEL merge predicate syntax")
	}
}
