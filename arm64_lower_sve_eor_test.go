package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEEORUnpredicated(second, first, destination int) uint32 {
	return 0x04a03000 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEEORPredicated(elementBits, second, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04190000 | size<<22 | uint32(second)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVEEORImmediateBits(imm13, destination int) uint32 {
	return 0x05400000 | uint32(imm13)<<5 | uint32(destination)
}

func TestTranslateARM64SVEEORCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT sveeornamed(SB),$0-0
	ZEOR Z31.D, Z30.D, Z29.D
	ZEOR Z28.B, Z0.B, P0.M, Z0.B
	ZEOR Z27.H, Z1.H, P1.M, Z1.H
	ZEOR Z26.S, Z2.S, P2.M, Z2.S
	ZEOR Z25.D, Z3.D, P7.M, Z3.D
	ZEOR $0x55, Z4.B, Z4.B
	ZEOR $0xff00, Z5.H, Z5.H
	ZEOR $0xffff0000, Z6.S, Z6.S
	ZEOR $0xffffffff00000000, Z7.D, Z7.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT sveeorraw(SB),$0-0\n")
	fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEEORUnpredicated(1, 2, 3))
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEEORPredicated(elementBits, 4, 5, 6))
	}
	for _, imm13 := range []int{0x03c, 0x227, 0x40f, 0x181f} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEEORImmediateBits(imm13, 7))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "sveeor" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve"`, " xor <vscale x ", " select <vscale x "} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE EOR lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-eor.ll", "arm64-sve-eor.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVEEORDecoderCoversEveryEncodingField(t *testing.T) {
	for second := 0; second < 32; second++ {
		for first := 0; first < 32; first++ {
			for destination := 0; destination < 32; destination++ {
				word := encodeARM64RawSVEEORUnpredicated(second, first, destination)
				got, ok := decodeARM64RawSVEEOR(word)
				if !ok || got.mode != arm64SVEEORUnpredicated || got.elementBits != 64 || got.second != second || got.first != first || got.destination != destination {
					t.Fatalf("decoded unpredicated SVE EOR %#08x as %+v, ok=%v", word, got, ok)
				}
			}
		}
	}
	for _, elementBits := range []int{8, 16, 32, 64} {
		for second := 0; second < 32; second++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEEORPredicated(elementBits, second, predicate, destination)
					got, ok := decodeARM64RawSVEEOR(word)
					if !ok || got.mode != arm64SVEEORPredicated || got.elementBits != elementBits || got.second != second || got.first != destination || got.predicate != predicate || got.destination != destination {
						t.Fatalf("decoded predicated SVE EOR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
	validImmediateEncodings := 0
	for imm13 := 0; imm13 < 1<<13; imm13++ {
		for destination := 0; destination < 32; destination++ {
			word := encodeARM64RawSVEEORImmediateBits(imm13, destination)
			got, ok := decodeARM64RawSVEEOR(word)
			if !ok {
				continue
			}
			if got.mode != arm64SVEEORImmediate || got.destination != destination || got.first != destination || got.immediate == 0 {
				t.Fatalf("decoded immediate SVE EOR %#08x as %+v", word, got)
			}
			validImmediateEncodings++
		}
	}
	if validImmediateEncodings != 7680*32 {
		t.Fatalf("decoded %d valid SVE logical-immediate fields, want %d", validImmediateEncodings, 7680*32)
	}
}

func TestARM64SVEEORLogicalImmediateKnownValuesAndInvalidForms(t *testing.T) {
	for _, test := range []struct {
		imm13, bits int
		value       uint64
	}{
		{0x03c, 8, 0x55},
		{0x227, 16, 0xff00},
		{0x40f, 32, 0xffff0000},
		{0x181f, 64, 0xffffffff00000000},
	} {
		got, ok := decodeARM64RawSVEEOR(encodeARM64RawSVEEORImmediateBits(test.imm13, 9))
		if !ok || got.elementBits != test.bits || got.immediate != test.value {
			t.Fatalf("logical immediate %#x decoded as %+v, ok=%v; want bits=%d value=%#x", test.imm13, got, ok, test.bits, test.value)
		}
	}
	for _, word := range []uint32{0x04a03400, 0x041c0000, encodeARM64RawSVEEORImmediateBits(0x3f, 0)} {
		if _, ok := decodeARM64RawSVEEOR(word); ok {
			t.Fatalf("SVE EOR decoder accepted adjacent/reserved encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsveeor(SB),$0-0
	ZEOR Z1.S, Z2.S, P0.M, Z3.S
	ZEOR $0, Z4.D, Z4.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveeor": {Name: "badsveeor", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted invalid SVE EOR forms")
	}
}
