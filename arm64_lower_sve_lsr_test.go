package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64SVEShiftImmediateBits(elementBits, shift, lowBit int) uint32 {
	encoded := 2*elementBits - shift
	if lowBit == 5 {
		return uint32(encoded&7)<<5 | uint32((encoded>>3)&3)<<8 | uint32((encoded>>5)&3)<<22
	}
	return uint32(encoded&7)<<16 | uint32((encoded>>3)&3)<<19 | uint32((encoded>>5)&3)<<22
}

func encodeARM64RawSVELSRWidePredicated(elementBits, shifts, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2}[elementBits]
	return 0x04198000 | size<<22 | uint32(shifts)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVELSRWideUnpredicated(elementBits, shifts, source, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2}[elementBits]
	return 0x04208400 | size<<22 | uint32(shifts)<<16 | uint32(source)<<5 | uint32(destination)
}

func encodeARM64RawSVELSRVectorPredicated(elementBits, shifts, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04118000 | size<<22 | uint32(shifts)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVELSRImmediatePredicated(elementBits, shift, predicate, destination int) uint32 {
	return 0x04018000 | encodeARM64SVEShiftImmediateBits(elementBits, shift, 5) | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVELSRImmediateUnpredicated(elementBits, shift, source, destination int) uint32 {
	return 0x04209400 | encodeARM64SVEShiftImmediateBits(elementBits, shift, 16) | uint32(source)<<5 | uint32(destination)
}

func TestTranslateARM64SVELSRCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT svelsrnamed(SB),$0-0
	ZLSR Z1.D, Z2.B, P0.M, Z2.B
	ZLSR Z3.D, Z4.H, P1.M, Z4.H
	ZLSR Z5.D, Z6.S, P2.M, Z6.S
	ZLSR Z7.D, Z8.B, Z9.B
	ZLSR Z10.D, Z11.H, Z12.H
	ZLSR Z13.D, Z14.S, Z15.S
	ZLSR Z16.B, Z17.B, P3.M, Z17.B
	ZLSR Z18.H, Z19.H, P4.M, Z19.H
	ZLSR Z20.S, Z21.S, P5.M, Z21.S
	ZLSR Z22.D, Z23.D, P6.M, Z23.D
	ZLSR $7, Z24.B, P7.M, Z24.B
	ZLSR $15, Z25.H, P0.M, Z25.H
	ZLSR $31, Z26.S, P1.M, Z26.S
	ZLSR $63, Z27.D, P2.M, Z27.D
	ZLSR $1, Z28.B, Z29.B
	ZLSR $15, Z28.H, Z29.H
	ZLSR $31, Z28.S, Z29.S
	ZLSR $63, Z28.D, Z29.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT svelsrraw(SB),$0-0\n")
	for _, elementBits := range []int{8, 16, 32} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVELSRWidePredicated(elementBits, 1, 2, 3))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVELSRWideUnpredicated(elementBits, 4, 5, 6))
	}
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVELSRVectorPredicated(elementBits, 7, 3, 8))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVELSRImmediatePredicated(elementBits, elementBits, 4, 9))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVELSRImmediateUnpredicated(elementBits, elementBits/2, 10, 11))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svelsr" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve"`, "@llvm.aarch64.sve.lsr.nxv", "@llvm.aarch64.sve.lsr.wide.nxv", "@llvm.aarch64.sve.ptrue"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE LSR lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-lsr.ll", "arm64-sve-lsr.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVELSRDecoderCoversEveryGo127EncodingField(t *testing.T) {
	for _, elementBits := range []int{8, 16, 32} {
		for shifts := 0; shifts < 32; shifts++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVELSRWidePredicated(elementBits, shifts, predicate, destination)
					got, ok := decodeARM64RawSVELSR(word)
					if !ok || got.mode != arm64SVELSRWidePredicated || got.elementBits != elementBits || got.shifts != shifts || got.predicate != predicate || got.source != destination || got.destination != destination {
						t.Fatalf("decoded wide predicated SVE LSR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for shifts := 0; shifts < 32; shifts++ {
			for source := 0; source < 32; source++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVELSRWideUnpredicated(elementBits, shifts, source, destination)
					got, ok := decodeARM64RawSVELSR(word)
					if !ok || got.mode != arm64SVELSRWideUnpredicated || got.elementBits != elementBits || got.shifts != shifts || got.source != source || got.destination != destination {
						t.Fatalf("decoded wide unpredicated SVE LSR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
	for _, elementBits := range []int{8, 16, 32, 64} {
		for shifts := 0; shifts < 32; shifts++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVELSRVectorPredicated(elementBits, shifts, predicate, destination)
					got, ok := decodeARM64RawSVELSR(word)
					if !ok || got.mode != arm64SVELSRVectorPredicated || got.elementBits != elementBits || got.shifts != shifts || got.predicate != predicate || got.source != destination || got.destination != destination {
						t.Fatalf("decoded vector predicated SVE LSR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for shift := 1; shift <= elementBits; shift++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVELSRImmediatePredicated(elementBits, shift, predicate, destination)
					got, ok := decodeARM64RawSVELSR(word)
					if !ok || got.mode != arm64SVELSRImmediatePredicated || got.elementBits != elementBits || got.shift != shift || got.predicate != predicate || got.source != destination || got.destination != destination {
						t.Fatalf("decoded immediate predicated SVE LSR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for shift := 1; shift <= elementBits; shift++ {
			for source := 0; source < 32; source++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVELSRImmediateUnpredicated(elementBits, shift, source, destination)
					got, ok := decodeARM64RawSVELSR(word)
					if !ok || got.mode != arm64SVELSRImmediateUnpredicated || got.elementBits != elementBits || got.shift != shift || got.source != source || got.destination != destination {
						t.Fatalf("decoded immediate unpredicated SVE LSR %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
}

func TestARM64SVELSRRejectsReservedAdjacentAndMismatchedDestructiveForms(t *testing.T) {
	for _, word := range []uint32{0x04d98400, 0x04208000, 0x04108000, 0x04008000, 0x04209000} {
		if _, ok := decodeARM64RawSVELSR(word); ok {
			t.Fatalf("SVE LSR decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsvelsr(SB),$0-0
	ZLSR $7, Z1.S, P0.M, Z2.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvelsr": {Name: "badsvelsr", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted mismatched destructive SVE LSR operands")
	}

	// The Arm encoding permits shifting by the complete element width, and the
	// raw decoder above covers it. Go 1.27's encodeShiftTriple currently rejects
	// that named boundary with v >= elemBits, so the named translator must match
	// the Go oracle instead of claiming a source form Go cannot assemble.
	const goRejectedBoundary = `
TEXT badsvelsrboundary(SB),$0-0
	ZLSR $32, Z1.S, Z2.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, goRejectedBoundary, false)
	file, err = Parse(ArchARM64, goRejectedBoundary)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvelsrboundary": {Name: "badsvelsrboundary", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted named SVE LSR element-width boundary rejected by Go 1.27")
	}
}
