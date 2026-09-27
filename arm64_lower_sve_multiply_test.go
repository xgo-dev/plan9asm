package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEMultiplyPredicated(elementBits, second, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04100000 | size<<22 | uint32(second)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVEMultiplyUnpredicated(elementBits, second, first, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04206000 | size<<22 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEMultiplyLane(elementBits, laneVector, lane, first, destination int) uint32 {
	word := uint32(0x44e0f800)
	switch elementBits {
	case 16:
		word = 0x4420f800 | uint32(laneVector)<<16 | uint32(lane&3)<<19 | uint32(lane>>2)<<22
	case 32:
		word = 0x44a0f800 | uint32(laneVector)<<16 | uint32(lane)<<19
	case 64:
		word |= uint32(laneVector)<<16 | uint32(lane)<<20
	}
	return word | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEMultiplyImmediate(elementBits, immediate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x2530c000 | size<<22 | uint32(uint8(int8(immediate)))<<5 | uint32(destination)
}

func TestTranslateARM64SVEMultiplyCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT svemulnamed(SB),$0-0
	ZMUL Z31.B, Z0.B, P0.M, Z0.B
	ZMUL Z30.H, Z1.H, P1.M, Z1.H
	ZMUL Z29.S, Z2.S, P2.M, Z2.S
	ZMUL Z28.D, Z3.D, P7.M, Z3.D
	ZMUL Z27.B, Z4.B, Z5.B
	ZMUL Z26.H, Z6.H, Z7.H
	ZMUL Z25.S, Z8.S, Z9.S
	ZMUL Z24.D, Z10.D, Z11.D
	ZMUL Z7.H[7], Z12.H, Z13.H
	ZMUL Z6.S[3], Z14.S, Z15.S
	ZMUL Z15.D[1], Z16.D, Z17.D
	ZMUL $-128, Z18.B, Z18.B
	ZMUL $127, Z19.H, Z19.H
	ZMUL $-1, Z20.S, Z20.S
	ZMUL $0, Z21.D, Z21.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT svemulraw(SB),$0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyPredicated(elementBits, 1, 2, 3))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyUnpredicated(elementBits, 4, 5, 6))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyImmediate(elementBits, -128+elementBits, 7))
	}
	for _, form := range []struct{ bits, vector, lane int }{{16, 7, 7}, {32, 7, 3}, {64, 15, 1}} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyLane(form.bits, form.vector, form.lane, 8, 9))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svemul" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.mul.nxv", "@llvm.aarch64.sve.mul.lane.nxv", " mul <vscale x "} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE MUL lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-multiply.ll", "arm64-sve-multiply.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVEMultiplyDecoderCoversEveryEncodingField(t *testing.T) {
	for _, elementBits := range []int{8, 16, 32, 64} {
		for second := 0; second < 32; second++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEMultiplyPredicated(elementBits, second, predicate, destination)
					got, ok := decodeARM64RawSVEMultiply(word)
					if !ok || got.mode != arm64SVEMultiplyPredicated || got.elementBits != elementBits || got.second != second || got.first != destination || got.predicate != predicate || got.destination != destination {
						t.Fatalf("decoded predicated SVE MUL %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for second := 0; second < 32; second++ {
			for first := 0; first < 32; first++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEMultiplyUnpredicated(elementBits, second, first, destination)
					got, ok := decodeARM64RawSVEMultiply(word)
					if !ok || got.mode != arm64SVEMultiplyUnpredicated || got.elementBits != elementBits || got.second != second || got.first != first || got.destination != destination {
						t.Fatalf("decoded unpredicated SVE MUL %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for immediate := -128; immediate <= 127; immediate++ {
			for destination := 0; destination < 32; destination++ {
				word := encodeARM64RawSVEMultiplyImmediate(elementBits, immediate, destination)
				got, ok := decodeARM64RawSVEMultiply(word)
				if !ok || got.mode != arm64SVEMultiplyImmediate || got.elementBits != elementBits || got.immediate != immediate || got.first != destination || got.destination != destination {
					t.Fatalf("decoded immediate SVE MUL %#08x as %+v, ok=%v", word, got, ok)
				}
			}
		}
	}
	for _, domain := range []struct{ bits, vectors, lanes int }{{16, 8, 8}, {32, 8, 4}, {64, 16, 2}} {
		for laneVector := 0; laneVector < domain.vectors; laneVector++ {
			for lane := 0; lane < domain.lanes; lane++ {
				for first := 0; first < 32; first++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVEMultiplyLane(domain.bits, laneVector, lane, first, destination)
						got, ok := decodeARM64RawSVEMultiply(word)
						if !ok || got.mode != arm64SVEMultiplyLane || got.elementBits != domain.bits || got.laneVector != laneVector || got.lane != lane || got.first != first || got.destination != destination {
							t.Fatalf("decoded lane SVE MUL %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}

func TestARM64SVEMultiplyRejectsAdjacentAndInvalidForms(t *testing.T) {
	for _, word := range []uint32{0x04110000, 0x04206400, 0x2531c000, 0x4420fc00} {
		if _, ok := decodeARM64RawSVEMultiply(word); ok {
			t.Fatalf("SVE MUL decoder accepted adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsvemul(SB),$0-0
	ZMUL Z1.S, Z2.S, P0.M, Z3.S
	ZMUL Z8.H[0], Z2.H, Z3.H
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemul": {Name: "badsvemul", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted invalid SVE MUL forms")
	}
}
