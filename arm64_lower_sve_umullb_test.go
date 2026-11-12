package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEUMULLBVector(sourceBits, second, first, destination int) uint32 {
	size := map[int]uint32{8: 1, 16: 2, 32: 3}[sourceBits]
	return 0x45007800 | size<<22 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEUMULLBLane(sourceBits, laneVector, lane, first, destination int) uint32 {
	base := uint32(0x44a0d000)
	if sourceBits == 16 {
		return base | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<19 | uint32(first)<<5 | uint32(destination)
	}
	return 0x44e0d000 | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<20 | uint32(first)<<5 | uint32(destination)
}

func TestTranslateARM64SVEUMULLBCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT sveumullbnamed(SB),$0-0
	ZUMULLB Z31.B, Z30.B, Z29.H
	ZUMULLB Z28.H, Z27.H, Z26.S
	ZUMULLB Z25.S, Z24.S, Z23.D
	ZUMULLB Z7.H[7], Z22.H, Z21.S
	ZUMULLB Z15.S[3], Z20.S, Z19.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT sveumullbraw(SB),$0-0\n")
	for _, sourceBits := range []int{8, 16, 32} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEUMULLBVector(sourceBits, 1, 2, 3))
	}
	fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEUMULLBLane(16, 7, 7, 4, 5))
	fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEUMULLBLane(32, 15, 3, 6, 7))
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "sveumullb" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.umullb.nxv", "@llvm.aarch64.sve.umullb.lane.nxv"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE UMULLB lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-umullb.ll", "arm64-sve-umullb.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVEUMULLBDecoderCoversEveryEncodingField(t *testing.T) {
	for _, sourceBits := range []int{8, 16, 32} {
		for second := 0; second < 32; second++ {
			for first := 0; first < 32; first++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEUMULLBVector(sourceBits, second, first, destination)
					got, ok := decodeARM64RawSVEUMULLB(word)
					if !ok || got.mode != arm64SVEUMULLBVector || got.sourceBits != sourceBits || got.second != second || got.first != first || got.destination != destination {
						t.Fatalf("decoded vector SVE UMULLB %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
	for _, domain := range []struct{ bits, vectors, lanes int }{{16, 8, 8}, {32, 16, 4}} {
		for laneVector := 0; laneVector < domain.vectors; laneVector++ {
			for lane := 0; lane < domain.lanes; lane++ {
				for first := 0; first < 32; first++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVEUMULLBLane(domain.bits, laneVector, lane, first, destination)
						got, ok := decodeARM64RawSVEUMULLB(word)
						if !ok || got.mode != arm64SVEUMULLBLane || got.sourceBits != domain.bits || got.laneVector != laneVector || got.lane != lane || got.first != first || got.destination != destination {
							t.Fatalf("decoded lane SVE UMULLB %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}

func TestARM64SVEUMULLBRejectsReservedAndAdjacentForms(t *testing.T) {
	for _, word := range []uint32{0x45007800, 0x45007c00, 0x44a0f000, 0x44e0f000} {
		if _, ok := decodeARM64RawSVEUMULLB(word); ok {
			t.Fatalf("SVE UMULLB decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsveumullb(SB),$0-0
	ZUMULLB Z8.H[0], Z1.H, Z2.S
	ZUMULLB Z1.S, Z2.S, Z3.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveumullb": {Name: "badsveumullb", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted invalid SVE UMULLB forms")
	}
}
