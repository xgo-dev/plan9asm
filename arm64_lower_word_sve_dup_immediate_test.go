package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEDupImmediate(elementBits, immediate, shift, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x2538c000 | size<<22 | uint32(uint8(int8(immediate)))<<5 | uint32(shift/8)<<13 | uint32(destination)
}

func TestTranslateARM64SVEDupImmediateCompleteGo127Form(t *testing.T) {
	const named = `
TEXT svedupnamed(SB),$0-0
	ZDUP R0, Z14.B
	ZDUP R1, Z15.H
	ZDUP R2, Z16.S
	ZDUP RSP, Z17.D
	ZDUP Z0.B[0], Z18.B
	ZDUP Z1.B[15], Z19.B
	ZDUP Z2.H[0], Z20.H
	ZDUP Z3.H[7], Z21.H
	ZDUP Z4.S[0], Z22.S
	ZDUP Z5.S[3], Z23.S
	ZDUP Z6.D[0], Z24.D
	ZDUP Z7.D[1], Z25.D
	ZDUP Z8.Q[0], Z26.Q
	ZDUP Z9.Q[1], Z27.Q
	ZDUP $-128, Z0.B
	ZDUP $127, Z1.B
	ZDUP $-128, Z2.H
	ZDUP $127, Z3.H
	ZDUP $-32768, Z4.H
	ZDUP $32512, Z5.H
	ZDUP $-128, Z6.S
	ZDUP $127, Z7.S
	ZDUP $-32768, Z8.S
	ZDUP $32512, Z9.S
	ZDUP $-128, Z10.D
	ZDUP $127, Z11.D
	ZDUP $-32768, Z12.D
	ZDUP $32512, Z13.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT svedupraw(SB),$0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, shift := range []int{0, 8} {
			if elementBits == 8 && shift == 8 {
				continue
			}
			for _, immediate := range []int{-128, 0, 127} {
				fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEDupImmediate(elementBits, immediate, shift, (elementBits+shift+immediate)&31))
			}
		}
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	for name, source := range map[string]string{"named": named, "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svedup" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ll, err := Translate(file, Options{
						TargetTriple: triple,
						Goarch:       "arm64",
						Sigs:         map[string]FuncSig{function: {Name: function, Ret: Void}},
					})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"=`, "+sve", "<vscale x 16 x i8>", "splat (i"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE DUP immediate lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-dup-immediate.ll", "arm64-sve-dup-immediate.o", ll)
				})
			}
		})
	}
}

func encodeARM64RawSVEDupElement(elementBits, lane, source, destination int) uint32 {
	if elementBits == 128 {
		return 0x05202000 | 16<<16 | uint32(lane)<<22 | uint32(source)<<5 | uint32(destination)
	}
	size := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	imm5 := lane<<(size+1) | 1<<size
	return 0x05202000 | uint32(imm5)<<16 | uint32(source)<<5 | uint32(destination)
}

func TestARM64RawSVEDupElementDecoderCoversEveryEncodingField(t *testing.T) {
	count := 0
	for _, domain := range []struct {
		bits, lanes int
	}{{8, 16}, {16, 8}, {32, 4}, {64, 2}, {128, 2}} {
		for lane := 0; lane < domain.lanes; lane++ {
			for source := 0; source < 32; source++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEDupElement(domain.bits, lane, source, destination)
					got, ok := decodeARM64RawSVEDupElement(word)
					if !ok || got.elementBits != domain.bits || got.lane != lane || got.source != source || got.destination != destination {
						t.Fatalf("decoded SVE DUP element %#08x as %+v, ok=%v", word, got, ok)
					}
					count++
				}
			}
		}
	}
	if count != (16+8+4+2+2)*32*32 {
		t.Fatalf("covered %d SVE DUP element encodings", count)
	}
}

func TestARM64RawSVEDupElementRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{0x05202000, 0x05612000, 0x05202400} {
		if _, ok := decodeARM64RawSVEDupElement(word); ok {
			t.Fatalf("SVE DUP element decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
}

func TestARM64RawSVEDupImmediateDecoderCoversArchitecturalDomain(t *testing.T) {
	count := 0
	for _, elementBits := range []int{8, 16, 32, 64} {
		for _, shift := range []int{0, 8} {
			if elementBits == 8 && shift == 8 {
				continue
			}
			for immediate := -128; immediate <= 127; immediate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEDupImmediate(elementBits, immediate, shift, destination)
					got, ok := decodeARM64RawSVEDupImmediate(word)
					wantImmediate := immediate << shift
					if !ok || got.elementBits != elementBits || got.immediate != wantImmediate || got.destination != destination {
						t.Fatalf("decoded SVE DUP immediate word %#08x as %+v, ok=%v; want bits=%d immediate=%d destination=%d", word, got, ok, elementBits, wantImmediate, destination)
					}
					count++
				}
			}
		}
	}
	if count != 7*256*32 {
		t.Fatalf("covered %d SVE DUP immediate encodings, want %d", count, 7*256*32)
	}
}

func TestARM64RawSVEDupImmediateDecoderRejectsReservedAndAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		encodeARM64RawSVEDupImmediate(8, 1, 8, 0), // The shifted byte form is reserved.
		0x25388000, // Neighboring SVE broadcast class.
		0x2539c000, // Neighboring SVE instruction class.
	} {
		if _, ok := decodeARM64RawSVEDupImmediate(word); ok {
			t.Fatalf("SVE DUP immediate decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
}
