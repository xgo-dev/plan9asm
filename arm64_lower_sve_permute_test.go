package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVEPermuteOps = []Op{"ZZIP1", "ZZIP2", "ZUZP1", "ZUZP2", "ZTRN1", "ZTRN2"}

func encodeARM64RawSVEPermute(op Op, elementBits, second, first, destination int) uint32 {
	selector := 0
	for index, candidate := range arm64SVEPermuteOps {
		if op == candidate {
			selector = index
			break
		}
	}
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x05206000 | size<<22 | uint32(selector)<<10 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEPermuteQ(op Op, second, first, destination int) uint32 {
	selector := 0
	for index, candidate := range arm64SVEPermuteOps {
		if op == candidate {
			selector = index
			if selector >= 4 {
				selector += 2
			}
			break
		}
	}
	return 0x05a00000 | uint32(selector)<<10 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func TestTranslateARM64RawSVEPermuteReportedEncoding(t *testing.T) {
	const source = "TEXT svetrn2reported(SB),$0-0\n\tWORD $0x05e47490\n\tRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"svetrn2reported": {Name: "svetrn2reported", Ret: Void}}}); err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64SVEPermuteCompleteGo127Forms(t *testing.T) {
	var named strings.Builder
	named.WriteString("TEXT svepermutednamed(SB),$0-0\n")
	for _, op := range arm64SVEPermuteOps {
		fmt.Fprintf(&named, "\t%s Z2.B, Z1.B, Z0.B\n", op)
		fmt.Fprintf(&named, "\t%s Z4.H, Z3.H, Z0.H\n", op)
		fmt.Fprintf(&named, "\t%s Z6.S, Z5.S, Z0.S\n", op)
		fmt.Fprintf(&named, "\t%s Z8.D, Z7.D, Z0.D\n", op)
		fmt.Fprintf(&named, "\t%s Z10.Q, Z9.Q, Z0.Q\n", op)
	}
	named.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, named.String(), true)

	var raw strings.Builder
	raw.WriteString("TEXT svepermutedraw(SB),$0-0\n")
	for _, op := range arm64SVEPermuteOps {
		for _, elementBits := range []int{8, 16, 32, 64} {
			fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEPermute(op, elementBits, 2, 1, 0))
		}
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEPermuteQ(op, 10, 9, 0))
	}
	raw.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, raw.String(), true)

	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for name, source := range map[string]string{"named": named.String(), "raw": raw.String()} {
		t.Run(name, func(t *testing.T) {
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			function := "svepermuted" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+f64mm,+sve"`, "@llvm.aarch64.sve.zip1.nxv", "@llvm.aarch64.sve.uzp2.nxv", "@llvm.aarch64.sve.trn2.nxv", "@llvm.aarch64.sve.trn1q.nxv2i64"} {
						if !strings.Contains(ir, want) {
							t.Fatalf("SVE permute lowering omitted %q:\n%s", want, ir)
						}
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-permute.ll", "arm64-sve-permute.o", ir)
				})
			}
		})
	}
}

func TestARM64RawSVEPermuteDecoderCoversEveryEncodingField(t *testing.T) {
	for _, op := range arm64SVEPermuteOps {
		for _, elementBits := range []int{8, 16, 32, 64} {
			for second := 0; second < 32; second++ {
				for first := 0; first < 32; first++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVEPermute(op, elementBits, second, first, destination)
						got, ok := decodeARM64RawSVEPermute(word)
						if !ok || got.op != op || got.elementBits != elementBits || got.quad || got.second != second || got.first != first || got.destination != destination {
							t.Fatalf("decoded SVE permute %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
		for second := 0; second < 32; second++ {
			for first := 0; first < 32; first++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEPermuteQ(op, second, first, destination)
					got, ok := decodeARM64RawSVEPermute(word)
					if !ok || got.op != op || !got.quad || got.elementBits != 128 || got.second != second || got.first != first || got.destination != destination {
						t.Fatalf("decoded SVE Q permute %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
}

func TestARM64SVEPermuteRejectsAdjacentAndInvalidForms(t *testing.T) {
	for _, word := range []uint32{
		0x05206000 | 6<<10,
		0x05206000 | 7<<10,
		0x05a00000 | 4<<10,
		0x05a00000 | 5<<10,
	} {
		if _, ok := decodeARM64RawSVEPermute(word); ok {
			t.Fatalf("SVE permute decoder accepted adjacent encoding %#08x", word)
		}
	}
	const invalid = "TEXT badsvepermute(SB),$0-0\n\tZTRN2 Z1.B, Z2.H, Z3.B\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, invalid, false)
}
