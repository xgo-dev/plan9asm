package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEAddUnpredicated(elementBits, second, first, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04200000 | size<<22 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEAddPredicated(elementBits, second, predicate, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x04000000 | size<<22 | uint32(second)<<5 | uint32(predicate)<<10 | uint32(destination)
}

func encodeARM64RawSVEAddImmediate(elementBits, immediate, shift, destination int) uint32 {
	size := map[int]uint32{8: 0, 16: 1, 32: 2, 64: 3}[elementBits]
	return 0x2520c000 | size<<22 | uint32(immediate)<<5 | uint32(shift/8)<<13 | uint32(destination)
}

func TestTranslateARM64SVEAddCompleteGo127Forms(t *testing.T) {
	const named = `
TEXT sveaddnamed(SB),$0-0
	ZADD Z31.B, Z0.B, Z1.B
	ZADD Z30.H, Z2.H, Z3.H
	ZADD Z29.S, Z4.S, Z5.S
	ZADD Z28.D, Z6.D, Z7.D
	ZADD Z27.B, Z8.B, P0.M, Z8.B
	ZADD Z26.H, Z9.H, P1.M, Z9.H
	ZADD Z25.S, Z10.S, P2.M, Z10.S
	ZADD Z24.D, Z11.D, P7.M, Z11.D
	ZADD $255, Z12.B, Z12.B
	ZADD $65280, Z13.H, Z13.H
	ZADD $65280, Z14.S, Z14.S
	ZADD $65280, Z15.D, Z15.D
	RET
`
	requireARM64SVEGoAssemblerResult(t, named, true)

	var raw strings.Builder
	raw.WriteString("TEXT sveaddraw(SB),$0-0\n")
	for _, elementBits := range []int{8, 16, 32, 64} {
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEAddUnpredicated(elementBits, 2, 3, 4))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEAddPredicated(elementBits, 5, 6, 7))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEAddImmediate(elementBits, 255, 0, 8))
		if elementBits != 8 {
			fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEAddImmediate(elementBits, 255, 8, 9))
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
			function := "sveadd" + name
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
					for _, want := range []string{`"target-features"="+sve"`, " add <vscale x ", " select <vscale x ", "@llvm.aarch64.sve.convert.from.svbool"} {
						if !strings.Contains(ll, want) {
							t.Fatalf("ARM64 SVE ADD lowering for %s/%s omitted %q:\n%s", name, triple, want, ll)
						}
					}
					llc := findLLVM22Tool("llc")
					if llc == "" {
						t.Fatal("LLVM 22 llc not found")
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-add.ll", "arm64-sve-add.o", ll)
				})
			}
		})
	}
}

func TestARM64RawSVEAddDecoderCoversEveryEncodingField(t *testing.T) {
	for _, elementBits := range []int{8, 16, 32, 64} {
		for second := 0; second < 32; second++ {
			for first := 0; first < 32; first++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEAddUnpredicated(elementBits, second, first, destination)
					got, ok := decodeARM64RawSVEAdd(word)
					if !ok || got.mode != arm64SVEAddUnpredicated || got.elementBits != elementBits || got.second != second || got.first != first || got.destination != destination {
						t.Fatalf("decoded unpredicated SVE ADD %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for second := 0; second < 32; second++ {
			for predicate := 0; predicate < 8; predicate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEAddPredicated(elementBits, second, predicate, destination)
					got, ok := decodeARM64RawSVEAdd(word)
					if !ok || got.mode != arm64SVEAddPredicated || got.elementBits != elementBits || got.second != second || got.predicate != predicate || got.first != destination || got.destination != destination {
						t.Fatalf("decoded predicated SVE ADD %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
		for _, shift := range []int{0, 8} {
			if elementBits == 8 && shift == 8 {
				continue
			}
			for immediate := 0; immediate <= 255; immediate++ {
				for destination := 0; destination < 32; destination++ {
					word := encodeARM64RawSVEAddImmediate(elementBits, immediate, shift, destination)
					got, ok := decodeARM64RawSVEAdd(word)
					if !ok || got.mode != arm64SVEAddImmediate || got.elementBits != elementBits || got.immediate != immediate<<shift || got.first != destination || got.destination != destination {
						t.Fatalf("decoded immediate SVE ADD %#08x as %+v, ok=%v", word, got, ok)
					}
				}
			}
		}
	}
}

func TestARM64SVEAddRejectsReservedAdjacentAndNonDestructivePredicatedForms(t *testing.T) {
	if _, ok := decodeARM64RawSVEAdd(encodeARM64RawSVEAddImmediate(8, 1, 8, 0)); ok {
		t.Fatal("SVE ADD decoder accepted reserved shifted byte immediate")
	}
	for _, word := range []uint32{0x04010000, 0x04200400, 0x2521c000} {
		if _, ok := decodeARM64RawSVEAdd(word); ok {
			t.Fatalf("SVE ADD decoder accepted adjacent encoding %#08x", word)
		}
	}
	const invalid = `
TEXT badsveadd(SB),$0-0
	ZADD Z1.S, Z2.S, P0.M, Z3.S
	RET
`
	requireARM64SVEGoAssemblerResult(t, invalid, false)
	file, err := Parse(ArchARM64, invalid)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsveadd": {Name: "badsveadd", Ret: Void}}}); err == nil {
		t.Fatal("translator accepted a predicated SVE ADD whose destructive operands differ")
	}
}
