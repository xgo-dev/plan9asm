package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVELDST1D(load bool, immediate, predicate, base, vector int) uint32 {
	opcode := uint32(0xe5e0e000)
	if load {
		opcode = 0xa5e0a000
	}
	return opcode | uint32(immediate&15)<<16 | uint32(predicate)<<10 | uint32(base)<<5 | uint32(vector)
}

func TestTranslateARM64RawSVELDST1DScalarImmediateCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawldst1dforms(SB),$0-0\n")
	for _, load := range []bool{true, false} {
		for immediate := -8; immediate <= 7; immediate++ {
			fmt.Fprintf(&source, "\tWORD $%#08x\n", encodeARM64RawSVELDST1D(load, immediate, (immediate+8)%8, 2, 3))
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawldst1dforms": {Name: "rawldst1dforms", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve"`,
				"@llvm.aarch64.sve.convert.from.svbool.nxv2i1",
				"call <vscale x 2 x i64> @llvm.aarch64.sve.ld1.nxv2i64",
				"@llvm.masked.store.nxv2i64.p0", "call i64 @llvm.vscale.i64()",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SVE LD1D/ST1D lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-ldst1d.ll", "arm64-raw-sve-ldst1d.o", ll)
		})
	}
}

func TestARM64RawSVELDST1DDecoderCoversAllEncodingFields(t *testing.T) {
	for _, load := range []bool{true, false} {
		for immediate := -8; immediate <= 7; immediate++ {
			for predicate := 0; predicate < 8; predicate++ {
				for base := 0; base < 32; base++ {
					for vector := 0; vector < 32; vector++ {
						word := encodeARM64RawSVELDST1D(load, immediate, predicate, base, vector)
						got, ok := decodeARM64RawSVELDST1D(word)
						if !ok || got.load != load || got.immediate != immediate || got.predicate != predicate || got.base != base || got.vector != vector {
							t.Fatalf("decoded SVE LD1D/ST1D word %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}

func TestARM64RawSVELDST1DDecoderRejectsAdjacentAddressingClasses(t *testing.T) {
	for _, word := range []uint32{0xa5a04000, 0xc5e0c000, 0xe5a0c000} {
		if _, ok := decodeARM64RawSVELDST1D(word); ok {
			t.Fatalf("SVE LD1D/ST1D decoder accepted adjacent encoding %#08x", word)
		}
	}
}

func encodeARM64RawSVELDST1DScalarRegister(load bool, index, predicate, base, vector int) uint32 {
	opcode := uint32(0xe5e04000)
	if load {
		opcode = 0xa5e04000
	}
	return opcode | uint32(index)<<16 | uint32(predicate)<<10 | uint32(base)<<5 | uint32(vector)
}

func TestTranslateARM64RawSVELDST1DScalarRegisterCompleteFormat(t *testing.T) {
	const source = `TEXT rawldst1dregister(SB),$0-0
	WORD $0xa5ef40c1 // ld1d {z1.d}, p0/z, [x6,x15,lsl#3]
	WORD $0xe5ef40c0 // st1d {z0.d}, p0, [x6,x15,lsl#3]
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"rawldst1dregister": {Name: "rawldst1dregister", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"shl i64", "call <vscale x 2 x i64> @llvm.aarch64.sve.ld1.nxv2i64", "@llvm.masked.store.nxv2i64.p0", `"target-features"="+sve"`} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw SVE register-offset LD1D/ST1D lowering for %s omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-ldst1d-register.ll", "arm64-raw-sve-ldst1d-register.o", ll)
		})
	}
}

func TestARM64RawSVELDST1DScalarRegisterDecoderCoversAllFields(t *testing.T) {
	for _, load := range []bool{false, true} {
		for index := 0; index < 32; index++ {
			for predicate := 0; predicate < 8; predicate++ {
				for base := 0; base < 32; base++ {
					for vector := 0; vector < 32; vector++ {
						word := encodeARM64RawSVELDST1DScalarRegister(load, index, predicate, base, vector)
						got, ok := decodeARM64RawSVELDST1D(word)
						if !ok || got.load != load || !got.registerOffset || got.index != index || got.predicate != predicate || got.base != base || got.vector != vector {
							t.Fatalf("decoded register-offset SVE LD1D/ST1D %#08x as %+v, ok=%v", word, got, ok)
						}
					}
				}
			}
		}
	}
}
