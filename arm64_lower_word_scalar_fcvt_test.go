package plan9asm

import (
	"strings"
	"testing"
)

func TestARM64RawScalarFCVTToIntDecoderCompleteFamily(t *testing.T) {
	bases := map[arm64FloatToIntegerRounding]uint32{
		arm64FloatRoundNearestEven: 0x1e200000,
		arm64FloatRoundTiesAway:    0x1e240000,
		arm64FloatRoundPlusInf:     0x1e280000,
		arm64FloatRoundMinusInf:    0x1e300000,
		arm64FloatRoundZero:        0x1e380000,
	}
	for rounding, base := range bases {
		for _, unsigned := range []bool{false, true} {
			for _, source := range []struct {
				code uint32
				bits int
			}{{0, 32}, {1, 64}, {3, 16}} {
				for _, destinationBits := range []int{32, 64} {
					word := base | source.code<<22 | 7<<5 | 11
					if unsigned {
						word |= 1 << 16
					}
					if destinationBits == 64 {
						word |= 1 << 31
					}
					form, ok := decodeARM64RawScalarFCVTToInt(word)
					if !ok {
						t.Fatalf("decoder rejected scalar FCVT word %#08x", word)
					}
					if form.rounding != rounding || form.unsigned != unsigned ||
						form.sourceBits != source.bits || form.destinationBits != destinationBits ||
						form.source != 7 || form.destination != 11 {
						t.Fatalf("decoder returned the wrong form for %#08x: %+v", word, form)
					}
				}
			}
		}
	}
}

func TestTranslateARM64RawScalarFCVTToIntCompleteFamily(t *testing.T) {
	const source = `TEXT rawscalarfcvt(SB),$0-0
	WORD $0x1e200020 // FCVTNS S1, W0
	WORD $0x9e610062 // FCVTNU D3, X2
	WORD $0x1e240023 // FCVTAS S1, W3 (external corpus form)
	WORD $0x9ee500a4 // FCVTAU H5, X4
	WORD $0x9e2800e6 // FCVTPS S7, X6
	WORD $0x1e690128 // FCVTPU D9, W8
	WORD $0x9e70016a // FCVTMS D11, X10
	WORD $0x1e3101ac // FCVTMU S13, W12
	WORD $0x1ef801ee // FCVTZS H15, W14
	WORD $0x9e790230 // FCVTZU D17, X16
	RET
`
	requireARM64GoAssemblerResult(t, source, true)
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{
		"arm64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs:         map[string]FuncSig{"rawscalarfcvt": {Name: "rawscalarfcvt", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				"@llvm.roundeven.f32", "@llvm.round.f16", "@llvm.ceil.f32", "@llvm.ceil.f64",
				"@llvm.floor.f32", "@llvm.floor.f64", "@llvm.fptosi.sat.i32.f16",
				"@llvm.fptosi.sat.i32.f32", "@llvm.fptosi.sat.i64.f32",
				"@llvm.fptoui.sat.i32.f32", "@llvm.fptoui.sat.i64.f64",
				`"target-features"="+fullfp16"`,
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("ARM64 raw scalar FCVT lowering omitted %q:\n%s", want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-scalar-fcvt.ll", "arm64-raw-scalar-fcvt.o", ll)
		})
	}
}

func TestARM64RawScalarFCVTToIntDecoderRejectsAdjacentEncodings(t *testing.T) {
	for _, word := range []uint32{
		0x1e220020, // SCVTF S1, W0.
		0x1e240420, // Fixed-point scale bits are not part of this family.
		0x1ea40020, // Reserved floating source type.
		0x5e21a820, // Advanced SIMD FCVTNS.
	} {
		if form, ok := decodeARM64RawScalarFCVTToInt(word); ok {
			t.Fatalf("decoder accepted adjacent encoding %#08x as %+v", word, form)
		}
	}
}
