package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

var arm64SVEMultiplyAccumulateLongOps = []Op{
	"ZSMLALB", "ZSMLALT", "ZUMLALB", "ZUMLALT",
	"ZSMLSLB", "ZSMLSLT", "ZUMLSLB", "ZUMLSLT",
}

func encodeARM64RawSVEMultiplyAccumulateLongVector(op Op, sourceBits, second, first, destination int) uint32 {
	selector := arm64SVEMultiplyAccumulateLongSelector(op)
	size := map[int]uint32{8: 1, 16: 2, 32: 3}[sourceBits]
	return 0x44004000 | size<<22 | uint32(second)<<16 | uint32(selector)<<10 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEMultiplyAccumulateLongLane(op Op, sourceBits, laneVector, lane, first, destination int) uint32 {
	selector := arm64SVEMultiplyAccumulateLongSelector(op)
	opBits := uint32(selector&1)<<10 | uint32(selector&6)<<11
	if sourceBits == 16 {
		return 0x44a08000 | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<19 | opBits | uint32(first)<<5 | uint32(destination)
	}
	return 0x44e08000 | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<20 | opBits | uint32(first)<<5 | uint32(destination)
}

func arm64SVEMultiplyAccumulateLongSelector(op Op) int {
	for selector, candidate := range arm64SVEMultiplyAccumulateLongOps {
		if op == candidate {
			return selector
		}
	}
	panic("unknown SVE multiply-accumulate-long op " + op)
}

func TestTranslateARM64RawSVEUMLALBReportedEncoding(t *testing.T) {
	const source = "TEXT sveumlalbreported(SB),$0-0\n\tWORD $0x44d24a20\n\tRET\n"
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"sveumlalbreported": {Name: "sveumlalbreported", Ret: Void}}}); err != nil {
		t.Fatal(err)
	}
}

func TestTranslateARM64SVEMultiplyAccumulateLongCompleteGo127Forms(t *testing.T) {
	var named strings.Builder
	named.WriteString("TEXT svemlalnamed(SB),$0-0\n")
	for _, op := range arm64SVEMultiplyAccumulateLongOps {
		fmt.Fprintf(&named, "\t%s Z2.B, Z1.B, Z0.H\n", op)
		fmt.Fprintf(&named, "\t%s Z4.H, Z3.H, Z0.S\n", op)
		fmt.Fprintf(&named, "\t%s Z6.S, Z5.S, Z0.D\n", op)
		fmt.Fprintf(&named, "\t%s Z7.H[7], Z8.H, Z0.S\n", op)
		fmt.Fprintf(&named, "\t%s Z15.S[3], Z9.S, Z0.D\n", op)
	}
	named.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, named.String(), true)

	var raw strings.Builder
	raw.WriteString("TEXT svemlalraw(SB),$0-0\n")
	for _, op := range arm64SVEMultiplyAccumulateLongOps {
		for _, sourceBits := range []int{8, 16, 32} {
			fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyAccumulateLongVector(op, sourceBits, 2, 1, 0))
		}
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyAccumulateLongLane(op, 16, 7, 7, 8, 0))
		fmt.Fprintf(&raw, "\tWORD $%#08x\n", encodeARM64RawSVEMultiplyAccumulateLongLane(op, 32, 15, 3, 9, 0))
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
			function := "svemlal" + name
			for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
				t.Run(triple, func(t *testing.T) {
					ir, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{function: {Name: function, Ret: Void}}})
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range []string{`"target-features"="+sve,+sve2"`, "@llvm.aarch64.sve.smlalb", "@llvm.aarch64.sve.umlalt", "@llvm.aarch64.sve.smlslt", "@llvm.aarch64.sve.umlslb.lane"} {
						if !strings.Contains(ir, want) {
							t.Fatalf("SVE2 multiply-accumulate-long lowering omitted %q:\n%s", want, ir)
						}
					}
					compileLLVMToObject(t, llc, triple, "arm64-sve-mlal.ll", "arm64-sve-mlal.o", ir)
				})
			}
		})
	}
}

func TestARM64RawSVEMultiplyAccumulateLongDecoderCoversEveryEncodingField(t *testing.T) {
	for _, op := range arm64SVEMultiplyAccumulateLongOps {
		for _, sourceBits := range []int{8, 16, 32} {
			for second := 0; second < 32; second++ {
				for first := 0; first < 32; first++ {
					for destination := 0; destination < 32; destination++ {
						word := encodeARM64RawSVEMultiplyAccumulateLongVector(op, sourceBits, second, first, destination)
						got, ok := decodeARM64RawSVEMultiplyAccumulateLong(word)
						if !ok || got.op != op || got.mode != arm64SVEUMULLBVector || got.sourceBits != sourceBits || got.second != second || got.first != first || got.destination != destination {
							t.Fatalf("decoded vector %#08x as %+v, ok=%v", word, got, ok)
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
							word := encodeARM64RawSVEMultiplyAccumulateLongLane(op, domain.bits, laneVector, lane, first, destination)
							got, ok := decodeARM64RawSVEMultiplyAccumulateLong(word)
							if !ok || got.op != op || got.mode != arm64SVEUMULLBLane || got.sourceBits != domain.bits || got.laneVector != laneVector || got.lane != lane || got.first != first || got.destination != destination {
								t.Fatalf("decoded lane %#08x as %+v, ok=%v", word, got, ok)
							}
						}
					}
				}
			}
		}
	}
}

func TestARM64SVEMultiplyAccumulateLongRejectsReservedAndInvalidForms(t *testing.T) {
	for _, word := range []uint32{0x44004000, 0x44006000, 0x44a0c000, 0x44e0c000} {
		if _, ok := decodeARM64RawSVEMultiplyAccumulateLong(word); ok {
			t.Fatalf("decoder accepted reserved/adjacent encoding %#08x", word)
		}
	}
	const invalid = "TEXT badsvemlal(SB),$0-0\n\tZUMLALB Z1.B[0], Z2.B, Z3.H\n\tZUMLALB Z1.S, Z2.S, Z3.S\n\tRET\n"
	requireARM64SVEGoAssemblerResult(t, invalid, false)
}
