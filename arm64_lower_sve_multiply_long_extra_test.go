package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func encodeARM64RawSVEMultiplyLongVector(op Op, sourceBits, second, first, destination int) uint32 {
	spec := arm64SVEMultiplyLongSpecs[op]
	size := map[int]uint32{8: 1, 16: 2, 32: 3}[sourceBits]
	return spec.vectorBase | size<<22 | uint32(second)<<16 | uint32(first)<<5 | uint32(destination)
}

func encodeARM64RawSVEMultiplyLongLane(op Op, sourceBits, laneVector, lane, first, destination int) uint32 {
	spec := arm64SVEMultiplyLongSpecs[op]
	if sourceBits == 16 {
		return spec.laneHBase | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<19 | uint32(first)<<5 | uint32(destination)
	}
	return spec.laneSBase | uint32(laneVector)<<16 | uint32(lane&1)<<11 | uint32(lane>>1)<<20 | uint32(first)<<5 | uint32(destination)
}

func TestTranslateARM64SVEMultiplyLongExtraCompleteGo127Family(t *testing.T) {
	regular := []string{
		"ZSMULLB", "ZSMULLT", "ZUMULLT",
		"ZSQDMULLB", "ZSQDMULLT",
		"ZSQDMLALB", "ZSQDMLALT",
		"ZSQDMLSLB", "ZSQDMLSLT",
	}
	bottomTop := []string{"ZSQDMLALBT", "ZSQDMLSLBT"}
	widths := []struct {
		source, destination string
	}{{"B", "H"}, {"H", "S"}, {"S", "D"}}

	var source strings.Builder
	source.WriteString("TEXT svemultiplylongextra(SB),$0-0\n")
	for _, op := range regular {
		for _, width := range widths {
			fmt.Fprintf(&source, "\t%s Z1.%s, Z2.%s, Z3.%s\n", op, width.source, width.source, width.destination)
		}
		fmt.Fprintf(&source, "\t%s Z7.H[7], Z4.H, Z5.S\n", op)
		fmt.Fprintf(&source, "\t%s Z15.S[3], Z6.S, Z7.D\n", op)
	}
	for _, op := range bottomTop {
		for _, width := range widths {
			fmt.Fprintf(&source, "\t%s Z8.%s, Z9.%s, Z10.%s\n", op, width.source, width.source, width.destination)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64SVEGoAssemblerResult(t, source.String(), true)

	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemultiplylongextra": {Name: "svemultiplylongextra", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{
				`"target-features"="+sve,+sve2"`,
				"@llvm.aarch64.sve.smullb.",
				"@llvm.aarch64.sve.umullt.lane.",
				"@llvm.aarch64.sve.sqdmullt.",
				"@llvm.aarch64.sve.sqdmlalb.lane.",
				"@llvm.aarch64.sve.sqdmlslbt.",
			} {
				if !strings.Contains(ll, want) {
					t.Fatalf("%s SVE multiply-long lowering omitted %q:\n%s", triple, want, ll)
				}
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-multiply-long-extra.ll", "arm64-sve-multiply-long-extra.o", ll)
		})
	}
}

func TestTranslateARM64SVEMultiplyLongExtraRejectsFormsOutsideGo127Table(t *testing.T) {
	for _, instruction := range []string{
		"ZSMULLB Z1.D, Z2.D, Z3.Q",
		"ZSMULLT Z8.H[0], Z1.H, Z2.S",
		"ZUMULLT Z1.H, Z2.H, Z3.D",
		"ZSQDMULLB Z1.B[0], Z2.B, Z3.H",
		"ZSQDMLALBT Z1.H[0], Z2.H, Z3.S",
		"ZSQDMLSLBT Z1.B, Z2.B, Z3.S",
		"ZSQDMLALT.Z Z1.B, Z2.B, Z3.H",
	} {
		t.Run(strings.NewReplacer(" ", "_", ".", "_", ",", "_").Replace(instruction), func(t *testing.T) {
			source := "TEXT badsvemultiplylongextra(SB),$0-0\n\t" + instruction + "\n\tRET\n"
			requireARM64SVEGoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			if _, err := Translate(file, Options{TargetTriple: "aarch64-unknown-linux-gnu", Goarch: "arm64", Sigs: map[string]FuncSig{"badsvemultiplylongextra": {Name: "badsvemultiplylongextra", Ret: Void}}}); err == nil {
				t.Fatalf("Translate accepted %q outside Go 1.27's SVE multiply-long forms", instruction)
			}
		})
	}
}

func TestTranslateARM64SVEMultiplyLongRawEncodings(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT svemultiplylongraw(SB),$0-0\n")
	for _, op := range arm64SVEMultiplyLongOps {
		spec := arm64SVEMultiplyLongSpecs[op]
		for _, sourceBits := range []int{8, 16, 32} {
			word := encodeARM64RawSVEMultiplyLongVector(op, sourceBits, 1, 2, 3)
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			got, ok := decodeARM64RawSVEUMULLB(word)
			if !ok || got.op != op || got.mode != arm64SVEUMULLBVector || got.sourceBits != sourceBits || got.second != 1 || got.first != 2 || got.destination != 3 {
				t.Fatalf("decoded vector %s %#08x as %+v, ok=%v", op, word, got, ok)
			}
		}
		if spec.laneHBase == 0 {
			continue
		}
		for _, domain := range []struct {
			bits, vector, lane int
		}{{16, 7, 7}, {32, 15, 3}} {
			word := encodeARM64RawSVEMultiplyLongLane(op, domain.bits, domain.vector, domain.lane, 4, 5)
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
			got, ok := decodeARM64RawSVEUMULLB(word)
			if !ok || got.op != op || got.mode != arm64SVEUMULLBLane || got.sourceBits != domain.bits || got.laneVector != domain.vector || got.lane != domain.lane || got.first != 4 || got.destination != 5 {
				t.Fatalf("decoded indexed %s %#08x as %+v, ok=%v", op, word, got, ok)
			}
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
			ll, err := Translate(file, Options{TargetTriple: triple, Goarch: "arm64", Sigs: map[string]FuncSig{"svemultiplylongraw": {Name: "svemultiplylongraw", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			llc := findLLVM22Tool("llc")
			if llc == "" {
				t.Fatal("LLVM 22 llc not found")
			}
			compileLLVMToObject(t, llc, triple, "arm64-sve-multiply-long-raw.ll", "arm64-sve-multiply-long-raw.o", ll)
		})
	}
}
