package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEFloatMultiplyAccumulateCompleteGo127Encodings(t *testing.T) {
	if len(arm64RawSVEFloatMultiplyAccumulateBases) != 8 {
		t.Fatalf("want eight Go 1.27 predicated fused operations, got %d", len(arm64RawSVEFloatMultiplyAccumulateBases))
	}

	var source strings.Builder
	source.WriteString("TEXT rawSVEFused(SB),$0-0\n")
	for base, op := range arm64RawSVEFloatMultiplyAccumulateBases {
		for size, width := range []string{"", "H", "S", "D"} {
			word := base | uint32(size)<<22 | 30<<16 | 7<<10 | 24<<5 | 8
			decoded, ok := decodeARM64RawSVEFloatMultiplyAccumulate(word)
			if (size == 0 && ok) || (size != 0 && (!ok || decoded.Op != op)) {
				t.Fatalf("%s width %q word %#08x decoded as %+v, ok=%v", op, width, word, decoded, ok)
			}
			if size == 0 {
				continue
			}
			wantFirst, wantSecond := "Z30."+width, "Z24."+width
			switch op {
			case "ZFMAD", "ZFMSB", "ZFNMAD", "ZFNMSB":
				wantFirst, wantSecond = wantSecond, wantFirst
			}
			if string(decoded.Args[0].Reg) != wantFirst ||
				string(decoded.Args[1].Reg) != wantSecond ||
				string(decoded.Args[2].Reg) != "P7.M" ||
				string(decoded.Args[3].Reg) != "Z8."+width {
				t.Fatalf("%s word %#08x operands decoded as %+v", op, word, decoded.Args)
			}
			fmt.Fprintf(&source, "\tWORD $%#08x\n", word)
		}
	}
	source.WriteString("\tRET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{
		"aarch64-apple-darwin",
		"aarch64-unknown-linux-gnu",
		"aarch64-pc-windows-msvc",
	} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{
				TargetTriple: triple,
				Goarch:       "arm64",
				Sigs: map[string]FuncSig{
					"rawSVEFused": {Name: "rawSVEFused", Ret: Void},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "arm64-raw-sve-fused.ll", "arm64-raw-sve-fused.o", ir)
		})
	}
}
