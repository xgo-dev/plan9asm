package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEPredicateMemoryCompleteFormats(t *testing.T) {
	var source strings.Builder
	var lines []string
	for _, op := range []string{"ldr", "str"} {
		for _, offset := range []int{-256, -1, 0, 1, 255} {
			for _, base := range []string{"x0", "sp"} {
				lines = append(lines, fmt.Sprintf("%s p15, [%s, #%d, mul vl]", op, base, offset))
			}
		}
	}
	source.WriteString("TEXT rawpredmem(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
	}
	source.WriteString("RET\n")
	file, err := Parse(ArchARM64, source.String())
	if err != nil {
		t.Fatal(err)
	}
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM 22 llc not found")
	}
	for _, triple := range []string{"aarch64-apple-darwin", "aarch64-unknown-linux-gnu", "aarch64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: triple,
				Sigs: map[string]FuncSig{"rawpredmem": {Name: "rawpredmem", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawpredmem.ll", "rawpredmem.o", ir)
		})
	}
}

func TestARM64RawSVEPredicateMemoryOperandFields(t *testing.T) {
	var lines []string
	var wants []arm64RawSVELoadStore
	for _, load := range []bool{false, true} {
		op := "str"
		if load {
			op = "ldr"
		}
		for field, limit := range []int{512, 32, 16} {
			for value := 0; value < limit; value++ {
				fields := [3]int{-256, 31, 15}
				fields[field] = value
				if field == 0 {
					fields[0] -= 256
				}
				base := fmt.Sprintf("x%d", fields[1])
				if fields[1] == 31 {
					base = "sp"
				}
				lines = append(lines, fmt.Sprintf("%s p%d, [%s, #%d, mul vl]", op, fields[2], base, fields[0]))
				wants = append(wants, arm64RawSVELoadStore{load: load, predicate: true,
					immediate: fields[0], base: fields[1], vector: fields[2]})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		if got, ok := decodeARM64RawSVELoadStore(word); !ok || got != wants[i] {
			t.Errorf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x85800010, 0xe5800010, 0x85802000, 0xe5400000} {
		if got, ok := decodeARM64RawSVELoadStore(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
