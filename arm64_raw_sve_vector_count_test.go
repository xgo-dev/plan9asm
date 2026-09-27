package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVEVectorCountCompleteFormats(t *testing.T) {
	var lines []string
	for _, operation := range []string{"inc", "dec"} {
		for size := 1; size < 4; size++ {
			for pattern := 0; pattern < 32; pattern++ {
				for _, multiplier := range []int{1, 7, 16} {
					lines = append(lines, fmt.Sprintf("%s%c z31.%c, #%d, mul #%d", operation, "bhwd"[size], "bhsd"[size], pattern, multiplier))
				}
			}
		}
	}
	var source strings.Builder
	source.WriteString("TEXT rawvectorcount(SB),$0-0\n")
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
				Sigs: map[string]FuncSig{"rawvectorcount": {Name: "rawvectorcount", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawvectorcount.ll", "rawvectorcount.o", ir)
		})
	}
}

func TestARM64RawSVEVectorCountOperandFields(t *testing.T) {
	var lines []string
	var wants []arm64RawSVECnt
	for _, operation := range []string{"inc", "dec"} {
		for size := 1; size < 4; size++ {
			for field, limit := range []int{32, 32, 16} {
				for value := 0; value < limit; value++ {
					fields := [3]int{31, 31, 15}
					fields[field] = value
					dst, pattern, multiplier := fields[0], fields[1], fields[2]+1
					lines = append(lines, fmt.Sprintf("%s%c z%d.%c, #%d, mul #%d", operation, "bhwd"[size], dst, "bhsd"[size], pattern, multiplier))
					arithmetic := "add"
					if operation == "dec" {
						arithmetic = "sub"
					}
					wants = append(wants, arm64RawSVECnt{
						op: Op(strings.ToUpper(operation + string("bhwd"[size]))), elementBits: 8 << size,
						destination: dst, pattern: pattern, multiplier: multiplier, operation: arithmetic, vector: true,
					})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVECnt(word)
		if !ok || got != wants[i] {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
	}
	for _, word := range []uint32{0x0430c000, 0x0430c400, 0x0470c800, 0x0470d000, 0x0460c000} {
		if got, ok := decodeARM64RawSVECnt(word); ok {
			t.Errorf("unallocated or adjacent word %#08x decoded as %+v", word, got)
		}
	}
}
