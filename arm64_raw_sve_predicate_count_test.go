package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEPredicateCountNativeForms() []string {
	var lines []string
	for _, width := range []string{"b", "h", "s", "d"} {
		lines = append(lines, fmt.Sprintf("cntp x0, p15, p14.%s", width), fmt.Sprintf("cntp xzr, p0, p1.%s", width))
		for _, multiplier := range []int{2, 4} {
			lines = append(lines, fmt.Sprintf("cntp x30, pn0.%s, vlx%d", width, multiplier),
				fmt.Sprintf("cntp xzr, pn15.%s, vlx%d", width, multiplier))
		}
	}
	return lines
}

func TestARM64RawSVEPredicateCountCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawcntp(SB),$0-0\n")
	for _, word := range assembleARM64LLVMWords(t, arm64RawSVEPredicateCountNativeForms(), "+sve2p1") {
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
				Sigs: map[string]FuncSig{"rawcntp": {Name: "rawcntp", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawcntp.ll", "rawcntp.o", ir)
		})
	}
}

func TestARM64RawSVEPredicateCountOperandFields(t *testing.T) {
	lines := arm64RawSVEPredicateCountNativeForms()
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve2p1") {
		got, ok := decodeARM64RawSVEPredicateCount(word)
		if !ok {
			t.Fatalf("%s: rejected %#08x", lines[i], word)
		}
		fields := strings.Fields(strings.ReplaceAll(strings.ToUpper(lines[i]), ",", ""))
		destination := "R" + strings.TrimPrefix(fields[1], "X")
		if fields[1] == "XZR" {
			destination = "ZR"
		}
		if got.Op != "PCNTP" || got.Args[2].Reg != Reg(destination) {
			t.Errorf("%s: wrong destination: %+v", lines[i], got)
		}
		if strings.HasPrefix(fields[2], "PN") {
			if got.Args[0].Kind != OpIdent || got.Args[0].Ident != fields[3] || got.Args[1].Reg != Reg(fields[2]) {
				t.Errorf("%s: wrong counter form: %+v", lines[i], got)
			}
		} else if got.Args[0].Reg != Reg(fields[3]) || got.Args[1].Reg != Reg(fields[2]) {
			t.Errorf("%s: wrong predicate form: %+v", lines[i], got)
		}
	}
	for _, word := range []uint32{0x25208a00, 0x2520c000, 0x25207810} {
		if got, ok := decodeARM64RawSVEPredicateCount(word); ok {
			t.Errorf("reserved/neighboring word %#08x decoded as %+v", word, got)
		}
	}
}
