package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawSVECountPatternAndMultiplier(t *testing.T) {
	const source = `TEXT rawcount(SB),$0-0
WORD $0x0470e7ea // DECH X10
WORD $0x04a3e3e9 // CNTW X9, ALL, MUL #4
WORD $0x043fe010 // INCB X16, POW2, MUL #16
RET
`
	file, err := Parse(ArchARM64, source)
	if err != nil {
		t.Fatal(err)
	}
	ir, err := Translate(file, Options{Goarch: "arm64", TargetTriple: "aarch64-unknown-linux-gnu",
		Sigs: map[string]FuncSig{"rawcount": {Name: "rawcount", Ret: Void}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"@llvm.aarch64.sve.cnth(i32 31)", "@llvm.aarch64.sve.cntw(i32 31)",
		"@llvm.aarch64.sve.cntb(i32 0)", "sub i64", "add i64", ", 4\n", ", 16\n"} {
		if !strings.Contains(ir, want) {
			t.Fatalf("raw count IR omitted %q", want)
		}
	}
}

func TestARM64RawSVECountCompleteFormats(t *testing.T) {
	var source strings.Builder
	source.WriteString("TEXT rawcountforms(SB),$0-0\n")
	for size := uint32(0); size < 4; size++ {
		for _, base := range []uint32{0x0420e000, 0x0430e000, 0x0430e400} {
			for pattern := 0; pattern < 32; pattern++ {
				for _, multiplier := range []uint32{1, 4, 16} {
					word := base | size<<22 | (multiplier-1)<<16 | uint32(pattern)<<5 | 10
					fmt.Fprintf(&source, "WORD $%#08x\n", word)
				}
			}
		}
	}
	source.WriteString("RET\n")
	requireARM64GoAssemblerResult(t, source.String(), true)
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
				Sigs: map[string]FuncSig{"rawcountforms": {Name: "rawcountforms", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			compileLLVMToObject(t, llc, triple, "rawcount.ll", "rawcount.o", ir)
		})
	}
}

func TestARM64RawSVECountMatchesLLVM22Encoder(t *testing.T) {
	var lines []string
	type expectation struct {
		op                             Op
		bits, multiplier, pattern, dst int
	}
	var wants []expectation
	for size, suffix := range []string{"b", "h", "w", "d"} {
		for _, prefix := range []string{"cnt", "inc", "dec"} {
			for _, pattern := range []int{0, 13, 14, 28, 29, 30, 31} {
				for _, multiplier := range []int{1, 7, 16} {
					lines = append(lines, fmt.Sprintf("%s%s x30, #%d, mul #%d", prefix, suffix, pattern, multiplier))
					wants = append(wants, expectation{Op(strings.ToUpper(prefix + suffix)), 8 << size, multiplier, pattern, 30})
				}
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVECnt(word)
		want := wants[i]
		if !ok || got.op != want.op || got.elementBits != want.bits || got.pattern != want.pattern ||
			got.multiplier != want.multiplier || got.destination != want.dst {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, want)
		}
	}
	for _, word := range []uint32{0x0420e400, 0x0430c000, 0x0430f000, 0x0520e000} {
		if got, ok := decodeARM64RawSVECnt(word); ok {
			t.Fatalf("count decoder accepted adjacent instruction %#08x as %+v", word, got)
		}
	}
}
