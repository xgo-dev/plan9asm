package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64RawScalarAbsoluteDifferenceAndMultiplyExtended(t *testing.T) {
	var native []string
	for _, op := range []string{"fabd", "fmulx"} {
		for _, width := range []string{"h", "s", "d"} {
			for _, regs := range [][3]int{{0, 1, 2}, {29, 30, 31}, {31, 31, 31}} {
				native = append(native, fmt.Sprintf("%s %s%d, %s%d, %s%d", op, width, regs[0], width, regs[1], width, regs[2]))
			}
		}
	}
	words := assembleARM64LLVMWords(t, native, "+fullfp16")
	var source strings.Builder
	source.WriteString("TEXT rawscalarabsmul(SB),$0-0\n")
	for _, word := range words {
		fmt.Fprintf(&source, "WORD $%#08x\n", word)
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
				Sigs: map[string]FuncSig{"rawscalarabsmul": {Name: "rawscalarabsmul", Ret: Void}}})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"fabd", "fmulx"} {
				family := "sisd"
				if op == "fmulx" {
					family = "neon"
				}
				for _, width := range []int{16, 32, 64} {
					if !strings.Contains(ir, fmt.Sprintf("@llvm.aarch64.%s.%s.f%d", family, op, width)) {
						t.Fatalf("scalar %s f%d missing", op, width)
					}
				}
			}
			compileLLVMToObject(t, llc, triple, "rawscalarabsmul.ll", "rawscalarabsmul.o", ir)
		})
	}
}
