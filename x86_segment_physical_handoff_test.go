package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86NamedSegmentMemoryDoesNotReinterpretPhysicalDecoder(t *testing.T) {
	for _, prefix := range []byte{0x64, 0x65} {
		for _, address := range [][]byte{{0x04, 0x25, 0x30, 0, 0, 0}, {0x40, 0x30}} {
			source := "TEXT Physical(SB),4,$0-0\n"
			for _, value := range append([]byte{prefix, 0x48, 0x8b}, address...) {
				source += fmt.Sprintf("BYTE $%d\n", value)
			}
			file := mustParseX86RawReturn(t, source+"RET\n")
			function, err := decodeX86RawDirectives(file.Funcs[0], "amd64")
			if err != nil {
				t.Fatal(err)
			}
			observed := false
			for _, instruction := range function.Instrs {
				if instruction.Op != OpMOVQ {
					continue
				}
				observed = true
				if _, named, err := x86NamedSegmentMemorySource(instruction, instruction.Args[0], "amd64"); named || err != nil {
					t.Fatal("physical decoder operands were reinterpreted as named Go syntax", named, err)
				}
			}
			if !observed {
				t.Fatal("complete physical source lost its actual MOVQ")
			}
		}
	}
}
