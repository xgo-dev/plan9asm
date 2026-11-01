package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGoAMD64FixedLocalInputAffineAddresses(t *testing.T) {
	var original strings.Builder
	for index, row := range []struct {
		name, body string
		valid      bool
	}{
		{"pointer plus number", "ADDQ AX,SI\nMOVQ (SI),AX", true},
		{"number plus pointer", "ADDQ SI,AX\nMOVQ (AX),AX", true},
		{"pointer minus number", "SUBQ AX,SI\nMOVQ (SI),AX", true},
		{"pointer immediate", "ADDQ $8,SI\nSUBQ $16,SI\nMOVQ (SI),AX", true},
		{"indexed LEA scale1", "LEAQ -64(SI)(AX*1),CX\nMOVQ (CX),AX", true},
		{"indexed LEA scale2", "LEAQ -64(SI)(AX*2),CX\nMOVQ (CX),AX", true},
		{"indexed LEA scale4", "LEAQ -64(SI)(AX*4),CX\nMOVQ (CX),AX", true},
		{"indexed LEA scale8", "LEAQ -64(SI)(AX*8),CX\nMOVQ (CX),AX", true},
		{"pointer increment", "INCQ SI\nDECQ SI\nMOVQ (SI),AX", true},
		{"pointer compare", "CMPQ SI,DI\nSETCS AL", true},
		{"pointer immediate compare", "CMPQ SI,$0\nSETCS AL", true},
		{"pointer spill compare", "MOVQ SI,8(SP)\nCMPQ DI,8(SP)\nSETCS AL", true},
		{"reverse spill compare", "MOVQ SI,8(SP)\nCMPQ 8(SP),DI\nSETCS AL", true},
		{"dead differing origin", "CMPQ AX,$0\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ DI,CX\njoin:", true},
		{"dead conditional spill", "CMPQ AX,$0\nJEQ join\nMOVQ SI,8(SP)\njoin:", true},
		{"same origin derived join", "CMPQ AX,$0\nJEQ left\nLEAQ 8(SI),CX\nJMP join\nleft:\nLEAQ 16(SI),CX\njoin:\nMOVQ (CX),AX", true},
		{"pointer plus pointer", "ADDQ DI,SI\nMOVQ (SI),AX", false},
		{"number minus pointer", "SUBQ SI,AX\nMOVQ (AX),AX", false},
		{"pointer bits escape", "ADDQ SI,AX", false},
		{"partial pointer arithmetic", "ADDL $8,SI\nMOVQ (SI),AX", false},
		{"pointer index", "LEAQ (SI)(DI*2),CX\nMOVQ (CX),AX", false},
		{"aliased pointer index", "LEAQ (SI)(SI*1),CX\nMOVQ (CX),AX", false},
		{"unknown index", "LEAQ (SI)(R8*2),CX\nMOVQ (CX),AX", false},
		{"native and numerical comparison", "CMPQ SI,AX\nSETCS AL", true},
		{"uninitialized spill compare", "CMPQ SI,8(SP)\nSETCS AL", false},
		{"different origin consumed", "CMPQ AX,$0\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ DI,CX\njoin:\nMOVQ (CX),AX", true},
		{"pointer and number join", "CMPQ AX,$0\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ AX,CX\njoin:\nMOVQ (CX),AX", false},
		{"conditional spill consumed", "CMPQ AX,$0\nJEQ join\nMOVQ SI,8(SP)\njoin:\nMOVQ 8(SP),CX\nMOVQ (CX),AX", false},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, source := fixedLocalInputFixture(t, row.body)
			original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
			_, err := proveX86FixedLocal(fn, sig)
			if row.valid && err != nil {
				t.Fatal("typed input address lost its original identity", err)
			}
			if !row.valid && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("unproved pointer acquired numerical or native access", err)
			}
		})
	}
	// Positive and negative proof rows alike remain valid original Go syntax.
	// A refusal here must not masquerade as a translator provenance check.
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
