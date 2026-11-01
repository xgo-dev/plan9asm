package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARM64ScalarMemoryWritebackOverlapRetainsConcreteDiagnostic(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, suffix := range []string{".P", ".W"} {
			for _, offset := range []int{-256, 0, 255} {
				for _, store := range []bool{false, true} {
					operands := fmt.Sprintf("%d(R13),R13", offset)
					if store {
						operands = fmt.Sprintf("R13,%d(R13)", offset)
					}
					instruction := op + suffix + " " + operands
					t.Run(instruction, func(t *testing.T) {
						source := "TEXT overlap(SB),516,$0-0\n" + instruction + "\nRET\n"
						requireARM64GoAssemblerResult(t, source, false)
						file, err := Parse(ArchARM64, source)
						if err != nil {
							t.Fatal(err)
						}
						_, handled, err := parseARM64ScalarMemoryForm(Op(op), file.Funcs[0].Instrs[1])
						if !handled || err == nil || !strings.Contains(err.Error(), "base/data register overlap") {
							t.Fatalf("writeback overlap = (%v, %v), want its concrete Go rejection", handled, err)
						}
					})
				}
			}
		}
	}
}

func TestARM64ScalarMemoryRejectsStackPointerDataLikeGo(t *testing.T) {
	for _, op := range []string{"MOVB", "MOVBU", "MOVH", "MOVHU", "MOVW", "MOVWU", "MOVD"} {
		for _, operands := range []string{"(R0),RSP", "RSP,(R0)"} {
			instruction := op + " " + operands
			t.Run(instruction, func(t *testing.T) {
				source := "TEXT invalid(SB),516,$0-0\n" + instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, false)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				_, handled, err := parseARM64ScalarMemoryForm(Op(op), file.Funcs[0].Instrs[1])
				if !handled || err == nil {
					t.Fatalf("memory data RSP = (%v, %v), accepted Go-invalid transfer", handled, err)
				}
			})
		}
	}
}
