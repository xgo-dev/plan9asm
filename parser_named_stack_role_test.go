package plan9asm

import (
	"fmt"
	"testing"
)

func TestNamedStackOffsetKeepsItsSourceRole(t *testing.T) {
	for _, name := range []string{"slot", "UNKNOWN", "槽"} {
		for _, base := range []string{"SP", "RSP", "ESP", "R1"} {
			t.Run(name+"/"+base, func(t *testing.T) {
				memory, ok := parseMem(name + "(" + base + ")")
				if !ok || memory.OffRaw != name || memory.Off != 0 {
					t.Fatalf("bare spelling lost its original name: %+v, %t", memory, ok)
				}
				if _, constant := parseNamedStackConstantOffset(name); constant {
					t.Fatal("a bare name is not a resolved constant displacement")
				}
			})
		}
		for _, offset := range []int64{-8, 0, 4} {
			spelling := fmt.Sprintf("%s%+d", name, offset)
			for _, base := range []string{"SP", "RSP", "ESP", "R1"} {
				t.Run(spelling+"/"+base, func(t *testing.T) {
					memory, ok := parseMem(spelling + "(" + base + ")")
					if !ok || memory.Off != offset {
						t.Fatalf("explicit displacement changed: %+v, %t", memory, ok)
					}
					if base == "SP" {
						if memory.OffRaw != "" {
							t.Fatal("named pseudo-SP constant was not resolved", memory)
						}
					} else if memory.OffRaw != spelling {
						t.Fatal("physical base acquired NAME_AUTO resolution", memory)
					}
				})
			}
		}
	}
}

func TestARM64StackOffsetCannotBorrowNamedPseudoSP(t *testing.T) {
	for _, name := range []string{"slot", "UNKNOWN", "槽"} {
		for _, offset := range []int64{-8, 0, 4} {
			spelling := fmt.Sprintf("%s%+d", name, offset)
			if offset == 0 {
				spelling = name
			}
			for _, base := range []Reg{SP, "RSP"} {
				t.Run(spelling+"/"+string(base), func(t *testing.T) {
					memory := MemRef{Base: base, Off: offset, OffRaw: spelling}
					_, _, _, err := arm64StackMemoryExtent(Instr{Op: "MOVD"}, memory)
					if (err == nil) != (base == SP) {
						t.Fatalf("only an actual pseudo-SP role may resolve a stack name: %v", err)
					}
				})
			}
		}
	}
}
