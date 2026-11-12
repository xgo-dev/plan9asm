package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestX86ABI0ResultInitializationOccupiedPointerComponents(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := 8
		move := "MOVQ"
		if arch == "386" {
			word, move = 4, "MOVL"
		}
		for _, row := range []struct {
			name, declaration string
			input, result     int
		}{
			{"unused direct pointer", "func Value(x *uint32) uint32", -1, word},
			{"slice length", "func Value(x []uint32) uint32", word, 3 * word},
			{"slice capacity", "func Value(x []uint32) uint32", 2 * word, 3 * word},
			{"string length", "func Value(x string) uint32", word, 2 * word},
			{"struct numeric field", "type S struct { P *uint32; N uintptr }; func Value(x S) uint32", word, 2 * word},
		} {
			t.Run(arch+"/"+row.name, func(t *testing.T) {
				body := "MOVL $7,AX"
				if row.input >= 0 {
					body = fmt.Sprintf("%s x+%d(FP),AX", move, row.input)
				}
				body += fmt.Sprintf("\nMOVL AX,ret0+%d(FP)\nRET", row.result)
				_, file, sig, source := x86ResultInitializationFixture(t, arch, row.declaration, body)
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatalf("unused pointer storage must not invent or prevent a numeric input: %v", err)
				}
			})
		}
	}
}

func TestX86ABI0ResultInitializationConditionalSetCompleteFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		word := 8
		if arch == "386" {
			word = 4
		}
		for _, condition := range strings.Fields("CC CS EQ GE GT HI LE LS LT MI NE OC OS PC PL PS") {
			for _, destination := range []string{"AX", "AH", fmt.Sprintf("ret0+%d(FP)", word)} {
				t.Run(arch+"/"+condition+"/"+destination, func(t *testing.T) {
					body := fmt.Sprintf("MOVB x+0(FP),BX\nCMPB BX,$0\nSET%s %s", condition, destination)
					if destination == "AX" || destination == "AH" {
						body += fmt.Sprintf("\nMOVB %s,ret0+%d(FP)", destination, word)
					}
					body += "\nRET"
					_, file, sig, source := x86ResultInitializationFixture(t, arch, "func Value(x uint8) uint8", body)
					goAssemblerOracleOutput(t, arch, source, "", true)
					if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
						t.Fatalf("complete source-defined SETcc byte did not discharge its exact result: %v", err)
					}
				})
			}
		}
	}
}
