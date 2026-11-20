package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

type fixedLocalConstantIndexCase struct {
	name, body string
	literal    bool
}

func fixedLocalConstantIndexCases() []fixedLocalConstantIndexCase {
	var cases []fixedLocalConstantIndexCase
	// Independent physical GP inventory: SP is a base, never an index.
	for _, register := range strings.Fields("AX BX CX DX DI SI BP R8 R9 R10 R11 R12 R13 R14 R15") {
		for _, literal := range []bool{false, true} {
			var body strings.Builder
			body.WriteString("MOVQ $0,8(SP)\n")
			base, name := "SP", "private/"+register
			if literal {
				base, name = "SI", "literal/"+register
				if register == base {
					base = "DI"
				}
				fmt.Fprintf(&body, "LEAQ literal<>(SB),%s\n", base)
			} else {
				body.WriteString("MOVQ $77,48(SP)\n")
			}
			for ordinal, scale := range []int{1, 2, 4, 8} {
				offset := 56 // The final qword of this private 64-byte frame.
				if literal {
					offset = ordinal * 8
				}
				address := fmt.Sprintf("%d(%s)(%s*%d)", offset-3*scale, base, register, scale)
				if !literal {
					body.WriteString("MOVQ $0,56(SP)\n")
				}
				fmt.Fprintf(&body, "MOVQ $3,%s\n", register)
				if !literal {
					fmt.Fprintf(&body, "MOVQ $%d,%s\nADDQ $1,%s\n", 17+scale, address, address)
				}
				fmt.Fprintf(&body, "MOVQ %s,AX\nADDQ AX,8(SP)\n", address)
				if !literal {
					body.WriteString("MOVQ 56(SP),AX\nADDQ AX,8(SP)\n")
				}
			}
			if !literal {
				body.WriteString("MOVQ 48(SP),AX\nADDQ AX,8(SP)\n")
			}
			body.WriteString("MOVQ 8(SP),AX")
			cases = append(cases, fixedLocalConstantIndexCase{name, body.String(), literal})
		}
	}
	return cases
}

func TestGoAMD64FixedLocalConstantIndexPrivate(t *testing.T) {
	var original strings.Builder
	count := 0
	for _, row := range fixedLocalConstantIndexCases() {
		if row.literal {
			continue
		}
		fn, sig, source := fixedLocalGPFixture(t, row.body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", count), 1))
		count++
		t.Run(row.name, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal("constant index must retain exact private bytes", err)
			}
			accesses := 0
			for _, instruction := range proved.Instrs {
				for index, operand := range instruction.Args {
					if operand.Kind != OpMem || operand.Mem.Index == "" {
						continue
					}
					accesses++
					access, found := instruction.x86FixedLocalMemory[index]
					write := instruction.Op == "ADDQ" || index == 1
					if !found || access.owner != proved.x86FixedLocal || access.width != 8 ||
						access.nativeInput || access.write != write || access.offset != [8]int64{56, 56, 56, 56, 56, 56, 56, 56} {
						t.Fatalf("indexed access lost its exact byte/role certificate: %+v", access)
					}
				}
			}
			if accesses != 12 {
				t.Fatal("expected one store/RMW/load for each scale", accesses)
			}
		})
	}
	if count != 15 {
		t.Fatal("independent non-SP GP inventory changed", count)
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
