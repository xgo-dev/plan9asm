package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func fixedLocalConstantArithmeticCases() []struct{ name, body string } {
	return []struct{ name, body string }{
		{"zero xor", "XORQ SI,SI\nADDQ $3,SI"},
		{"add immediate", "MOVQ $1,SI\nADDQ $2,SI"},
		{"subtract immediate", "MOVQ $5,SI\nSUBQ $2,SI"},
		{"and immediate", "MOVQ $7,SI\nANDQ $3,SI"},
		{"or immediate", "MOVQ $2,SI\nORQ $1,SI"},
		{"xor immediate", "MOVQ $4,SI\nXORQ $7,SI"},
		{"add register", "MOVQ $1,SI\nMOVQ $2,DI\nADDQ DI,SI"},
		{"subtract register", "MOVQ $5,SI\nMOVQ $2,DI\nSUBQ DI,SI"},
		{"and register", "MOVQ $7,SI\nMOVQ $3,DI\nANDQ DI,SI"},
		{"or register", "MOVQ $2,SI\nMOVQ $1,DI\nORQ DI,SI"},
		{"xor register", "MOVQ $4,SI\nMOVQ $7,DI\nXORQ DI,SI"},
		{"increment", "MOVQ $2,SI\nINCQ SI"},
		{"decrement", "MOVQ $4,SI\nDECQ SI"},
		{"negate", "MOVQ $-3,SI\nNEGQ SI"},
		{"complement", "MOVQ $-4,SI\nNOTQ SI"},
		{"sign extended immediate", "MOVQ $4,SI\nADDQ $0xffffffff,SI"},
		{"negative operand", "MOVQ $-1,SI\nADDQ $4,SI"},
		{"modular arithmetic", "MOVQ $0x7fffffffffffffff,SI\nADDQ $1,SI\nSUBQ $1,SI\nANDQ $3,SI"},
		{"value copied before overwrite", "MOVQ $3,DI\nMOVQ DI,SI\nMOVQ $5,DI\nADDQ $0,SI"},
		{"same value at join", "MOVQ $3,SI\nCMPQ AX,$0\nJEQ joined\nADDQ $0,SI\njoined:"},
	}
}

func TestGoAMD64FixedLocalConstantArithmeticIndex(t *testing.T) {
	var original strings.Builder
	cases := fixedLocalConstantArithmeticCases()
	if len(cases) != 20 {
		t.Fatal("constant arithmetic operand and boundary inventory changed", len(cases))
	}
	for index, row := range cases {
		body := "MOVQ $77,24(SP)\n" + row.body + "\nMOVQ (SP)(SI*8),AX"
		fn, sig, source := fixedLocalGPFixture(t, body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			proved, err := proveX86FixedLocal(fn, sig)
			if err != nil {
				t.Fatal("exact numerical index from typed arithmetic was lost", err)
			}
			found := false
			for _, instruction := range proved.Instrs {
				if instruction.Op != "MOVQ" || instruction.Args[0].Kind != OpMem || instruction.Args[0].Mem.Index != SI {
					continue
				}
				access, present := instruction.x86FixedLocalMemory[0]
				if !present || access.nativeInput || access.write || access.width != 8 ||
					access.offset != [8]int64{24, 24, 24, 24, 24, 24, 24, 24} {
					t.Fatalf("constant arithmetic acquired different bytes: %+v", access)
				}
				found = true
			}
			if !found {
				t.Fatal("original indexed instruction disappeared")
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalConstantArithmeticKeepsUnknownRoles(t *testing.T) {
	var original strings.Builder
	for index, row := range []struct{ name, body string }{
		{"unknown initial value", "ADDQ $3,SI"},
		{"unknown source", "MOVQ $3,SI\nADDQ CX,SI"},
		{"partial source", "MOVQ $3,SI\nMOVW $0,CX\nADDQ CX,SI"},
		{"partial overwrite", "MOVQ $3,SI\nADDB $0,SI"},
		{"pointer source", "MOVQ $3,SI\nMOVQ SP,DI\nADDQ DI,SI"},
		{"numeric is not private", "MOVQ $0,DI\nADDQ $0,DI\nMOVQ (DI),SI"},
		{"carry value unavailable", "MOVQ $3,SI\nSTC\nADCQ $0,SI"},
		{"borrow value unavailable", "MOVQ $3,SI\nSTC\nSBBQ $0,SI"},
		{"different values at join", "MOVQ $3,SI\nCMPQ AX,$0\nJEQ joined\nADDQ $1,SI\njoined:"},
		{"zero xor word is partial", "XORW SI,SI\nADDQ $3,SI"},
		{"overflow cannot grant extent", "MOVQ $0x7fffffffffffffff,SI\nADDQ $1,SI"},
		{"arithmetic cannot grant extent", "MOVQ $7,SI\nADDQ $1,SI"},
	} {
		body := "MOVQ $77,24(SP)\nMOVQ $77,32(SP)\n" + row.body + "\nMOVQ (SP)(SI*8),AX"
		fn, sig, source := fixedLocalGPFixture(t, body)
		original.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err == nil {
				t.Fatal("unknown numerical value or memory origin became an exact index")
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}
