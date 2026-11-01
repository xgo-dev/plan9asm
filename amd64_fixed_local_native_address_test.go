package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// Every read below is valid for both runtime choices when the native input
// points to its actual test buffer. A possible literal in the abstract state
// is not proof that an out-of-range literal access is executed.
func fixedLocalNativeAddressCases() []fixedLocalPointerChoiceCase {
	selected := "LEAQ choice<>(SB),CX\nCMPQ AX,$0\nCMOVQNE SI,CX\n"
	guarded := "CMPQ AX,$0\nJE literal\nMOVOU 128(CX),X0\nJMP read\nliteral:\nMOVOU (CX),X0\nread:\nMOVQ X0,AX"
	return []fixedLocalPointerChoiceCase{
		{"two actual read paths", selected + guarded},
		{"unexecuted out-of-range candidate", selected + "CMPQ AX,$0\nJE done\nMOVQ 128(CX),AX\ndone:"},
		{"CFG preserves actual address", "CMPQ AX,$0\nJE choose\nMOVQ SI,CX\nJMP join\nchoose:\nLEAQ choice<>(SB),CX\njoin:\n" + guarded},
		{"private spill preserves actual address", selected + "MOVQ CX,8(SP)\nMOVQ 8(SP),CX\n" + guarded},
		{"exact address excursion returns before read", "LEAQ choice<>(SB),CX\nADDQ $128,CX\nSUBQ $128,CX\nMOVQ (CX),AX"},
		{"source address expression returns before read", "LEAQ choice<>+128(SB),CX\nSUBQ $128,CX\nMOVQ (CX),AX"},
		{"dynamic affine literal address", "MOVQ AX,DX\nANDQ $7,DX\nSHLQ $3,DX\nLEAQ choice<>(SB),CX\nADDQ DX,CX\nMOVQ (CX),AX"},
		{"dynamic affine selected address", selected + "MOVQ AX,DX\nANDQ $7,DX\nSHLQ $3,DX\nADDQ DX,CX\nMOVQ (CX),AX"},
		{"finite address loop converges", selected + "MOVQ $4,R11\nagain:\nADDQ $8,CX\nDECQ R11\nJNE again\nMOVQ (CX),AX"},
		{"native compare retains carry flags", selected + "CMPQ CX,CX\nCMOVQCC DI,CX\nMOVQ (CX),AX"},
		{"native address arithmetic retains carry flags", selected + "ADDQ $0,CX\nCMOVQCC DI,CX\nMOVQ (CX),AX"},
		{"more than four source choices", fixedLocalChoiceCountBody(8)},
		{"former fifth alternative limit", fixedLocalChoiceCountBody(5)},
		{"dynamic indexed selected address", selected + "MOVQ AX,DX\nANDQ $7,DX\nMOVQ (CX)(DX*8),AX"},
		{"indexed joined literals", "LEAQ choice<>(SB),CX\nLEAQ other<>(SB),DX\nCMPQ AX,$0\nCMOVQEQ DX,CX\nMOVQ $1,DX\nMOVQ (CX)(DX*8),AX"},
		{"dynamic indexed literal address", "MOVQ AX,DX\nANDQ $7,DX\nSHLQ $3,DX\nLEAQ choice<>(SB),CX\nMOVQ (CX)(DX*1),AX"},
		{"dynamic indexed literal LEA", "MOVQ AX,DX\nANDQ $7,DX\nLEAQ choice<>(SB),CX\nLEAQ (CX)(DX*8),CX\nMOVQ (CX),AX"},
	}
}

func TestGoAMD64FixedLocalNativeAddressCompleteSources(t *testing.T) {
	var assembly strings.Builder
	assembly.WriteString(fixedLocalChoiceData)
	for index, row := range fixedLocalNativeAddressCases() {
		fn, sig, source := fixedLocalPointerChoiceFixture(t, row.body)
		assembly.WriteString(strings.Replace(source, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("complete original native address operation was rejected", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", assembly.String(), true)
}

func TestGoAMD64FixedLocalNativeAddressRetainsBoundaries(t *testing.T) {
	t.Run("native address has machine bits", func(t *testing.T) {
		fn, sig, _ := fixedLocalPointerChoiceFixture(t, fixedLocalChoicePrefix+"XORQ CX,AX")
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatal("complete native arithmetic source rejected", err)
		}
	})
	for _, row := range []fixedLocalPointerChoiceCase{
		{"known literal read exceeds object", "LEAQ choice<>(SB),CX\nMOVQ 64(CX),AX"},
		{"known literal vector crosses object", "LEAQ choice<>(SB),CX\nMOVOU 56(CX),X0\nMOVQ X0,AX"},
		{"known indexed literal exceeds object", "LEAQ choice<>(SB),CX\nMOVQ $8,DX\nMOVQ (CX)(DX*8),AX"},
		{"known readonly write", "LEAQ choice<>(SB),CX\nMOVQ AX,(CX)"},
		{"readonly alternative does not grant write", fixedLocalChoicePrefix + "MOVQ AX,(CX)"},
		{"other object does not establish adjacency", "LEAQ choice<>+64(SB),CX\nLEAQ other<>(SB),DX\nMOVQ (CX),AX"},
		{"private address cannot merge with native", "LEAQ 8(SP),CX\nCMPQ AX,$0\nCMOVQEQ SI,CX\nMOVQ (CX),AX"},
		{"partial register address is undefined", fixedLocalChoicePrefix + "MOVL CX,DX\nMOVQ (DX),AX"},
		{"partial spilled address is undefined", fixedLocalChoicePrefix + "MOVQ CX,8(SP)\nMOVB $1,9(SP)\nMOVQ 8(SP),DX\nMOVQ (DX),AX"},
		{"unknown input is not an address", "CMPQ AX,$0\nCMOVQEQ SI,R12\nMOVQ (R12),AX"},
		{"numeric input is not an address", "MOVQ $1,CX\nMOVQ (CX),AX"},
		{"unknown index is not numerical", fixedLocalChoicePrefix + "MOVQ (CX)(R12*8),AX"},
		{"private index is not numerical", fixedLocalChoicePrefix + "MOVQ (CX)(SP*1),AX"},
		{"address index is not numerical", fixedLocalChoicePrefix + "MOVQ (CX)(DI*8),AX"},
		{"partial index is undefined", fixedLocalChoicePrefix + "MOVW $1,R12\nMOVQ (CX)(R12*8),AX"},
		{"equality does not grant readonly write", fixedLocalChoicePrefix + "CMPQ CX,R8\nJNE done\nMOVQ AX,(CX)\ndone:"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalPointerChoiceFixture(t, row.body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("native address acquired unrelated storage or numerical permission", err)
			}
		})
	}
}
