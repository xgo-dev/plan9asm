package plan9asm

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const fixedLocalChoiceData = "DATA choice<>+0(SB)/8,$11\n" +
	"DATA choice<>+56(SB)/8,$19\nGLOBL choice<>(SB),8,$64\n" +
	"DATA other<>+0(SB)/8,$23\nGLOBL other<>(SB),8,$64\n" +
	"DATA twin<>+0(SB)/8,$11\nDATA twin<>+56(SB)/8,$19\nGLOBL twin<>(SB),8,$64\n"

const fixedLocalChoicePrefix = "LEAQ choice<>(SB),R8\nMOVQ SI,CX\nCMPQ AX,$0\nCMOVQEQ R8,CX\n"

type fixedLocalPointerChoiceCase struct{ name, body string }

func fixedLocalChoiceCountBody(count int) string {
	var body strings.Builder
	body.WriteString("LEAQ choice<>(SB),CX\n")
	for index := 1; index < count; index++ {
		fmt.Fprintf(&body, "LEAQ choice<>+%d(SB),R8\nCMPQ AX,$%d\nCMOVQEQ R8,CX\n", index*8, index)
	}
	body.WriteString("MOVQ (CX),AX")
	return body.String()
}

func fixedLocalNativePointerChoiceCases() []fixedLocalPointerChoiceCase {
	return []fixedLocalPointerChoiceCase{
		{"two native inputs", "MOVQ SI,CX\nCMPQ AX,$0\nCMOVQEQ DI,CX\nMOVQ (CX),AX"},
		{"affine native input join", "CMPQ AX,$0\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ DI,CX\njoin:\nMOVQ (CX),AX"},
		{"memory native input join", "CMPQ AX,$1\nJEQ left\nMOVQ SI,CX\nJMP join\nleft:\nMOVQ DI,CX\njoin:\nMOVQ (CX),AX"},
	}
}

func fixedLocalPointerChoiceCases() []fixedLocalPointerChoiceCase {
	rows := []fixedLocalPointerChoiceCase{
		{"conditional read", fixedLocalChoicePrefix + "MOVQ (CX),AX"},
		{"reverse conditional operands", "LEAQ choice<>(SB),CX\nCMPQ AX,$0\nCMOVQNE SI,CX\nMOVQ (CX),AX"},
	}
	rows = append(rows, fixedLocalNativePointerChoiceCases()...)
	return append(rows, []fixedLocalPointerChoiceCase{
		{"two literals", "LEAQ choice<>(SB),CX\nLEAQ other<>(SB),DX\nCMPQ AX,$0\nCMOVQEQ DX,CX\nMOVQ (CX),AX"},
		{"identical contents retain address identity", "LEAQ choice<>(SB),CX\nLEAQ twin<>(SB),DX\nCMPQ CX,DX\nSETNE AL\nMOVBLZX AL,AX"},
		{"two offsets", "LEAQ choice<>(SB),CX\nLEAQ choice<>+8(SB),DX\nCMPQ AX,$0\nCMOVQEQ DX,CX\nMOVOU 32(CX),X0\nMOVQ X0,AX"},
		{"four bounded choices", fixedLocalChoiceCountBody(4)},
		{"CFG join", "CMPQ AX,$0\nJE literal\nMOVQ SI,CX\nJMP joined\nliteral:\nLEAQ choice<>(SB),CX\njoined:\nMOVQ (CX),AX"},
		{"private pointer spill", fixedLocalChoicePrefix + "MOVQ CX,8(SP)\nMOVQ 8(SP),DX\nMOVQ (DX),AX"},
		{"conditional pointer spill read", "LEAQ choice<>(SB),R8\nMOVQ R8,8(SP)\nMOVQ SI,CX\nCMPQ AX,$0\nCMOVQEQ 8(SP),CX\nMOVQ (CX),AX"},
		{"exchange pointer spill", fixedLocalChoicePrefix + "MOVQ CX,8(SP)\nMOVQ DI,DX\nXCHGQ DX,8(SP)\nMOVQ (DX),AX"},
		{"bounded affine shift", fixedLocalChoicePrefix + "ADDQ $8,CX\nMOVQ 48(CX),AX"},
		{"sentinel excludes readonly write", fixedLocalChoicePrefix + "CMPQ CX,R8\nJE done\nMOVQ AX,(CX)\ndone:"},
		{"sentinel excludes literal extent", fixedLocalChoicePrefix + "CMPQ CX,R8\nJE done\nMOVQ 64(CX),AX\ndone:"},
		{"captured comparator value", fixedLocalChoicePrefix + "CMPQ CX,R8\nMOVQ DI,R8\nJE done\nMOVQ 64(CX),AX\ndone:"},
		{"compared value exchanged", fixedLocalChoicePrefix + "CMPQ CX,R8\nXCHGQ CX,DX\nJE done\nMOVQ 64(DX),AX\ndone:"},
		{"finite sentinel loop", "LEAQ choice<>(SB),R8\nMOVQ SI,CX\nagain:\nCMPQ CX,R8\nJE done\nMOVQ 64(CX),AX\nMOVQ R8,CX\nJMP again\ndone:"},
	}...)
}

func fixedLocalPointerChoiceFixture(t *testing.T, body string) (Func, FuncSig, string) {
	t.Helper()
	fn, sig, source := fixedLocalInputFixture(t, "MOVQ AX,DX\n"+body)
	// Internal replay only; the public object gates capture complete sources
	// through the existing actual Go source/object producer.
	sig.x86FixedLocal = &x86FixedLocalBinding{literalData: map[string]x86FixedLocalData{
		"choice<>": {size: 64, alignment: 16},
		"other<>":  {size: 64, alignment: 16},
		"twin<>":   {size: 64, alignment: 16},
	}}
	return fn, sig, source
}

func TestGoAMD64FixedLocalPointerChoicesCompleteSources(t *testing.T) {
	var original strings.Builder
	original.WriteString(fixedLocalChoiceData)
	for index, row := range fixedLocalPointerChoiceCases() {
		fn, sig, assembly := fixedLocalPointerChoiceFixture(t, row.body)
		original.WriteString(strings.Replace(assembly, "·Value", fmt.Sprintf("·Value%d", index), 1))
		t.Run(row.name, func(t *testing.T) {
			if _, err := proveX86FixedLocal(fn, sig); err != nil {
				t.Fatal("individually bounded pointer alternatives rejected", err)
			}
		})
	}
	requireX86GoAssemblerResult(t, "amd64", original.String(), true)
}

func TestGoAMD64FixedLocalPointerChoicesRetainBoundaries(t *testing.T) {
	t.Run("native pointer bits are numerical", func(t *testing.T) {
		fn, sig, _ := fixedLocalPointerChoiceFixture(t, fixedLocalChoicePrefix+"XORQ CX,AX")
		if _, err := proveX86FixedLocal(fn, sig); err != nil {
			t.Fatal("complete native arithmetic source rejected", err)
		}
	})
	for _, row := range []fixedLocalPointerChoiceCase{
		{"exact address exceeds extent", "LEAQ choice<>(SB),CX\nMOVQ 64(CX),AX"},
		{"exact vector access crosses extent", "LEAQ choice<>(SB),CX\nMOVOU 56(CX),X0\nMOVQ X0,AX"},
		{"one candidate is readonly", fixedLocalChoicePrefix + "MOVQ AX,(CX)"},
		{"partial pointer read", fixedLocalChoicePrefix + "MOVL CX,DX\nMOVQ (DX),AX"},
		{"partial pointer spill overwrite", fixedLocalChoicePrefix + "MOVQ CX,8(SP)\nMOVB $1,9(SP)\nMOVQ 8(SP),DX\nMOVQ (DX),AX"},
		{"private relocation is separate", "LEAQ 8(SP),CX\nCMPQ AX,$0\nCMOVQEQ SI,CX\nMOVQ (CX),AX"},
		{"unknown value is not parameter zero", "CMPQ AX,$0\nCMOVQEQ SI,R12\nMOVQ (R12),AX"},
		{"stale equality flags", fixedLocalChoicePrefix + "CMPQ CX,R8\nCMPQ AX,$1\nJE done\nMOVQ AX,(CX)\ndone:"},
		{"compared register overwritten", fixedLocalChoicePrefix + "CMPQ CX,R8\nMOVQ R8,CX\nJE done\nMOVQ 64(CX),AX\ndone:"},
		{"ordered literal comparison", fixedLocalChoicePrefix + "CMPQ CX,R8\nJAE done\nMOVQ AX,(CX)\ndone:"},
		{"other literal cannot remove candidate", fixedLocalChoicePrefix + "LEAQ other<>(SB),R9\nCMPQ CX,R9\nJE done\nMOVQ AX,(CX)\ndone:"},
		{"other offset cannot remove candidate", fixedLocalChoicePrefix + "LEAQ choice<>+8(SB),R9\nCMPQ CX,R9\nJE done\nMOVQ AX,(CX)\ndone:"},
		{"equality does not grant readonly write", fixedLocalChoicePrefix + "CMPQ CX,R8\nJNE done\nMOVQ AX,(CX)\ndone:"},
		{"label does not prove identity", fixedLocalChoicePrefix + "native:\nJNE done\nMOVQ AX,(CX)\ndone:"},
		{"loop reintroduces literal", "LEAQ choice<>(SB),R8\nMOVQ SI,CX\nagain:\nCMPQ CX,R8\nJE done\nMOVQ R8,CX\nMOVQ 64(CX),AX\nJMP again\ndone:"},
	} {
		t.Run(row.name, func(t *testing.T) {
			fn, sig, _ := fixedLocalPointerChoiceFixture(t, row.body)
			if _, err := proveX86FixedLocal(fn, sig); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("conditional pointer invented an origin, access or predicate", err)
			}
		})
	}
}
