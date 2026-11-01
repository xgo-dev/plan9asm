package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func TestARMWordFloatGrammarSharesExactScratchInventory(t *testing.T) {
	for _, fixture := range armFloatConversionEffectCases() {
		t.Run(strings.ReplaceAll(fixture.instruction, " ", "_"), func(t *testing.T) {
			file, err := Parse(ArchARM, "TEXT conversion(SB),4,$0-0\nCMP R0,R0\n"+fixture.instruction+"\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[2] // TEXT, CMP, conversion, RET.
			op, _, _, _ := armDecodeOp(string(ins.Op))
			form, handled, err := parseARMWordFloatConversion(op, ins)
			if err != nil || !handled {
				t.Fatalf("valid Go conversion rejected: handled=%v, err=%v", handled, err)
			}
			wantScratch := strings.Contains(fixture.instruction, "R2")
			if form.usesScratch() != wantScratch {
				t.Fatalf("scratch=%v want %v", form.usesScratch(), wantScratch)
			}
			ir, err := Translate(file, Options{
				Goarch: "arm", TargetTriple: "armv7-unknown-linux-gnueabihf",
				Sigs: map[string]FuncSig{"conversion": {Name: "conversion", Ret: Void}},
			})
			if err != nil {
				t.Fatal(err)
			}
			wantAllocation := wantScratch || strings.Contains(fixture.instruction, "F15")
			if strings.Contains(ir, "%freg_F15 = alloca i64") != wantAllocation {
				t.Fatalf("F15 allocation disagrees with typed effect, want %v:\n%s", wantAllocation, ir)
			}
		})
	}
}

func TestARMWordFloatGrammarKeepsRawSingleInstructionsDistinct(t *testing.T) {
	for _, word := range []uint32{0xeef80aee, 0xeeb81a4f, 0xeefd1aef, 0xeebc2ac0} {
		ins, err := decodeARMRawWordInstruction(Instr{
			Op: OpWORD, Args: []Operand{{Kind: OpImm, Imm: int64(word)}}, Raw: fmt.Sprintf("WORD $%#x", word),
		})
		if err != nil {
			t.Fatal(err)
		}
		op, _, _, _ := armDecodeOp(string(ins.Op))
		form, handled, err := parseARMWordFloatConversion(op, ins)
		if err != nil || !handled || form.usesScratch() {
			t.Fatalf("raw %#x acquired a Go macro effect: %+v, %v", word, form, err)
		}
		if form.source.kind == armConversionSingle || form.destination.kind == armConversionSingle {
			ins.Raw = "source spelling without decoder provenance"
			if _, _, err := parseARMWordFloatConversion(op, ins); err == nil {
				t.Fatalf("source Go spelling accepted decoder-only S registers: %#x", word)
			}
		} else if form.source.kind != armConversionFloat || form.destination.kind != armConversionFloat {
			// The architectural decoder may spell two even halves with their
			// exact Go F aliases. Neither spelling introduces a core-register macro.
			t.Fatalf("raw %#x lost its physical floating operands: %+v", word, form)
		}
	}
}

func TestARMWordFloatGrammarRejectsAdjacentOperandAndSuffixClasses(t *testing.T) {
	rejectARMFormsOutsideGo127Optabs(t, []string{
		"MOVWF S0,F1", "MOVWD S0,F1", "MOVFW F0,S1", "MOVDW F0,S1",
		"MOVWF F16,F0", "MOVWD R16,F0", "MOVFW F0,F16", "MOVDW F0,R16",
		"MOVWF $1,F0", "MOVWD symbol(SB),F0", "MOVFW F0,result+0(FP)",
		"MOVDW F0,(R0)", "MOVWF.P R0,F0", "MOVWD.W R0,F0",
		"MOVFW.S F0,R0", "MOVDW.PW F0,R0",
	})
}
