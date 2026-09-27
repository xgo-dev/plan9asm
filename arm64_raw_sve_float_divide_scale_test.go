package plan9asm

import (
	"fmt"
	"strings"
	"testing"
)

func arm64RawSVEFloatDivideScaleCases() []arm64RawSVEFloatArithmeticCase {
	var forms []arm64RawSVEFloatArithmeticCase
	for _, op := range []string{"fdiv", "fdivr", "fscale"} {
		for size := 1; size < 4; size++ {
			forms = append(forms, arm64RawSVEFloatArithmeticCase{op: op, size: size, mode: "predicated"})
		}
	}
	return forms
}

func TestARM64RawSVEFloatDivideScaleCompleteFormats(t *testing.T) {
	testARM64RawSVEFloatArithmeticObjects(t, arm64RawSVEFloatDivideScaleCases())
}

func TestARM64RawSVEFloatDivideScaleOperandFields(t *testing.T) {
	var lines []string
	var wants []Instr
	for _, form := range arm64RawSVEFloatDivideScaleCases() {
		for field, limit := range [3]int{32, 32, 8} {
			for value := 0; value < limit; value++ {
				fields := [3]int{31, 30, 7}
				fields[field] = value
				dst, second, predicate := fields[0], fields[1], fields[2]
				lines = append(lines, form.assembly(dst, dst, second, predicate))
				register := func(number int) Operand {
					return Operand{Kind: OpReg, Reg: Reg(fmt.Sprintf("Z%d.%c", number, "BHSD"[form.size]))}
				}
				wants = append(wants, Instr{Op: Op("Z" + strings.ToUpper(form.op)), Args: []Operand{
					register(second), register(dst), {Kind: OpReg, Reg: Reg(fmt.Sprintf("P%d.M", predicate))}, register(dst),
				}})
			}
		}
	}
	for i, word := range assembleARM64LLVMWords(t, lines, "+sve") {
		got, ok := decodeARM64RawSVEFloatDivideScale(word)
		if !ok || got.Op != wants[i].Op || fmt.Sprint(got.Args) != fmt.Sprint(wants[i].Args) {
			t.Fatalf("%s: decoded %#08x as %+v, %v; want %+v", lines[i], word, got, ok, wants[i])
		}
		if got, ok := decodeARM64RawSVEFloatDivideScale(word &^ (3 << 22)); ok {
			t.Errorf("reserved byte-width encoding decoded as %+v", got)
		}
	}
	for _, word := range []uint32{0x65008000, 0x650da000, 0x65098000, 0x658da000, 0x65808000} {
		if got, ok := decodeARM64RawSVEFloatDivideScale(word); ok {
			t.Errorf("neighboring/reserved word %#08x decoded as %+v", word, got)
		}
	}
}
