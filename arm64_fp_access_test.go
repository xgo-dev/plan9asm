package plan9asm

import (
	"fmt"
	"reflect"
	"testing"
)

func TestARM64WideFPAccessUsesCompleteIntegerPairGrammar(t *testing.T) {
	want := map[Op]arm64IntegerPairSpec{
		"LDP":   {elementBytes: 8, load: true},
		"LDPW":  {elementBytes: 4, load: true},
		"LDPSW": {elementBytes: 4, load: true, signed: true},
		"STP":   {elementBytes: 8},
		"STPW":  {elementBytes: 4},
	}
	if !reflect.DeepEqual(arm64IntegerPairSpecs, want) {
		t.Fatalf("integer pair grammar changed: %+v", arm64IntegerPairSpecs)
	}
	for op, spec := range want {
		for _, offset := range []int64{0, 1, 7, 8, 512, 16384} {
			instruction := fmt.Sprintf("%s frame+%d(FP), (R3, R4)", op, offset)
			memoryIndex := 0
			if !spec.load {
				instruction = fmt.Sprintf("%s (R3, R4), frame+%d(FP)", op, offset)
				memoryIndex = 1
			}
			t.Run(instruction, func(t *testing.T) {
				source := "TEXT span(SB),$0-20000\n" + instruction + "\nRET\n"
				requireARM64GoAssemblerResult(t, source, true)
				file, err := Parse(ArchARM64, source)
				if err != nil {
					t.Fatal(err)
				}
				got := ARM64FPAccessBytes(file.Funcs[0].Instrs[1], memoryIndex)
				if got != int64(spec.elementBytes*2) {
					t.Fatalf("byte width=%d, want %d", got, spec.elementBytes*2)
				}
			})
		}
	}
	for _, instruction := range []string{
		"FMOVQ frame+0(FP), F0", "FMOVQ F31, frame+8(FP)",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT span(SB),$0-32\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, true)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				t.Fatal(err)
			}
			ins := file.Funcs[0].Instrs[1]
			for i, operand := range ins.Args {
				if operand.Kind == OpFP && ARM64FPAccessBytes(ins, i) != 16 {
					t.Fatal("quad FP memory operand lost its full sixteen-byte span")
				}
			}
		})
	}
}

func TestARM64WideFPAccessCannotInventSpansForMalformedForms(t *testing.T) {
	for _, instruction := range []string{
		"LDP.W frame+0(FP), (R3, R4)", "LDP.P frame+0(FP), (R3, R4)",
		"LDP frame+0(FP), (R3, R3)", "LDP frame+0(FP), (F3, F4)",
		"LDP frame+0(FP), R3", "LDP frame+0(FP), (R3, R4), R5",
		"STP (F3, F4), frame+0(FP)", "LDP (R3, R4), frame+0(FP)",
		"FMOVQ frame+0(FP), R3", "FMOVQ.W F0, frame+0(FP)",
	} {
		t.Run(instruction, func(t *testing.T) {
			source := "TEXT span(SB),$0-16\n" + instruction + "\nRET\n"
			requireARM64GoAssemblerResult(t, source, false)
			file, err := Parse(ArchARM64, source)
			if err != nil {
				return
			}
			ins := file.Funcs[0].Instrs[1]
			for i := -1; i <= len(ins.Args); i++ {
				if got := ARM64FPAccessBytes(ins, i); got != 0 {
					t.Fatalf("malformed operand acquired a %d-byte span", got)
				}
			}
		})
	}
	for _, offset := range []int64{-8, 1<<63 - 8} {
		ins := Instr{Op: "LDP", Args: []Operand{
			{Kind: OpFP, FPOffset: offset},
			{Kind: OpRegList, RegList: []Reg{"R3", "R4"}},
		}}
		if ARM64FPAccessBytes(ins, 0) != 0 {
			t.Fatalf("invalid/overflowing offset acquired a span: %d", offset)
		}
	}
}
