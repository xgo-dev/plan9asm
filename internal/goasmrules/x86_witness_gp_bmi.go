package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// These four scalar transports share the original VEX payload, not numerical
// semantics. In particular, MULX's vvvv operand is an output, not an input.
type x86GPBMIFormat struct {
	width, immediate    int
	reversed, extension bool
	digit               byte
	encoding            x86PackedAVXOpcode
}

func x86GPBMITab(table string) bool {
	return table == "_yandnl" || table == "_ybextrl" || table == "_yblsil" || table == "_yrorxl"
}

func x86GPBMIFormatForRule(rule X86AVXRule) (x86GPBMIFormat, error) {
	f := x86GPBMIFormat{width: 32, immediate: -1}
	f.encoding.kind = "vex"
	fail := func() (x86GPBMIFormat, error) {
		return f, fmt.Errorf("%s scalar GP roles/row/VEX payload differ from the original format", rule.Opcode)
	}
	if !x86GPBMITab(rule.Ytab) || rule.Prefix != "Pavx" || rule.EncodingOffset != 0 {
		return fail()
	}
	classes, zcase, zoffset, row, stride := "Yml,Yrl,Yrl", "Zvex_rm_v_r", 2, 0, 2
	mapTerm := "vex0F38"
	optional := []string{"vexW0", "vexW1", "vexF2", "vexF3"}
	switch rule.Ytab {
	case "_ybextrl":
		f.reversed = true
		classes, zcase = "Yrl,Yml,Yrl", "Zvex_v_rm_r"
		optional = append(optional, "vex66")
	case "_yblsil":
		f.extension = true
		classes, zcase, zoffset, stride = "Yml,Yrl", "Zvex_rm_r_vo", 3, 3
		optional = []string{"vexW0", "vexW1"}
	case "_yrorxl":
		f.immediate = 1
		classes, zcase, zoffset, mapTerm = "Yu8,Yml,Yrl", "Zvex_i_rm_r", 0, "vex0F3A"
		if rule.RowIndex == 1 {
			f.immediate, classes, zoffset, row = 255, "Yi8,Yml,Yrl", 2, 1
		}
		optional = []string{"vexW0", "vexW1", "vexF2"}
	}
	if rule.RowIndex != row || rule.ZOffset != zoffset || rule.ZCase != zcase ||
		strings.Join(rule.Classes, ",") != classes || len(rule.OpBytes) != stride {
		return fail()
	}
	atoms, err := x86PackedEncodingAtoms(rule.OpBytes[0], []string{"avxEscape", "vex128", mapTerm}, optional)
	if err != nil || atoms["vexW0"] == atoms["vexW1"] {
		return fail()
	}
	if atoms["vexW1"] {
		f.width, f.encoding.wBit = 64, 0x80
	}
	if !strings.HasSuffix(rule.Opcode, "L") && !strings.HasSuffix(rule.Opcode, "Q") ||
		strings.HasSuffix(rule.Opcode, "Q") != (f.width == 64) {
		return fail()
	}
	prefixes := 0
	for index, prefix := range []string{"66", "F3", "F2"} {
		if atoms["vex"+prefix] {
			prefixes++
			f.encoding.pp = byte(index + 1)
		}
	}
	if prefixes > 1 || f.immediate >= 0 && !atoms["vexF2"] {
		return fail()
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[1], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding.mapByte, f.encoding.opcode = 2, byte(opcode)
	if f.immediate >= 0 {
		f.encoding.mapByte = 3
	}
	if f.extension {
		digit, err := strconv.ParseUint(rule.OpBytes[2], 0, 3)
		if err != nil {
			return fail()
		}
		f.digit = byte(digit)
	}
	return f, nil
}

func x86GPBMIRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86GPBMIFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	var witnesses []X86PackedBinaryWitness
	for _, memory := range []bool{false, true} {
		rm, modrm := "AX", byte(0xd8) // BX is ModRM.reg; AX is r/m.
		if memory {
			rm, modrm = "(AX)", 0x18
		}
		first, second, destination, vvvv := rm, "CX", "BX", byte(0x70)
		operands := first + "," + second + "," + destination
		if f.reversed {
			first, second = second, first
			operands = first + "," + second + "," + destination
		} else if f.extension {
			second, destination = "", "CX" // Result is VEX.vvvv; reg is literal /digit.
			modrm = modrm&0xc7 | f.digit<<3
			operands = first + "," + destination
		} else if f.immediate >= 0 {
			second, vvvv = "", 0x78 // The original immediate transport reserves vvvv.
			immediate := "$1"
			if f.immediate == 255 {
				immediate = "$-1"
			}
			operands = immediate + "," + first + "," + destination
		}
		encoded := f.encoding.bytes(vvvv, 0, 0, modrm)
		if f.immediate >= 0 {
			encoded = append(encoded, byte(f.immediate))
		}
		witnesses = append(witnesses, X86PackedBinaryWitness{
			Instruction: rule.Opcode + " " + operands, Generation: "vex",
			First: first, Second: second, Destination: destination,
			Width: f.width, Memory: memory, Encoding: encoded,
		})
	}
	return witnesses, nil
}
