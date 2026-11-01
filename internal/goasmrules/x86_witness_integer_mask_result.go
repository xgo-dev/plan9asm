package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// Vector input width/tuple and K result/writemask are independent roles.
// Matching this physical format grants no input, memory or numeric authority.
type x86IntegerMaskResultFormat struct {
	width, broadcast  int
	masked, immediate bool
	encoding          x86PackedAVXOpcode
}

func x86IntegerMaskResultFormatForRule(rule X86AVXRule) (x86IntegerMaskResultFormat, error) {
	f := x86IntegerMaskResultFormat{immediate: rule.Ytab == "_yvpcmpb"}
	fail := func() (x86IntegerMaskResultFormat, error) {
		return f, fmt.Errorf("integer mask-result input/tuple/K roles differ from their official format")
	}
	first, plain, masked := 0, "Zevex_rm_v_r", "Zevex_rm_v_k_r"
	if f.immediate {
		first, plain, masked = 1, "Zevex_i_rm_v_r", "Zevex_i_rm_v_k_r"
	}
	f.masked = rule.ZCase == masked
	count := first + 3
	if f.masked {
		count++
	}
	if rule.Ytab != "_yvpcmpb" && rule.Ytab != "_yvpshufbitqmb" || rule.Prefix != "Pavx" || rule.ZCase != plain && !f.masked ||
		len(rule.Classes) != count || f.immediate && rule.Classes[0] != "Yu8" || rule.Classes[count-1] != "Yk" ||
		f.masked && rule.Classes[first+2] != "Yknot0" {
		return fail()
	}
	f.width = map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[rule.Classes[first]]
	second := map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[f.width]
	member, valid := strings.CutPrefix(rule.Opcode, "VPCMP")
	member = strings.TrimPrefix(member, "U")
	pp, opcodeMap, mapByte := "66", "0F3A", byte(3)
	if !f.immediate {
		member, valid = strings.CutPrefix(rule.Opcode, "VPTESTM")
		if !valid {
			member, valid = strings.CutPrefix(rule.Opcode, "VPTESTNM")
			pp = "F3"
		}
		opcodeMap, mapByte = "0F38", 2
	}
	if !valid || len(member) != 1 || f.width == 0 || rule.Classes[first+1] != second {
		return fail()
	}
	bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}[member[0]]
	if bits == 0 {
		return fail()
	}
	widthIndex := map[int]int{128: 0, 256: 1, 512: 2}[f.width]
	maskIndex := 0
	if f.masked {
		maskIndex = 1
	}
	if rule.RowIndex != widthIndex*2+maskIndex || rule.ZOffset != maskIndex*3 ||
		rule.EncodingOffset != widthIndex*3 || len(rule.OpBytes) != 9 {
		return fail()
	}
	w := "W0"
	if bits == 16 || bits == 64 {
		w = "W1"
	}
	offset := rule.EncodingOffset
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", "evex" + strconv.Itoa(f.width), "evex" + pp, "evex" + opcodeMap, "evex" + w,
	}, nil); err != nil {
		return fail()
	}
	required := []string{"evexN" + strconv.Itoa(f.width/8)}
	if bits >= 32 {
		f.broadcast = bits / 8
		required = append(required, "evexBcstN"+strconv.Itoa(f.broadcast))
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], required, nil); err != nil {
		return fail()
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[offset+2], 0, 8)
	if err != nil {
		return fail()
	}
	if !f.immediate {
		want := uint64(0x26)
		if bits >= 32 {
			want++
		}
		if opcode != want {
			return fail() // The shared ytab also has a distinct VPSHUFBITQMB opcode.
		}
	}
	f.encoding = x86PackedAVXOpcode{kind: "evex", mapByte: mapByte, pp: 1, length: byte(widthIndex), opcode: byte(opcode)}
	if pp == "F3" {
		f.encoding.pp = 2
	}
	if w == "W1" {
		f.encoding.wBit = 0x80
	}
	return f, nil
}

func x86IntegerMaskResultRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86IntegerMaskResultFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	physical := x86VectorResultFormat{width: f.width, masked: f.masked, broadcast: f.broadcast != 0, maskResult: true, encoding: f.encoding}
	return physical.witnessesWithControl(rule.Opcode, f.immediate, 7), nil
}
