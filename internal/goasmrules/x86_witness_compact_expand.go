package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

func x86PackedCompactFormatForRule(rule X86AVXRule) (x86PackedUnaryMemoryFormat, error) {
	f := x86PackedUnaryMemoryFormat{store: rule.Ytab == "_yvcompresspd"}
	fail := func() (x86PackedUnaryMemoryFormat, error) {
		return f, fmt.Errorf("compact/expand direction, carrier or element tuple differs from its official format")
	}
	stem, plain, masked := "EXPAND", "Zevex_rm_v_r", "Zevex_rm_k_r"
	if f.store {
		stem, plain, masked = "COMPRESS", "Zevex_r_v_rm", "Zevex_r_k_rm"
	}
	f.masked = rule.ZCase == masked
	count, maskIndex := 2, 0
	if f.masked {
		count, maskIndex = 3, 1
	}
	if rule.Prefix != "Pavx" || rule.Ytab != "_yvcompresspd" && rule.Ytab != "_yvexpandpd" ||
		rule.ZCase != plain && !f.masked || len(rule.Classes) != count || f.masked && rule.Classes[1] != "Yknot0" {
		return fail()
	}
	first, last := rule.Classes[0], rule.Classes[count-1]
	if f.store {
		first, last = last, first
	}
	f.width = map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[first]
	register := map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[f.width]
	widthIndex := map[int]int{128: 0, 256: 1, 512: 2}[f.width]
	prefix, integer := "V", strings.HasPrefix(rule.Opcode, "VP")
	if integer {
		prefix = "VP"
	}
	member, valid := strings.CutPrefix(rule.Opcode, prefix+stem)
	f.tuple = map[string]int{"B": 1, "W": 2, "D": 4, "Q": 8, "PS": 4, "PD": 8}[member]
	if !valid || f.tuple == 0 || integer == strings.HasPrefix(member, "P") || f.width == 0 || last != register ||
		rule.RowIndex != widthIndex*2+maskIndex || rule.ZOffset != maskIndex*3 ||
		rule.EncodingOffset != widthIndex*3 || len(rule.OpBytes) != 9 {
		return fail()
	}
	f.carrier = f.width / 8
	w := "evexW0"
	if f.tuple == 2 || f.tuple == 8 {
		w = "evexW1"
	}
	offset := rule.EncodingOffset
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", "evex" + strconv.Itoa(f.width), "evex66", "evex0F38", w,
	}, nil); err != nil {
		return fail()
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], []string{
		"evexN" + strconv.Itoa(f.tuple), "evexZeroingEnabled",
	}, nil); err != nil {
		return fail()
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[offset+2], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding = x86PackedAVXOpcode{kind: "evex", mapByte: 2, pp: 1, length: byte(widthIndex), opcode: byte(opcode)}
	if w == "evexW1" {
		f.encoding.wBit = 0x80
	}
	return f, nil
}

func x86PackedCompactRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86PackedCompactFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	return f.witnesses(rule.Opcode), nil
}
