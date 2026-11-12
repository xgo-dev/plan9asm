package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

func x86PackedSingleSourceNarrowFormatForRule(rule X86AVXRule) (x86PackedUnaryMemoryFormat, error) {
	f := x86PackedUnaryMemoryFormat{masked: rule.ZCase == "Zevex_r_k_rm", store: true}
	fail := func() (x86PackedUnaryMemoryFormat, error) {
		return f, fmt.Errorf("single-source narrowing source/tuple/carrier differs from its official format")
	}
	if rule.Prefix != "Pavx" || rule.Ytab != "_yvpmovdb" && rule.Ytab != "_yvpmovdw" ||
		rule.ZCase != "Zevex_r_v_rm" && !f.masked || len(rule.Classes) != 2 && !f.masked ||
		f.masked && (len(rule.Classes) != 3 || rule.Classes[1] != "Yknot0") {
		return fail()
	}
	f.width = map[string]int{"YxrEvex": 128, "YyrEvex": 256, "Yzr": 512}[rule.Classes[0]]
	pair, found := strings.CutPrefix(rule.Opcode, "VPMOV")
	if !found {
		return fail()
	}
	pair = strings.TrimPrefix(strings.TrimPrefix(pair, "US"), "S")
	if len(pair) != 2 {
		return fail()
	}
	bits := map[byte]int{'B': 8, 'W': 16, 'D': 32, 'Q': 64}
	input, output := bits[pair[0]], bits[pair[1]]
	if input <= output || output == 0 || f.width == 0 ||
		(rule.Ytab == "_yvpmovdw") != (input/output == 2) {
		return fail()
	}
	f.tuple, f.carrier = f.width/8*output/input, 16
	destination := "YxmEvex"
	if f.tuple > 16 {
		f.carrier, destination = 32, "YymEvex"
	}
	widthIndex := map[int]int{128: 0, 256: 1, 512: 2}[f.width]
	maskIndex := 0
	if f.masked {
		maskIndex = 1
	}
	if rule.Classes[len(rule.Classes)-1] != destination || rule.RowIndex != widthIndex*2+maskIndex ||
		rule.ZOffset != maskIndex*3 || rule.EncodingOffset != widthIndex*3 || len(rule.OpBytes) != 9 {
		return fail()
	}
	offset := rule.EncodingOffset
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", "evex" + strconv.Itoa(f.width), "evexF3", "evex0F38", "evexW0",
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
	f.encoding = x86PackedAVXOpcode{kind: "evex", mapByte: 2, pp: 2, length: byte(widthIndex), opcode: byte(opcode)}
	return f, nil
}

func x86PackedSingleSourceNarrowRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86PackedSingleSourceNarrowFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	return f.witnesses(rule.Opcode), nil
}
