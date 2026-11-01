package goasmrules

import (
	"fmt"
	"strconv"
)

// The three original FP-control tables share emission with leading-immediate
// vector rows. Scalar N4/N8 tuples do not change the X register carrier or
// certify MXCSR, old-destination, numerical input or native memory authority.
func x86FloatingImmediateControlRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f := x86VectorResultFormat{unary: rule.Ytab == "_yvgetmantpd"}
	fail := func() ([]X86PackedBinaryWitness, error) {
		return nil, fmt.Errorf("FP immediate source/carrier/tuple/SAE differs from its official format")
	}
	scalar := rule.Ytab == "_yvfixupimmsd"
	if !f.unary && !scalar && rule.Ytab != "_yvfixupimmpd" {
		return fail()
	}
	plain, masked, count := "Zevex_i_rm_v_r", "Zevex_i_rm_v_k_r", 4
	if f.unary {
		plain, masked, count = "Zevex_i_rm_r", "Zevex_i_rm_k_r", 3
	}
	f.masked = rule.ZCase == masked
	maskIndex := 0
	if f.masked {
		count, maskIndex = count+1, 1
	}
	if len(rule.Opcode) < 2 || rule.Prefix != "Pavx" || rule.ZCase != plain && !f.masked || len(rule.Classes) != count ||
		rule.Classes[0] != "Yu8" || f.masked && rule.Classes[count-2] != "Yknot0" {
		return fail()
	}
	f.width = map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[rule.Classes[1]]
	register := map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[f.width]
	index := map[int]int{512: 0, 128: 1, 256: 2}[f.width] // Original Z, X, Y order.
	extent, tuple := 9, f.width/8
	precision, w := 4, "evexW0"
	suffix := rule.Opcode[len(rule.Opcode)-2:]
	if suffix == "PD" || suffix == "SD" {
		precision, w = 8, "evexW1"
	}
	if scalar {
		index, extent, tuple = 0, 3, precision
	}
	if f.width == 0 || scalar && (f.width != 128 || suffix != "SS" && suffix != "SD") ||
		!scalar && suffix != "PS" && suffix != "PD" || rule.Classes[count-1] != register ||
		!f.unary && rule.Classes[2] != register || rule.RowIndex != index*2+maskIndex ||
		rule.EncodingOffset != index*3 || rule.ZOffset != maskIndex*3 || len(rule.OpBytes) != extent {
		return fail()
	}
	offset := rule.EncodingOffset
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", "evex" + strconv.Itoa(f.width), "evex66", "evex0F3A", w,
	}, nil); err != nil {
		return fail()
	}
	f.broadcast, f.sae = !scalar, scalar || f.width == 512
	features := []string{"evexN" + strconv.Itoa(tuple), "evexZeroingEnabled"}
	if f.broadcast {
		features = append(features, "evexBcstN"+strconv.Itoa(precision))
	}
	if f.sae {
		features = append(features, "evexSaeEnabled")
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], features, nil); err != nil {
		return fail()
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[offset+2], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding = x86PackedAVXOpcode{kind: "evex", mapByte: 3, pp: 1,
		length: map[int]byte{128: 0, 256: 1, 512: 2}[f.width], opcode: byte(opcode)}
	if precision == 8 {
		f.encoding.wBit = 0x80
	}
	return f.witnesses(rule.Opcode), nil
}
