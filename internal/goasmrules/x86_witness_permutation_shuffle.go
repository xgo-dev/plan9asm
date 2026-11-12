package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// These source schemas share transport, not selector topology, old values or
// native-access authority. The literal opcode remains in the original payload.
func x86PermutationShuffleRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f := x86VectorResultFormat{}
	fail := func() ([]X86PackedBinaryWitness, error) {
		return nil, fmt.Errorf("permutation source/control/result differs from its official format")
	}
	immediate := strings.Contains(rule.ZCase, "_i_")
	f.unary = immediate && (rule.ZCase == "Zvex_i_rm_r" || rule.ZCase == "Zevex_i_rm_r" || rule.ZCase == "Zevex_i_rm_k_r")
	f.masked = rule.ZCase == "Zevex_rm_v_k_r" || rule.ZCase == "Zevex_i_rm_k_r" || rule.ZCase == "Zevex_i_rm_v_k_r"
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	first, count, kind := 0, 3, "vex"
	if immediate {
		first, count = 1, 4
		if f.unary {
			count--
		}
	}
	if f.masked {
		count++
	}
	if evex {
		kind = "evex"
	}
	plain := "Zvex_rm_v_r"
	if immediate {
		plain = "Zvex_i_rm_v_r"
		if f.unary {
			plain = "Zvex_i_rm_r"
		}
	}
	if evex {
		plain = strings.Replace(plain, "Zvex_", "Zevex_", 1)
	}
	selector := 7
	if immediate && len(rule.Classes) > 0 && rule.Classes[0] == "Yi8" && !evex {
		selector = -1
	}
	if rule.Prefix != "Pavx" || rule.ZCase != plain && !f.masked || len(rule.Classes) != count ||
		immediate && rule.Classes[0] != "Yu8" && selector != -1 ||
		f.masked && rule.Classes[count-2] != "Yknot0" {
		return fail()
	}
	f.width = map[string]int{"Yxm": 128, "Yym": 256}[rule.Classes[first]]
	register := map[int]string{128: "Yxr", 256: "Yyr"}[f.width]
	if evex {
		f.width = map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[rule.Classes[first]]
		register = map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[f.width]
	}
	if f.width == 0 || rule.Classes[count-1] != register || !f.unary && rule.Classes[first+1] != register {
		return fail()
	}
	widthIndex, maskIndex := map[int]int{128: 0, 256: 1, 512: 2}[f.width], 0
	if f.masked {
		maskIndex = 1
	}
	index, offset, zoffset, extent := 0, 0, 2, 2
	switch rule.Ytab {
	case "_yvperm2f128":
		if evex || f.width != 256 || !immediate || f.unary || selector < 0 {
			return fail()
		}
	case "_yvpermd":
		if immediate || f.width == 128 || !evex && f.width != 256 {
			return fail()
		}
		extent = 8
		if evex {
			index, offset, zoffset = 1+(widthIndex-1)*2+maskIndex, 2+(widthIndex-1)*3, maskIndex*3
		}
	case "_yvpermilpd":
		extent = 26
		index, offset = 4+widthIndex, 4+widthIndex*2
		if immediate {
			index, offset, zoffset = widthIndex*2, widthIndex*2, 0
			if selector < 0 {
				index, zoffset = index+1, 2
			}
		}
		if evex {
			index, offset, zoffset = 12+widthIndex*2+maskIndex, 17+widthIndex*3, maskIndex*3
			if immediate {
				index, offset = 6+widthIndex*2+maskIndex, 8+widthIndex*3
			}
		}
	case "_yvpermq":
		if f.width == 128 || !evex && (!immediate || f.width != 256) {
			return fail()
		}
		extent = 14
		index, zoffset = 0, 0
		if selector < 0 {
			index, zoffset = 1, 2
		}
		if evex {
			index, offset, zoffset = 6+(widthIndex-1)*2+maskIndex, 8+(widthIndex-1)*3, maskIndex*3
			if immediate {
				index, offset = 2+(widthIndex-1)*2+maskIndex, 2+(widthIndex-1)*3
			}
		}
	case "_yvshuff32x4":
		if !evex || f.width == 128 || !immediate || f.unary {
			return fail()
		}
		index, offset, zoffset, extent = (widthIndex-1)*2+maskIndex, (widthIndex-1)*3, maskIndex*3, 6
	default:
		return fail()
	}
	if !evex && f.width == 512 || rule.RowIndex != index || rule.EncodingOffset != offset ||
		rule.ZOffset != zoffset || len(rule.OpBytes) != extent {
		return fail()
	}
	w, bits := "W0", 32
	if rule.Ytab == "_yvpermq" || strings.HasSuffix(rule.Opcode, "64X2") ||
		evex && rule.Ytab == "_yvpermilpd" && strings.HasSuffix(rule.Opcode, "PD") {
		w, bits = "W1", 64
	}
	opcodeMap, mapByte := "0F38", byte(2)
	if immediate {
		opcodeMap, mapByte = "0F3A", 3
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", kind + strconv.Itoa(f.width), kind + "66", kind + opcodeMap, kind + w,
	}, nil); err != nil {
		return fail()
	}
	opcodeOffset := offset + 1
	if evex {
		features := []string{"evexN" + strconv.Itoa(f.width/8), "evexBcstN" + strconv.Itoa(bits/8), "evexZeroingEnabled"}
		if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], features, nil); err != nil {
			return fail()
		}
		f.broadcast, opcodeOffset = true, opcodeOffset+1
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[opcodeOffset], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding = x86PackedAVXOpcode{kind: kind, mapByte: mapByte, pp: 1, length: byte(widthIndex), opcode: byte(opcode)}
	if w == "W1" {
		f.encoding.wBit = 0x80
	}
	return f.witnessesWithControl(rule.Opcode, immediate, selector), nil
}
