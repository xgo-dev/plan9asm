package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// Original operand transport, not initialized values or native storage. The official row and its payload remain the encoding authority.
type x86MoveRemainderFormat struct {
	width, tuple     int
	rm, reg, vvvv    int
	classes          []string
	masked, zeroable bool
	encoding         x86PackedAVXOpcode
}

func x86MoveRemainderTable(table string) bool {
	switch table {
	case "_yvlddqu", "_yvmaskmovdqu", "_yvmaskmovpd", "_yvmovd",
		"_yvmovhlps", "_yvmovhpd", "_yvmovmskpd", "_yvmovntdq",
		"_yvmovntdqa", "_yvmovq", "_yvmovsd":
		return true
	}
	return false
}

func x86MoveRemainderFormatForRule(rule X86AVXRule) (x86MoveRemainderFormat, error) {
	f := x86MoveRemainderFormat{width: 128, rm: 0, vvvv: -1}
	fail := func() (x86MoveRemainderFormat, error) {
		return f, fmt.Errorf("move row differs from its original finite transport")
	}
	if !x86MoveRemainderTable(rule.Ytab) || rule.Prefix != "Pavx" || rule.Opcode == "" ||
		rule.EncodingOffset < 0 || rule.EncodingOffset >= len(rule.OpBytes) {
		return fail()
	}
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	kind, stride := "vex", 2
	if evex {
		kind, stride = "evex", 3
	}
	header := rule.OpBytes[rule.EncodingOffset]
	if hasEncodingTerm(header, kind+"256") {
		f.width = 256
	} else if hasEncodingTerm(header, kind+"512") {
		f.width = 512
	}
	v := map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[f.width]
	if evex && f.width != 512 {
		v += "Evex"
	}
	index, offset, extent := rule.RowIndex, rule.EncodingOffset, 0
	wantIndex, wantOffset, wantStride := 0, 0, stride
	store, tupleAttribute, zeroAttribute := false, evex, false
	zcase := kind + "_rm_v_r"
	classes := ""
	pp, w, opcodeMap := "", "W0", "0F"
	switch rule.Ytab {
	case "_yvlddqu", "_yvmovmskpd":
		if evex || f.width == 512 {
			return fail()
		}
		wantIndex, wantOffset, extent = f.width/256, 2*(f.width/256), 4
		classes, f.tuple = "Ym,"+v, f.width/8
		pp = "F2"
		if rule.Ytab == "_yvmovmskpd" {
			classes, f.tuple, pp = v+",Yrl", 0, "66"
			if strings.HasSuffix(rule.Opcode, "PS") {
				pp = ""
			}
		}
	case "_yvmaskmovdqu":
		if evex || f.width != 128 {
			return fail()
		}
		classes, pp, extent = v+","+v, "66", 2
	case "_yvmaskmovpd":
		if evex || f.width == 512 || index < 0 || index > 3 {
			return fail()
		}
		store, f.tuple, f.vvvv, pp, opcodeMap = index < 2, f.width/8, 1, "66", "0F38"
		wantIndex = f.width / 256
		if !store {
			wantIndex += 2
		}
		wantOffset, extent = 2*wantIndex, 8
		classes = "Ym," + v + "," + v
		if store {
			classes = v + "," + v + ",Ym"
		}
		if strings.HasSuffix(rule.Opcode, "Q") {
			w = "W1"
		}
	case "_yvmovntdq", "_yvmovntdqa":
		if !evex && f.width == 512 {
			return fail()
		}
		wantIndex, wantOffset, extent = f.width/256, 2*(f.width/256), 13
		if evex {
			wantIndex += 2
			wantOffset = 4 + 3*(wantIndex-2)
		}
		store, f.tuple, pp = rule.Ytab == "_yvmovntdq", f.width/8, "66"
		classes = "Ym," + v
		if store {
			classes = v + ",Ym"
			if strings.HasSuffix(rule.Opcode, "PS") {
				pp = ""
			} else if evex && strings.HasSuffix(rule.Opcode, "PD") {
				w = "W1"
			}
		} else {
			opcodeMap = "0F38"
		}
	case "_yvmovhlps":
		if f.width != 128 {
			return fail()
		}
		classes, f.vvvv, tupleAttribute, extent = v+","+v+","+v, 1, false, 5
		if evex {
			wantIndex, wantOffset = 1, 2
		}
	case "_yvmovhpd", "_yvmovd":
		if f.width != 128 || index < 0 || index > 3 || evex != (index >= 2) {
			return fail()
		}
		store, wantIndex, extent = index%2 == 0, index, 10
		wantOffset = []int{0, 2, 4, 7}[index]
		f.tuple = 8
		transfer := "Ym"
		if rule.Ytab == "_yvmovd" {
			transfer, f.tuple, pp = "Yml", 4, "66"
		} else if strings.HasSuffix(rule.Opcode, "PD") {
			pp = "66"
			if evex {
				w = "W1"
			}
		}
		classes = transfer + "," + v
		if store {
			classes = v + "," + transfer
		} else if rule.Ytab == "_yvmovhpd" {
			classes, f.vvvv = transfer+","+v+","+v, 1
		}
	case "_yvmovq":
		if f.width != 128 || index < 0 || index > 7 || evex != (index >= 4) {
			return fail()
		}
		local := index % 4
		store, wantIndex, f.tuple, pp, w, extent = local < 2, index, 8, "66", "W1", 20
		wantOffset = 2 * index
		if evex {
			wantOffset = 8 + 3*(index-4)
		} else if local == 1 {
			w = "W0"
		}
		transfer := "Yml"
		if local%2 != 0 {
			transfer = "Yxm"
			if evex {
				transfer += "Evex"
			}
		}
		if local == 3 {
			pp = "F3"
			if !evex {
				w = "W0"
			}
		}
		classes = transfer + "," + v
		if store {
			classes = v + "," + transfer
		}
	case "_yvmovsd":
		if f.width != 128 || index < 0 || index > 11 || evex != (index >= 4) {
			return fail()
		}
		wantIndex, extent = index, 20
		wantOffset = []int{0, 2, 4, 6, 8, 8, 11, 11, 14, 14, 17, 17}[index]
		if evex && index%2 == 0 {
			wantStride = 0
		}
		pp, f.tuple = "F3", 4
		if strings.HasSuffix(rule.Opcode, "SD") {
			pp, f.tuple = "F2", 8
			if evex {
				w = "W1"
			}
		}
		formats := []string{
			v + "," + v + "," + v, v + ",Ym", "Ym," + v, v + "," + v + "," + v,
			v + "," + v + "," + v, v + "," + v + ",Yknot0," + v,
			v + ",Ym", v + ",Yknot0,Ym", "Ym," + v, "Ym,Yknot0," + v,
			v + "," + v + "," + v, v + "," + v + ",Yknot0," + v,
		}
		classes = formats[index]
		store = index == 0 || index == 1 || index >= 4 && index <= 7
		f.masked = index == 5 || index == 7 || index == 9 || index == 11
		if index == 0 || index == 3 || index == 4 || index == 5 || index >= 10 {
			f.vvvv, tupleAttribute = 1, false
		}
		zeroAttribute = evex && index != 6 && index != 7
	default:
		return fail()
	}
	if store {
		zcase = kind + "_r_v_rm"
	}
	f.classes = strings.Split(classes, ",")
	f.reg = len(f.classes) - 1
	if store {
		f.rm, f.reg = len(f.classes)-1, 0
	}
	if f.masked {
		if f.vvvv >= 0 {
			zcase = strings.Replace(zcase, "_v_", "_v_k_", 1)
		} else {
			zcase = strings.Replace(zcase, "_v_", "_k_", 1)
		}
	}
	if index != wantIndex || offset != wantOffset || rule.ZOffset != wantStride || len(rule.OpBytes) != extent ||
		rule.ZCase != "Z"+zcase || strings.Join(rule.Classes, ",") != classes {
		return fail()
	}
	atoms := []string{"avxEscape", kind + strconv.Itoa(f.width), kind + opcodeMap, kind + w}
	if pp != "" {
		atoms = append(atoms, kind+pp)
	}
	if _, err := x86PackedEncodingAtoms(header, atoms, nil); err != nil {
		return fail()
	}
	if evex {
		var attributes []string
		if tupleAttribute {
			attributes = append(attributes, "evexN"+strconv.Itoa(f.tuple))
		}
		if zeroAttribute {
			attributes = append(attributes, "evexZeroingEnabled")
		}
		if len(attributes) == 0 {
			attributes = []string{"0"}
		}
		if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], attributes, nil); err != nil {
			return fail()
		}
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[offset+stride-1], 0, 8)
	if err != nil {
		return fail()
	}
	f.zeroable = f.masked && zeroAttribute
	f.encoding = x86PackedAVXOpcode{kind: kind, mapByte: 1, length: byte(f.width / 256), opcode: byte(opcode)}
	if opcodeMap == "0F38" {
		f.encoding.mapByte = 2
	}
	if w == "W1" {
		f.encoding.wBit = 0x80
	}
	f.encoding.pp = map[string]byte{"": 0, "66": 1, "F3": 2, "F2": 3}[pp]
	return f, nil
}

func x86MoveRemainderRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86MoveRemainderFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	bank := 0
	if f.encoding.kind == "evex" {
		bank = 16 // Force the late EVEX row instead of an earlier VEX match.
	}
	rmClass := f.classes[f.rm]
	var witnesses []X86PackedBinaryWitness
	for _, memory := range []bool{false, true} {
		if memory && rmClass != "Ym" && rmClass != "Yml" && !strings.Contains(rmClass, "mEvex") && rmClass != "Yxm" ||
			!memory && rmClass == "Ym" {
			continue
		}
		for _, zeroing := range []bool{false, true} {
			if zeroing && !f.zeroable {
				continue
			}
			args, indices := make([]string, len(f.classes)), make([]int, len(f.classes))
			for i, class := range f.classes {
				indices[i] = bank + i
				switch class {
				case "Yknot0":
					args[i], indices[i] = "K1", 1
				case "Yml", "Yrl":
					args[i], indices[i] = "CX", 1
				default:
					args[i] = fmt.Sprint(map[int]string{128: "X", 256: "Y", 512: "Z"}[f.width], indices[i])
				}
			}
			if memory {
				args[f.rm], indices[f.rm] = "(AX)", 0
			}
			reg, rm := indices[f.reg], indices[f.rm]
			modrm := byte(0xc0 | (reg&7)<<3 | rm&7)
			if memory {
				modrm &^= 0xc0
			}
			vvvv, p0, p2 := byte(0x78), byte(0), f.encoding.length<<5|8
			if f.vvvv >= 0 {
				index := indices[f.vvvv]
				vvvv, p2 = byte(^index&15)<<3, f.encoding.length<<5|byte(1-index/16)<<3
			}
			if f.encoding.kind == "evex" {
				p0 = byte((1-reg/8&1)<<7 | (1-rm/8&1)<<5 | (1-reg/16)<<4)
				if memory || rmClass == "Yml" || rmClass == "Yrl" {
					p0 |= 0x40
				} else {
					p0 |= byte(1-rm/16) << 6
				}
			}
			if f.masked {
				p2 |= 1
			}
			suffix := ""
			if zeroing {
				suffix, p2 = ".Z", p2|0x80
			}
			second := ""
			if f.vvvv >= 0 {
				second = args[f.vvvv]
			}
			witnesses = append(witnesses, X86PackedBinaryWitness{
				Instruction: rule.Opcode + suffix + " " + strings.Join(args, ","), Generation: f.encoding.kind,
				First: args[0], Second: second, Destination: args[len(args)-1], Width: f.width,
				Memory: memory && f.rm == 0, Masked: f.masked, Zeroing: zeroing,
				Encoding: f.encoding.bytes(vvvv, p0, p2, modrm),
			})
		}
	}
	return witnesses, nil
}
