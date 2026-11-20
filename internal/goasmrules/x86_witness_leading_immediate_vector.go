package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// Physical immediate/source/result roles do not combine the families'
// numerical, old-destination or native-access contracts.
type x86VectorResultFormat struct {
	width                         int
	unary, masked, broadcast, sae bool
	rounding, maskResult          bool
	encoding                      x86PackedAVXOpcode
}

func x86LeadingImmediateVectorFormatForRule(rule X86AVXRule) (x86VectorResultFormat, error) {
	f := x86VectorResultFormat{masked: rule.ZCase == "Zevex_i_rm_v_k_r"}
	fail := func() (x86VectorResultFormat, error) {
		return f, fmt.Errorf("leading-immediate two-vector result roles differ from their official format")
	}
	count, maskIndex := 4, 0
	if f.masked {
		count, maskIndex = 5, 1
	}
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	plain, kind := "Zvex_i_rm_v_r", "vex"
	if evex {
		plain, kind = "Zevex_i_rm_v_r", "evex"
	}
	if rule.Prefix != "Pavx" || rule.ZCase != plain && !f.masked || len(rule.Classes) != count ||
		rule.Classes[0] != "Yu8" || f.masked && rule.Classes[3] != "Yknot0" {
		return fail()
	}
	f.width = map[string]int{"Yxm": 128, "Yym": 256}[rule.Classes[1]]
	register := map[int]string{128: "Yxr", 256: "Yyr"}[f.width]
	if evex {
		f.width = map[string]int{"YxmEvex": 128, "YymEvex": 256, "Yzm": 512}[rule.Classes[1]]
		register = map[int]string{128: "YxrEvex", 256: "YyrEvex", 512: "Yzr"}[f.width]
	}
	widthIndex := map[int]int{128: 0, 256: 1, 512: 2}[f.width]
	index, offset, zoffset, extent := widthIndex*2+maskIndex, widthIndex*3, maskIndex*3, 9
	if rule.Ytab == "_yvgf2p8affineinvqb" {
		extent = 13
		index, offset = index+2, offset+4
		if !evex {
			index, offset, zoffset = widthIndex, widthIndex*2, 2
		}
	} else if rule.Ytab != "_yvalignd" || !evex {
		return fail()
	}
	if f.width == 0 || rule.Classes[2] != register || rule.Classes[count-1] != register ||
		rule.RowIndex != index || rule.ZOffset != zoffset ||
		rule.EncodingOffset != offset || len(rule.OpBytes) != extent {
		return fail()
	}
	w, opcodeMap, pp, mapByte, bcstBytes := "W0", "0F3A", byte(1), byte(3), 0
	if strings.HasSuffix(rule.Opcode, "Q") || strings.HasSuffix(rule.Opcode, "DW") {
		w = "W1"
	}
	if strings.HasSuffix(rule.Opcode, "D") || strings.HasSuffix(rule.Opcode, "Q") {
		bcstBytes = 4
		if w == "W1" {
			bcstBytes = 8
		}
	}
	if extent == 13 {
		switch rule.Opcode {
		case "VPALIGNR":
		case "VSHUFPS", "VSHUFPD":
			opcodeMap, mapByte = "0F", 1
			if rule.Opcode == "VSHUFPS" {
				pp, bcstBytes = 0, 4
			} else {
				bcstBytes = 8
				if evex {
					w = "W1"
				}
			}
		default:
			return fail()
		}
	}
	header := []string{"avxEscape", kind + strconv.Itoa(f.width), kind + opcodeMap, kind + w}
	if pp != 0 {
		header = append(header, kind+"66")
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], header, nil); err != nil {
		return fail()
	}
	opcodeOffset := offset + 1
	if evex {
		f.broadcast = bcstBytes != 0
		features := []string{"evexN" + strconv.Itoa(f.width/8), "evexZeroingEnabled"}
		if f.broadcast {
			features = append(features, "evexBcstN"+strconv.Itoa(bcstBytes))
		}
		if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], features, nil); err != nil {
			return fail()
		}
		opcodeOffset++
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[opcodeOffset], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding = x86PackedAVXOpcode{kind: kind, mapByte: mapByte, pp: pp, length: byte(widthIndex), opcode: byte(opcode)}
	if w == "W1" {
		f.encoding.wBit = 0x80
	}
	return f, nil
}

func x86LeadingImmediateVectorRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86LeadingImmediateVectorFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	return f.witnesses(rule.Opcode), nil
}

// Only validated vector-source/vector-result transport is shared.
// Family factories retain mandatory prefixes, W, tuples and broadcast guards.
func (f x86VectorResultFormat) witnesses(opcode string) []X86PackedBinaryWitness {
	return f.witnessesWithControl(opcode, true, 7)
}

func (f x86VectorResultFormat) witnessesWithControl(opcode string, immediate bool, selector int) []X86PackedBinaryWitness {
	bank := map[int]string{128: "X", 256: "Y", 512: "Z"}[f.width]
	first, second, destination := bank+"0", bank+"1", bank+"2"
	if f.encoding.kind == "evex" {
		first, second, destination = bank+"16", bank+"17", bank+"18"
	}
	if f.unary {
		second = ""
	}
	destinations := []struct {
		name string
		reg  byte
	}{{destination, 2}}
	if f.maskResult {
		destinations = []struct {
			name string
			reg  byte
		}{{"K2", 2}, {"K0", 0}}
	}
	var witnesses []X86PackedBinaryWitness
	// K2 then K0 stays outside the source/control loops, preserving prior owners.
	for _, target := range destinations {
		for _, source := range []string{first, "(AX)"} {
			for _, control := range []string{"", "BCST", "SAE", "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				broadcast, sae := control == "BCST", control == "SAE"
				rounding := strings.HasSuffix(control, "_SAE")
				if broadcast && (source != "(AX)" || !f.broadcast) || sae && (source == "(AX)" || !f.sae) || rounding && (source == "(AX)" || !f.rounding) {
					continue
				}
				for _, zeroing := range []bool{false, true} {
					if zeroing && (!f.masked || f.maskResult) {
						continue
					}
					operands, suffix, vvvv := source, "", byte(0x70)
					if immediate {
						operands = fmt.Sprintf("$%d,%s", selector, source)
					}
					p0, p2, modrm := byte(0xa0), f.encoding.length<<5, byte(0xc0)|target.reg<<3
					if f.maskResult {
						p0 |= 0x10
					}
					if f.unary {
						vvvv, p2 = 0x78, p2|8
					} else {
						operands += "," + second
					}
					if source == "(AX)" {
						p0, modrm = p0|0x40, target.reg<<3
					}
					if f.masked {
						operands, p2 = operands+",K1", p2|1
					}
					if control != "" {
						suffix, p2 = "."+control, p2|0x10
					}
					if rounding {
						p2 = p2&^0x60 | map[string]byte{"RN_SAE": 0, "RD_SAE": 1, "RU_SAE": 2, "RZ_SAE": 3}[control]<<5
					}
					if zeroing {
						suffix, p2 = suffix+".Z", p2|0x80
					}
					encoding := f.encoding.bytes(vvvv, p0, p2, modrm)
					if immediate {
						encoding = append(encoding, byte(selector))
					}
					witnesses = append(witnesses, X86PackedBinaryWitness{
						Instruction: opcode + suffix + " " + operands + "," + target.name, Generation: f.encoding.kind,
						First: source, Second: second, Destination: target.name, Width: f.width, Memory: source == "(AX)",
						Masked: f.masked, Zeroing: zeroing, Broadcast: broadcast, MaskResult: f.maskResult, Encoding: encoding,
					})
				}
			}
		}
	}
	return witnesses
}
