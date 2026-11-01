package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// Physical carriers, active input tuple and encoded width are independent.
// These source-table facts confer no numerical, pointee or native authority.
type x86PackedNumericConversionFormat struct {
	source, result, tuple, broadcast int
	masked, rounding, sae            bool
	encoding                         x86PackedAVXOpcode
}

func x86PackedNumericConversionFormatForRule(rule X86AVXRule) (x86PackedNumericConversionFormat, error) {
	f := x86PackedNumericConversionFormat{masked: rule.ZCase == "Zevex_rm_k_r"}
	f.encoding.kind = "vex"
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	if evex {
		f.encoding.kind = "evex"
	}
	fail := func() (x86PackedNumericConversionFormat, error) {
		return f, fmt.Errorf("packed numeric source/result/tuple/control differs from its official format")
	}
	stride := 2
	if evex {
		stride = 3
	}
	if rule.Prefix != "Pavx" || rule.ZCase != "Zvex_rm_v_r" && rule.ZCase != "Zevex_rm_v_r" && !f.masked ||
		len(rule.Classes) != 2 && !f.masked || f.masked && (len(rule.Classes) != 3 || rule.Classes[1] != "Yknot0") ||
		rule.EncodingOffset < 0 || rule.EncodingOffset+stride > len(rule.OpBytes) {
		return fail()
	}
	kind := f.encoding.kind
	atoms, err := x86PackedEncodingAtoms(rule.OpBytes[rule.EncodingOffset], []string{"avxEscape", kind + "0F"}, []string{
		kind + "128", kind + "256", kind + "512", kind + "66", kind + "F2", kind + "F3", kind + "W0", kind + "W1",
	})
	if err != nil || atoms[kind+"W0"] == atoms[kind+"W1"] {
		return fail()
	}
	width, lengths, prefixes, pp := 0, 0, 0, ""
	for index, bits := range []int{128, 256, 512} {
		if atoms[kind+strconv.Itoa(bits)] {
			width, f.encoding.length = bits, byte(index)
			lengths++
		}
	}
	for index, prefix := range []string{"66", "F3", "F2"} {
		if atoms[kind+prefix] {
			pp, f.encoding.pp = prefix, byte(index+1)
			prefixes++
		}
	}
	if lengths != 1 || prefixes > 1 || !evex && (width == 512 || atoms["vexW1"]) {
		return fail()
	}
	input, output, vexRows := 32, 32, 0
	order, control, allowedPP, w := []int{512, 128, 256}, true, "", "W0"
	switch rule.Ytab {
	case "_yvcvtdq2ps":
		vexRows, allowedPP = 2, ",66,F3"
	case "_yvcvtdq2pd", "_yvcvtudq2pd":
		output, control, allowedPP, order = 64, false, "F3", []int{128, 256, 512}
		if rule.Ytab == "_yvcvtdq2pd" {
			vexRows = 2
		}
	case "_yvcvtps2qq":
		output, allowedPP = 64, "66"
	case "_yvcvtpd2qq":
		allowedPP = ",F2"
		if atoms["evexW1"] {
			input, output, w, allowedPP = 64, 64, "W1", "66,F3"
		}
	case "_yvcvtpd2dq", "_yvcvtpd2dqx", "_yvcvtpd2dqy", "_yvcvtpd2udqx", "_yvcvtpd2udqy":
		input, w, allowedPP, order = 64, "W1", ",66,F2", []int{512}
		if rule.Ytab != "_yvcvtpd2dq" {
			control, order = false, []int{128}
			if strings.HasSuffix(rule.Ytab, "y") {
				order[0] = 256
			}
			allowedPP = ",F2"
			if rule.Ytab == "_yvcvtpd2dqx" || rule.Ytab == "_yvcvtpd2dqy" {
				vexRows, allowedPP = 1, "66,F2"
				if !evex {
					w = "W0"
				}
			}
		}
	default:
		return fail()
	}
	if !atoms[kind+w] || !strings.Contains(","+allowedPP+",", ","+pp+",") {
		return fail()
	}
	f.source, f.result, f.tuple = width, width, width/8
	if input < output {
		f.source, f.tuple = maxConversionCarrier(width/2), width/16
	} else if input > output {
		f.result = maxConversionCarrier(width / 2)
	}
	sourceClass := map[int]string{128: "Yxm", 256: "Yym", 512: "Yzm"}[f.source]
	resultClass := map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[f.result]
	if evex {
		if f.source < 512 {
			sourceClass += "Evex"
		}
		if f.result < 512 {
			resultClass += "Evex"
		}
	}
	index, offset, zoffset := -1, -1, 2
	if evex {
		for i, candidate := range order {
			if width == candidate {
				index, offset, zoffset = vexRows+2*i, 2*vexRows+3*i, 0
			}
		}
		if f.masked {
			index, zoffset = index+1, 3
		}
	} else if vexRows == 2 && width == 128 || vexRows == 1 && width == order[0] {
		index, offset = 0, 0
	} else if vexRows == 2 && width == 256 {
		index, offset = 1, 2
	}
	if rule.Classes[0] != sourceClass || rule.Classes[len(rule.Classes)-1] != resultClass ||
		index < 0 || rule.RowIndex != index || rule.EncodingOffset != offset || rule.ZOffset != zoffset || len(rule.OpBytes) != 2*vexRows+3*len(order) {
		return fail()
	}
	if evex {
		optional := []string{}
		if control && width == 512 {
			optional = []string{"evexRoundingEnabled", "evexSaeEnabled"}
		}
		flags, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], []string{
			"evexN" + strconv.Itoa(f.tuple), "evexBcstN" + strconv.Itoa(input/8), "evexZeroingEnabled",
		}, optional)
		if err != nil || control && width == 512 && flags["evexRoundingEnabled"] == flags["evexSaeEnabled"] {
			return fail()
		}
		f.broadcast, f.rounding, f.sae = input/8, flags["evexRoundingEnabled"], flags["evexSaeEnabled"]
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[rule.EncodingOffset+stride-1], 0, 8)
	if err != nil {
		return fail()
	}
	f.encoding.mapByte, f.encoding.opcode = 1, byte(opcode)
	if atoms[kind+"W1"] {
		f.encoding.wBit = 0x80
	}
	return f, nil
}

func maxConversionCarrier(bits int) int {
	if bits < 128 {
		return 128
	}
	return bits
}

func x86PackedNumericConversionRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86PackedNumericConversionFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	return f.witnesses(rule.Opcode), nil
}

func (f x86PackedNumericConversionFormat) witnesses(opcode string) []X86PackedBinaryWitness {
	bank := map[int]string{128: "X", 256: "Y", 512: "Z"}
	source, destination := bank[f.source]+"0", bank[f.result]+"2"
	if f.encoding.kind == "evex" {
		source, destination = bank[f.source]+"16", bank[f.result]+"18"
	}
	controls := []string{""}
	if f.masked {
		controls = append(controls, ".Z")
	}
	var witnesses []X86PackedBinaryWitness
	add := func(first, suffix string, p2 byte) {
		operands, p0, modrm := first+","+destination, byte(0xa0), byte(0xd0)
		if first == "(AX)" {
			p0, modrm = 0xe0, 0x10
		}
		if f.masked {
			operands, p2 = first+",K1,"+destination, p2|1
		}
		if strings.HasSuffix(suffix, ".Z") {
			p2 |= 0x80
		}
		witnesses = append(witnesses, X86PackedBinaryWitness{
			Instruction: opcode + suffix + " " + operands, Generation: f.encoding.kind,
			First: first, Destination: destination, Width: f.result, Memory: first == "(AX)",
			Masked: f.masked, Zeroing: strings.HasSuffix(suffix, ".Z"), Broadcast: strings.Contains(suffix, ".BCST"),
			Encoding: f.encoding.bytes(0x78, p0, p2, modrm),
		})
	}
	p2 := f.encoding.length<<5 | 8
	for _, first := range []string{source, "(AX)"} {
		for _, suffix := range controls {
			add(first, suffix, p2)
		}
	}
	for _, suffix := range controls {
		if f.broadcast != 0 {
			add("(AX)", ".BCST"+suffix, p2|0x10)
		}
		if f.rounding {
			for index, rounding := range []string{"RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE"} {
				add(source, "."+rounding+suffix, p2&^0x60|byte(index)<<5|0x10)
			}
		}
		if f.sae {
			add(source, ".SAE"+suffix, p2|0x10)
		}
	}
	return witnesses
}
