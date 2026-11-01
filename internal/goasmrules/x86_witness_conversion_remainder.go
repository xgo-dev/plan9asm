package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// The six remaining ytabs reuse existing carriers and encoders.
// The fourteen already-supported rows retain their existing dispatcher path.
func x86ConversionRemainderTable(table string) bool {
	switch table {
	case "_yvcvtph2ps", "_yvcvtps2ph", "_yvcvtsd2si", "_yvcvtsd2usil", "_yvcvtsi2sdl", "_yvcvtusi2sdl":
		return true
	}
	return false
}

// A fixed physical header is validated against its original source payload.
// This reads no opcode-value registry, normalized operand or source permission.
func x86ConversionRemainderEncoding(rule X86AVXRule, op x86PackedAVXOpcode, features []string) (x86PackedAVXOpcode, error) {
	stride := 2
	if op.kind == "evex" {
		stride = 3
	}
	offset := rule.EncodingOffset
	if rule.Prefix != "Pavx" || offset < 0 || offset+stride > len(rule.OpBytes) {
		return op, fmt.Errorf("conversion prefix/payload boundary differs")
	}
	header := []string{
		"avxEscape",
		op.kind + strconv.Itoa([]int{128, 256, 512}[op.length]),
		op.kind + map[byte]string{1: "0F", 2: "0F38", 3: "0F3A"}[op.mapByte],
		op.kind + map[byte]string{0: "W0", 0x80: "W1"}[op.wBit],
	}
	if op.pp != 0 {
		header = append(header, op.kind+map[byte]string{1: "66", 2: "F3", 3: "F2"}[op.pp])
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], header, nil); err != nil {
		return op, err
	}
	if op.kind == "evex" {
		if len(features) == 0 {
			features = []string{"0"}
		}
		if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset+1], features, nil); err != nil {
			return op, err
		}
	}
	value, err := strconv.ParseUint(rule.OpBytes[offset+stride-1], 0, 8)
	if err != nil {
		return op, err
	}
	op.opcode = byte(value)
	return op, nil
}

func x86ConversionRemainderPackedFormatForRule(rule X86AVXRule) (x86PackedNumericConversionFormat, error) {
	f := x86PackedNumericConversionFormat{masked: rule.ZCase == "Zevex_rm_k_r"}
	fail := func() (x86PackedNumericConversionFormat, error) {
		return f, fmt.Errorf("precision/half widening carrier, tuple or controls differ")
	}
	if rule.Ytab != "_yvcvtph2ps" || rule.Opcode != "VCVTPH2PS" && rule.Opcode != "VCVTPS2PD" || rule.EncodingOffset < 0 || rule.EncodingOffset >= len(rule.OpBytes) {
		return fail()
	}
	kind := "vex"
	if strings.HasPrefix(rule.ZCase, "Zevex_") {
		kind = "evex"
	}
	width := 128
	if hasEncodingTerm(rule.OpBytes[rule.EncodingOffset], kind+"256") {
		width = 256
	} else if hasEncodingTerm(rule.OpBytes[rule.EncodingOffset], kind+"512") {
		width = 512
	}
	index, offset, zoffset := width/256, 2*(width/256), 2
	source, result := "Yxm", map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[width]
	if kind == "evex" {
		order := map[int]int{512: 0, 128: 1, 256: 2}[width]
		index, offset, zoffset = 2+2*order, 4+3*order, 0
		source = map[int]string{128: "YxmEvex", 256: "YxmEvex", 512: "YymEvex"}[width]
		if width < 512 {
			result += "Evex"
		}
		if f.masked {
			index++
			zoffset = 3
		}
	} else if width == 512 {
		return fail()
	}
	classes := []string{source, result}
	if f.masked {
		classes = []string{source, "Yknot0", result}
	}
	if rule.ZCase != "Z"+kind+"_rm_v_r" && !f.masked ||
		strings.Join(rule.Classes, ",") != strings.Join(classes, ",") || rule.RowIndex != index ||
		rule.EncodingOffset != offset || rule.ZOffset != zoffset || len(rule.OpBytes) != 13 {
		return fail()
	}
	f.source, f.result, f.tuple = maxConversionCarrier(width/2), width, width/16
	op := x86PackedAVXOpcode{kind: kind, mapByte: 1, length: byte(width / 256)}
	if rule.Opcode == "VCVTPH2PS" {
		op.mapByte, op.pp = 2, 1
	} else if kind == "evex" {
		f.broadcast = 4
	}
	var features []string
	if kind == "evex" {
		features = []string{"evexN" + strconv.Itoa(f.tuple), "evexZeroingEnabled"}
		if f.broadcast != 0 {
			features = append(features, "evexBcstN4")
		}
		if width == 512 {
			f.sae = true
			features = append(features, "evexSaeEnabled")
		}
	}
	var err error
	f.encoding, err = x86ConversionRemainderEncoding(rule, op, features)
	return f, err
}

func x86ConversionRemainderHalfFormatForRule(rule X86AVXRule) (x86PackedUnaryMemoryFormat, int, bool, error) {
	f := x86PackedUnaryMemoryFormat{store: true, masked: rule.ZCase == "Zevex_i_r_k_rm"}
	fail := func() (x86PackedUnaryMemoryFormat, int, bool, error) {
		return f, 0, false, fmt.Errorf("half narrowing immediate/carriers/tuple differ")
	}
	if rule.Ytab != "_yvcvtps2ph" || rule.Opcode != "VCVTPS2PH" || rule.EncodingOffset < 0 || rule.EncodingOffset >= len(rule.OpBytes) {
		return fail()
	}
	kind, selector := "vex", 7
	if strings.HasPrefix(rule.ZCase, "Zevex_") {
		kind = "evex"
	}
	width := 128
	if hasEncodingTerm(rule.OpBytes[rule.EncodingOffset], kind+"256") {
		width = 256
	} else if hasEncodingTerm(rule.OpBytes[rule.EncodingOffset], kind+"512") {
		width = 512
	}
	index, offset, zoffset := 2*(width/256), 2*(width/256), 0
	source, result, immediate := map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[width], "Yxm", "Yu8"
	if kind == "evex" {
		order := map[int]int{512: 0, 128: 1, 256: 2}[width]
		index, offset = 4+2*order, 4+3*order
		if width < 512 {
			source += "Evex"
		}
		result = map[int]string{128: "YxmEvex", 256: "YxmEvex", 512: "YymEvex"}[width]
		if f.masked {
			index++
			zoffset = 3
		}
	} else {
		if width == 512 || len(rule.Classes) < 1 {
			return fail()
		}
		if rule.Classes[0] == "Yi8" {
			selector, immediate, zoffset = -1, "Yi8", 2
			index++
		}
	}
	classes := []string{immediate, source, result}
	if f.masked {
		classes = []string{immediate, source, "Yknot0", result}
	}
	if rule.ZCase != "Z"+kind+"_i_r_rm" && !f.masked ||
		strings.Join(rule.Classes, ",") != strings.Join(classes, ",") || rule.RowIndex != index ||
		rule.EncodingOffset != offset || rule.ZOffset != zoffset || len(rule.OpBytes) != 13 {
		return fail()
	}
	f.width, f.tuple, f.carrier = width, width/16, maxConversionCarrier(width/2)/8
	features := []string{}
	sae := kind == "evex" && width == 512
	if kind == "evex" {
		features = []string{"evexN" + strconv.Itoa(f.tuple), "evexZeroingEnabled"}
		if sae {
			features = append(features, "evexSaeEnabled")
		}
	}
	var err error
	f.encoding, err = x86ConversionRemainderEncoding(rule, x86PackedAVXOpcode{kind: kind, mapByte: 3, pp: 1, length: byte(width / 256)}, features)
	return f, selector, sae, err
}

// The two scalar transports keep GP result and vector-upper copy distinct.
// Scalar tuple and encoded W remain independent of mode32's effective GP word.
type x86ConversionRemainderScalarFormat struct {
	gpResult, rounding, sae bool
	encoding                x86PackedAVXOpcode
}

func x86ConversionRemainderScalarFormatForRule(rule X86AVXRule) (x86ConversionRemainderScalarFormat, error) {
	f := x86ConversionRemainderScalarFormat{gpResult: rule.Ytab == "_yvcvtsd2si" || rule.Ytab == "_yvcvtsd2usil"}
	fail := func() (x86ConversionRemainderScalarFormat, error) {
		return f, fmt.Errorf("scalar conversion GP/upper/result roles differ")
	}
	if !strings.HasPrefix(rule.Opcode, "VCVT") {
		return fail()
	}
	left, right, ok := strings.Cut(strings.TrimPrefix(rule.Opcode, "VCVT"), "2")
	if !ok {
		return fail()
	}
	kind := "vex"
	if strings.HasPrefix(rule.ZCase, "Zevex_") {
		kind = "evex"
	}
	unsigned := rule.Ytab == "_yvcvtsd2usil" || rule.Ytab == "_yvcvtusi2sdl"
	if unsigned && kind != "evex" {
		return fail()
	}
	precision, gp64, tuple := "", false, 4
	if f.gpResult {
		truncated := strings.HasPrefix(left, "T")
		precision = strings.TrimPrefix(left, "T")
		if precision != "SS" && precision != "SD" || !unsigned && right != "SI" && right != "SIQ" || unsigned && right != "USIL" && right != "USIQ" {
			return fail()
		}
		gp64 = strings.HasSuffix(right, "Q")
		if precision == "SD" {
			tuple = 8
		}
		f.sae, f.rounding = kind == "evex" && truncated, kind == "evex" && !truncated
	} else {
		if rule.Ytab != "_yvcvtsi2sdl" && rule.Ytab != "_yvcvtusi2sdl" || !unsigned && left != "SI" || unsigned && left != "USI" || len(right) != 3 {
			return fail()
		}
		precision, gp64 = right[:2], right[2] == 'Q'
		if precision != "SS" && precision != "SD" || right[2] != 'Q' && right[2] != 'L' {
			return fail()
		}
		if gp64 {
			tuple = 8
		}
		f.rounding = kind == "evex" && (gp64 || precision == "SS")
	}
	index, offset, zoffset, extent := 0, 0, 2, 5
	if kind == "evex" {
		index, offset, zoffset = 1, 2, 3
	}
	if unsigned {
		index, offset, extent = 0, 0, 3
	}
	classes := []string{"Yml", "Yxr", "Yxr"}
	if f.gpResult {
		classes = []string{"Yxm", "Yrl"}
	}
	if kind == "evex" {
		if f.gpResult {
			classes[0] += "Evex"
		} else {
			classes[1] += "Evex"
			classes[2] += "Evex"
		}
	}
	if rule.ZCase != "Z"+kind+"_rm_v_r" ||
		strings.Join(rule.Classes, ",") != strings.Join(classes, ",") || rule.RowIndex != index ||
		rule.EncodingOffset != offset || rule.ZOffset != zoffset || len(rule.OpBytes) != extent {
		return fail()
	}
	op := x86PackedAVXOpcode{kind: kind, mapByte: 1, pp: 2}
	if precision == "SD" {
		op.pp = 3
	}
	if gp64 {
		op.wBit = 0x80
	}
	var features []string
	if kind == "evex" {
		features = []string{"evexN" + strconv.Itoa(tuple)}
		if f.rounding {
			features = append(features, "evexRoundingEnabled")
		}
		if f.sae {
			features = append(features, "evexSaeEnabled")
		}
	}
	var err error
	f.encoding, err = x86ConversionRemainderEncoding(rule, op, features)
	return f, err
}

func (f x86ConversionRemainderScalarFormat) witnesses(opcode string) []X86PackedBinaryWitness {
	bank := 0
	if f.encoding.kind == "evex" {
		bank = 16
	}
	first, second, last := fmt.Sprint("X", bank), "", "CX"
	reg, rm := 1, bank
	vvvv, p2 := byte(0x78), byte(8)
	if !f.gpResult {
		first, second, last = "CX", fmt.Sprint("X", bank+1), fmt.Sprint("X", bank+2)
		reg, rm = bank+2, 1
		vvvv, p2 = byte(^(bank+1)&15)<<3, byte(1-(bank+1)/16)<<3
	}
	var witnesses []X86PackedBinaryWitness
	for _, memory := range []bool{false, true} {
		controls := []string{""}
		if !memory {
			if f.rounding {
				controls = append(controls, "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE")
			}
			if f.sae {
				controls = append(controls, "SAE")
			}
		}
		for _, control := range controls {
			source, r := first, rm
			mod := byte(0xc0)
			if memory {
				source, r, mod = "(AX)", 0, 0
			}
			p0 := byte((1-reg/8&1)<<7 | (1-r/8&1)<<5 | (1-reg/16)<<4)
			if memory || !f.gpResult {
				p0 |= 0x40
			} else {
				p0 |= byte(1-r/16) << 6
			}
			flags := p2
			suffix := ""
			if control != "" {
				suffix = "." + control
				flags |= 0x10
				if control != "SAE" {
					flags |= map[string]byte{"RN_SAE": 0, "RD_SAE": 1, "RU_SAE": 2, "RZ_SAE": 3}[control] << 5
				}
			}
			operands := source + "," + last
			if second != "" {
				operands = source + "," + second + "," + last
			}
			witnesses = append(witnesses, X86PackedBinaryWitness{
				Instruction: opcode + suffix + " " + operands, Generation: f.encoding.kind,
				First: source, Second: second, Destination: last, Width: 128, Memory: memory,
				Encoding: f.encoding.bytes(vvvv, p0, flags, mod|byte(reg&7)<<3|byte(r&7)),
			})
		}
	}
	return witnesses
}

func x86ConversionRemainderRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	switch rule.Ytab {
	case "_yvcvtph2ps":
		f, err := x86ConversionRemainderPackedFormatForRule(rule)
		if err != nil {
			return nil, err
		}
		return f.witnesses(rule.Opcode), nil
	case "_yvcvtps2ph":
		f, selector, sae, err := x86ConversionRemainderHalfFormatForRule(rule)
		if err != nil {
			return nil, err
		}
		var result []X86PackedBinaryWitness
		for _, w := range f.witnesses(rule.Opcode) {
			name, operands, _ := strings.Cut(w.Instruction, " ")
			w.Instruction = fmt.Sprintf("%s $%d,%s", name, selector, operands)
			w.Encoding = append(w.Encoding, byte(selector))
			result = append(result, w)
			if sae && w.Destination != "(AX)" {
				copy := w
				suffix := ".SAE"
				if w.Zeroing {
					suffix += ".Z"
				}
				copy.Instruction = fmt.Sprintf("%s%s $%d,%s", rule.Opcode, suffix, selector, operands)
				copy.Encoding = append([]byte(nil), w.Encoding...)
				copy.Encoding[3] |= 0x10
				result = append(result, copy)
			}
		}
		return result, nil
	default:
		f, err := x86ConversionRemainderScalarFormatForRule(rule)
		if err != nil {
			return nil, err
		}
		return f.witnesses(rule.Opcode), nil
	}
}
