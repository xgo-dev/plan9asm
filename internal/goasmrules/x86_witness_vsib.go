package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// VSIB has independent data and index carriers. The encoding transport does
// not establish initialized indices, a backing allocation or active-lane rights.
type x86VSIBFormat struct {
	encoding          x86PackedAVXOpcode
	data, index       int
	scatter, prefetch bool
	extension         byte
}

func x86VSIBTable(table string) bool {
	switch table {
	case "_yvgatherdps", "_yvgatherdpd", "_yvgatherqps",
		"_yvpscatterdd", "_yvpscatterdq", "_yvpscatterqd",
		"_yvgatherpf0dps", "_yvgatherpf0dpd":
		return true
	}
	return false
}

// X86IndexedMemoryRows keeps every gather, scatter and prefetch source row.
// Prefetch is a hint; an object for it is not evidence of an actual memory read.
func X86IndexedMemoryRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	var names []string
	seen := make(map[string]bool)
	for _, rule := range avx {
		if x86VSIBTable(rule.Ytab) && !seen[rule.Opcode] {
			names = append(names, rule.Opcode)
			seen[rule.Opcode] = true
		}
	}
	return x86PackedBinaryRows(legacy, avx, strings.Join(names, " "))
}

func x86VSIBClassWidth(class string, memory bool) int {
	class = strings.TrimSuffix(class, "Evex")
	classes := []string{"Yxr", "Yyr", "Yzr"}
	if memory {
		classes = []string{"Yxvm", "Yyvm", "Yzvm"}
	}
	for index, candidate := range classes {
		if class == candidate {
			return 128 << index
		}
	}
	return 0
}

func x86VSIBFormatForRule(rule X86AVXRule) (x86VSIBFormat, error) {
	f := x86VSIBFormat{}
	fail := func() (x86VSIBFormat, error) {
		return f, fmt.Errorf("VSIB source roles, carriers or physical payload differ")
	}
	if !x86VSIBTable(rule.Ytab) || rule.EncodingOffset < 0 || rule.EncodingOffset >= len(rule.OpBytes) {
		return fail()
	}
	kind, memory, data := "evex", 0, 2
	switch rule.ZCase {
	case "Zvex_v_rm_r":
		kind, memory = "vex", 1
	case "Zevex_rm_k_r":
	case "Zevex_r_k_rm":
		f.scatter, memory, data = true, 2, 0
	case "Zevex_k_rmo":
		f.prefetch, memory = true, 1
	default:
		return fail()
	}
	wantClasses := 3
	if f.prefetch {
		wantClasses = 2
	}
	if len(rule.Classes) != wantClasses {
		return fail()
	}
	f.index = x86VSIBClassWidth(rule.Classes[memory], true)
	if f.prefetch {
		if rule.Classes[0] != "Yknot0" {
			return fail()
		}
	} else {
		f.data = x86VSIBClassWidth(rule.Classes[data], false)
		if kind == "vex" && x86VSIBClassWidth(rule.Classes[0], false) != f.data ||
			kind == "evex" && rule.Classes[1] != "Yknot0" {
			return fail()
		}
	}
	width := f.data
	if f.index > width {
		width = f.index
	}
	if f.index == 0 || !f.prefetch && f.data == 0 {
		return fail()
	}
	class := func(width int, indexed bool) string {
		name := map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[width]
		if indexed {
			name = map[int]string{128: "Yxvm", 256: "Yyvm", 512: "Yzvm"}[width]
		}
		if kind == "evex" && width < 512 {
			name += "Evex"
		}
		return name
	}
	if rule.Classes[memory] != class(f.index, true) ||
		!f.prefetch && rule.Classes[data] != class(f.data, false) ||
		kind == "vex" && rule.Classes[0] != class(f.data, false) {
		return fail()
	}
	if f.prefetch {
		wantIndex := 512
		if rule.Ytab == "_yvgatherpf0dpd" {
			wantIndex = 256
		}
		if f.index != wantIndex {
			return fail()
		}
	} else {
		wantData, wantIndex := width, width
		switch rule.Ytab {
		case "_yvgatherdpd", "_yvpscatterdq":
			wantIndex = maxConversionCarrier(width / 2)
		case "_yvgatherqps", "_yvpscatterqd":
			wantData = maxConversionCarrier(width / 2)
		}
		if f.data != wantData || f.index != wantIndex {
			return fail()
		}
	}
	index, offset, zoffset, extent := width/256, 2*(width/256), 2, 13
	if kind == "evex" {
		index, offset, zoffset = 2+width/256, 4+3*(width/256), 3
		if f.scatter {
			index, offset, extent = width/256, 3*(width/256), 9
		}
		if f.prefetch {
			width, index, offset, zoffset, extent = 512, 0, 0, 4, 4
		}
	} else if width == 512 {
		return fail()
	}
	if rule.RowIndex != index || rule.EncodingOffset != offset || rule.ZOffset != zoffset || len(rule.OpBytes) != extent {
		return fail()
	}
	op := x86PackedAVXOpcode{kind: kind, mapByte: 2, pp: 1, length: byte(width / 256)}
	element := 4
	if hasEncodingTerm(rule.OpBytes[offset], kind+"W1") {
		op.wBit, element = 0x80, 8
	}
	var features []string
	if kind == "evex" {
		features = []string{"evexN" + strconv.Itoa(element)}
	}
	var err error
	f.encoding, err = x86ConversionRemainderEncoding(rule, op, features)
	if err != nil {
		return f, err
	}
	if f.prefetch {
		extension, err := strconv.ParseUint(rule.OpBytes[3], 0, 3)
		if err != nil || extension != 1 && extension != 2 && extension != 5 && extension != 6 {
			return fail()
		}
		f.extension = byte(extension)
	}
	return f, nil
}

func x86VSIBRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86VSIBFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	bank := 0
	if f.encoding.kind == "evex" {
		bank = 16
	}
	carrier := func(width, register int) string {
		return fmt.Sprint(map[int]string{128: "X", 256: "Y", 512: "Z"}[width], register)
	}
	index := carrier(f.index, bank)
	data, mask := carrier(f.data, bank+2), "K1"
	if f.prefetch {
		data = ""
	}
	if f.encoding.kind == "vex" {
		mask = carrier(f.data, 1)
	}
	reg, vvvv, p0 := byte(2), byte(0x78), byte(0xe0)
	p2 := f.encoding.length<<5 | 1
	if f.encoding.kind == "vex" {
		vvvv = 0x70 // VEX vector mask register one.
	}
	if f.prefetch {
		reg, p0 = f.extension, 0xf0
	}
	var witnesses []X86PackedBinaryWitness
	for scale := 0; scale < 4; scale++ {
		memory := fmt.Sprintf("(AX)(%s*%d)", index, 1<<scale)
		operands := memory + "," + mask + "," + data
		if f.encoding.kind == "vex" {
			operands = mask + "," + memory + "," + data
		} else if f.scatter {
			operands = data + "," + mask + "," + memory
		} else if f.prefetch {
			operands = mask + "," + memory
		}
		encoding := f.encoding.bytes(vvvv, p0, p2, reg<<3|4)
		encoding = append(encoding, byte(scale)<<6) // index low bits and AX are zero.
		witnesses = append(witnesses, X86PackedBinaryWitness{
			Instruction: rule.Opcode + " " + operands, Generation: f.encoding.kind,
			First: memory, Second: index, Destination: data, Width: f.data,
			Memory: true, Masked: true, Encoding: encoding,
		})
	}
	return witnesses, nil
}
