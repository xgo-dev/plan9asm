package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// Transfer direction and tuple are independent of the vector carrier. This
// record owns physical syntax only, never numerical inputs or native storage.
type x86InsertExtractFormat struct {
	width, tuple, selector int
	insert, gp, alternate  bool
	masked, memory         bool
	encoding               x86PackedAVXOpcode
}

func x86InsertExtractFormatForRule(rule X86AVXRule) (x86InsertExtractFormat, error) {
	f := x86InsertExtractFormat{selector: 7, memory: true}
	fail := func() (x86InsertExtractFormat, error) {
		return f, fmt.Errorf("insert/extract source, transfer and result differ from their official format")
	}
	if len(rule.Classes) < 3 || rule.Prefix != "Pavx" || rule.Opcode == "" {
		return fail()
	}
	f.insert = strings.HasPrefix(rule.Ytab, "_yvinsert") || rule.Ytab == "_yvpinsrb"
	f.gp = rule.Ytab == "_yvextractps" || rule.Ytab == "_yvpextrw" || rule.Ytab == "_yvpinsrb"
	maskedCase := "Zevex_i_r_k_rm"
	if f.insert {
		maskedCase = "Zevex_i_rm_v_k_r"
	}
	f.masked = rule.ZCase == maskedCase
	evex := strings.HasPrefix(rule.ZCase, "Zevex_")
	kind, plain, count := "vex", "Zvex_i_r_rm", 3
	if f.insert {
		plain, count = "Zvex_i_rm_v_r", 4
	}
	if evex {
		kind, plain = "evex", strings.Replace(plain, "Zvex_", "Zevex_", 1)
	}
	if f.masked {
		count++
	}
	if rule.Classes[0] == "Yi8" && !evex && !f.insert {
		f.selector = -1
	} else if rule.Classes[0] != "Yu8" {
		return fail()
	}
	f.alternate = rule.Ytab == "_yvpextrw" && rule.Classes[len(rule.Classes)-1] == "Yrl"
	if f.alternate {
		plain = strings.Replace(plain, "_i_r_rm", "_i_rm_r", 1)
		f.memory = false
	}
	if len(rule.Classes) != count || rule.ZCase != plain && !f.masked ||
		f.masked && rule.Classes[count-2] != "Yknot0" {
		return fail()
	}
	vector := 1
	if f.insert {
		vector = 2
	}
	f.width = map[string]int{"Yxr": 128, "YxrEvex": 128, "Yyr": 256, "YyrEvex": 256, "Yzr": 512}[rule.Classes[vector]]
	register := map[int]string{128: "Yxr", 256: "Yyr", 512: "Yzr"}[f.width]
	if evex && f.width != 512 {
		register += "Evex"
	}
	if f.width == 0 || rule.Classes[vector] != register || f.insert && rule.Classes[count-1] != register {
		return fail()
	}
	index, offset, stride, extent := 0, 0, 2, 2
	block, wide := false, false
	switch rule.Ytab {
	case "_yvextractf128", "_yvinsertf128":
		f.tuple, block = 16, true
		if evex || f.width != 256 {
			return fail()
		}
		if !f.insert {
			stride = 0
			if f.selector < 0 {
				index, stride = 1, 2
			}
		}
	case "_yvextractf32x4", "_yvinsertf32x4", "_yvextractf32x8", "_yvinsertf32x8":
		f.tuple, block, extent = 16, true, 6
		wide = strings.HasSuffix(rule.Ytab, "x8")
		if wide {
			f.tuple, extent = 32, 3
		}
		if !evex || f.width != 256 && f.width != 512 || wide && f.width != 512 {
			return fail()
		}
		if !wide {
			index, offset = (f.width/256-1)*2, (f.width/256-1)*3
		}
		stride = 0
		if f.masked {
			index, stride = index+1, 3
		}
	case "_yvextractps", "_yvpextrw", "_yvinsertps", "_yvpinsrb":
		f.tuple, extent = 4, 5
		if f.gp && rule.Opcode != "VEXTRACTPS" {
			f.tuple = map[byte]int{'B': 1, 'W': 2, 'D': 4, 'Q': 8}[rule.Opcode[len(rule.Opcode)-1]]
		}
		if f.width != 128 || f.masked || f.tuple == 0 {
			return fail()
		}
		if !f.insert {
			stride = 0
			if f.selector < 0 {
				index, stride = 1, 2
			}
		}
		if evex {
			index, offset, stride = 2, 2, 3
			if f.insert {
				index = 1
			}
		}
		if rule.Ytab == "_yvpextrw" {
			extent = 10
			if f.alternate {
				index, offset = index+2, 2
			}
			if evex {
				index, offset = 4, 4
				if f.alternate {
					index, offset = 5, 7
				}
			}
		}
	default:
		return fail()
	}
	transfer := "Yml"
	if !f.gp {
		transfer = "Yxm"
		if f.tuple == 32 {
			transfer = "Yym"
		}
		if evex {
			transfer += "Evex"
		}
	} else if f.alternate {
		transfer = "Yrl"
	}
	transferIndex := count - 1
	if f.insert {
		transferIndex = 1
	}
	if rule.Classes[transferIndex] != transfer || rule.RowIndex != index || rule.EncodingOffset != offset ||
		rule.ZOffset != stride || len(rule.OpBytes) != extent {
		return fail()
	}
	w, opcodeMap, mapByte := "W0", "0F3A", byte(3)
	if strings.HasSuffix(rule.Opcode, "Q") || strings.Contains(rule.Opcode, "64X") {
		w = "W1"
	}
	// Word insertion uses the older 0F transport, independently of its
	// r/m-to-vvvv/result roles. Alternate word extraction shares that map.
	if f.alternate || f.insert && f.gp && f.tuple == 2 {
		opcodeMap, mapByte = "0F", 1
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], []string{
		"avxEscape", kind + strconv.Itoa(f.width), kind + "66", kind + opcodeMap, kind + w,
	}, nil); err != nil {
		return fail()
	}
	opcodeOffset := offset + 1
	if evex {
		features := []string{"evexN" + strconv.Itoa(f.tuple)}
		if block {
			features = append(features, "evexZeroingEnabled")
		}
		if f.alternate {
			features = []string{"0"} // Register-only 0F/C5 has no memory tuple.
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
	f.encoding = x86PackedAVXOpcode{kind: kind, mapByte: mapByte, pp: 1, length: byte(f.width / 256), opcode: byte(opcode)}
	if w == "W1" {
		f.encoding.wBit = 0x80
	}
	return f, nil
}

func x86InsertExtractRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	f, err := x86InsertExtractFormatForRule(rule)
	if err != nil {
		return nil, err
	}
	bank, base := 0, 1
	if f.encoding.kind == "evex" {
		bank, base = 16, 17
	}
	vector := func(bytes, index int) string {
		return fmt.Sprint(map[int]string{16: "X", 32: "Y", 64: "Z"}[bytes], index)
	}
	transferBytes := f.tuple
	if transferBytes < 16 {
		transferBytes = 16
	}
	var witnesses []X86PackedBinaryWitness
	for _, memory := range []bool{false, true} {
		if memory && !f.memory {
			continue
		}
		for _, zeroing := range []bool{false, true} {
			// Memory .Z extraction is retained as a separate source/ISA
			// observation, never silently presented as an ordinary store.
			if zeroing && (!f.masked || memory && !f.insert) {
				continue
			}
			first, second, last := vector(f.width/8, bank), "", vector(transferBytes, bank+2)
			reg, rm, vvvv, p2 := bank, bank+2, byte(0x78), f.encoding.length<<5|8
			if f.gp {
				last, rm = "CX", 1
			}
			if f.insert {
				first, second, last = vector(transferBytes, bank), vector(f.width/8, base), vector(f.width/8, bank+2)
				reg, rm, vvvv = bank+2, bank, byte((^base&15)<<3)
				if f.gp {
					first, rm = "CX", 1
				}
				if base&16 != 0 {
					p2 &^= 8
				}
			} else if f.alternate {
				reg, rm = rm, reg
			}
			modrm := byte(0xc0 | (reg&7)<<3 | rm&7)
			if memory {
				rm, modrm = 0, byte((reg&7)<<3)
				if f.insert {
					first = "(AX)"
				} else {
					last = "(AX)"
				}
			}
			p0 := byte(0)
			for _, extension := range []struct{ bit, mask int }{{8, 0x80}, {16, 0x10}} {
				if reg&extension.bit == 0 {
					p0 |= byte(extension.mask)
				}
			}
			if rm&8 == 0 {
				p0 |= 0x20
			}
			if rm&16 == 0 {
				p0 |= 0x40
			}
			operands, suffix := fmt.Sprintf("$%d,%s", f.selector, first), ""
			if f.insert {
				operands += "," + second
			}
			if f.masked {
				operands, p2 = operands+",K1", p2|1
			}
			if zeroing {
				suffix, p2 = ".Z", p2|0x80
			}
			encoding := append(f.encoding.bytes(vvvv, p0, p2, modrm), byte(f.selector))
			witnesses = append(witnesses, X86PackedBinaryWitness{
				Instruction: rule.Opcode + suffix + " " + operands + "," + last, Generation: f.encoding.kind,
				First: first, Second: second, Destination: last, Width: f.width,
				Memory: f.insert && memory, Masked: f.masked, Zeroing: zeroing, Encoding: encoding,
			})
		}
	}
	return witnesses, nil
}
