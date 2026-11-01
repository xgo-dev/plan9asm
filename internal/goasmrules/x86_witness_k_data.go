package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// These are source semantic families, not opcode values or ISA permissions.
// K-data widths and encoded vector length are deliberately independent.
func x86KDataTable(name string) string {
	if len(name) == 8 && strings.HasPrefix(name, "VPMOVM2") && strings.ContainsRune("BWDQ", rune(name[7])) {
		return "_yvpbroadcastmb2q"
	}
	if len(name) == 8 && strings.HasPrefix(name, "VPMOV") && strings.HasSuffix(name, "2M") && strings.ContainsRune("BWDQ", rune(name[5])) {
		return "_yvpmovb2m"
	}
	if len(name) == 8 && strings.HasPrefix(name, "KUNPCK") {
		first, last := strings.IndexByte("BWDQ", name[6]), strings.IndexByte("BWDQ", name[7])
		if first >= 0 && last == first+1 {
			return "_ykaddb"
		}
	}
	if len(name) < 2 || !strings.ContainsRune("BWDQ", rune(name[len(name)-1])) {
		return ""
	}
	switch name[:len(name)-1] {
	case "KADD", "KAND", "KANDN", "KOR", "KXNOR", "KXOR":
		return "_ykaddb"
	case "KNOT", "KTEST", "KORTEST":
		return "_yknotb"
	case "KMOV":
		return "_ykmovb"
	case "KSHIFTL", "KSHIFTR":
		return "_ykshiftlb"
	}
	return ""
}

func X86KDataRows(legacy X86LegacyCatalog, avx []X86AVXRule) ([]X86PackedBinaryRow, error) {
	seen := map[string]bool{}
	var names []string
	for _, rule := range avx {
		if x86KDataTable(rule.Opcode) != "" && !seen[rule.Opcode] {
			seen[rule.Opcode] = true
			names = append(names, rule.Opcode)
		}
	}
	rows, err := x86PackedBinaryRows(legacy, avx, strings.Join(names, " "))
	if err == nil && (len(names) != 59 || len(rows) != 87) {
		err = fmt.Errorf("incomplete K-data source closure: names=%d rows=%d", len(names), len(rows))
	}
	return rows, err
}

func x86KDataRowWitnesses(rule X86AVXRule) ([]X86PackedBinaryWitness, error) {
	fail := func() ([]X86PackedBinaryWitness, error) {
		return nil, fmt.Errorf("K-data roles, width, prefix or ordered source payload changed")
	}
	table, name := rule.Ytab, rule.Opcode
	if table == "" || table != x86KDataTable(name) || rule.Prefix != "Pavx" {
		return fail()
	}
	classes, zcase, index, offset, stride, payload := "Yk,Yk", "Zvex_rm_v_r", 0, 0, 2, 2
	kind, carrier, length, mapName, opcodeMap := "vex", 0, byte(0), "0F", byte(1)
	lane := name[len(name)-1]
	pp, w := byte(0), byte(0)
	if lane == 'B' || lane == 'D' {
		pp = 1
	}
	if lane == 'D' || lane == 'Q' {
		w = 0x80
	}
	switch table {
	case "_ykaddb":
		classes, length = "Yk,Yk,Yk", 1
		if strings.HasPrefix(name, "KUNPCK") {
			pp, w = 0, 0
			if name[6] == 'B' {
				pp = 1
			} else if name[6] == 'D' {
				w = 0x80
			}
		}
	case "_yknotb":
	case "_ykshiftlb":
		classes, zcase, mapName, opcodeMap, pp = "Yu8,Yk,Yk", "Zvex_i_rm_r", "0F3A", 3, 1
		w = 0
		if lane == 'W' || lane == 'Q' {
			w = 0x80
		}
	case "_ykmovb":
		index, payload = rule.RowIndex, 8
		if index < 0 || index >= 4 {
			return fail()
		}
		classes = []string{"Yk,Ym", "Yk,Yrl", "Ykm,Yk", "Yrl,Yk"}[index]
		offset = index * 2
		if index == 0 {
			zcase = "Zvex_r_v_rm"
		}
		if index == 1 || index == 3 {
			if lane == 'D' || lane == 'Q' {
				pp, w = 3, 0
				if lane == 'Q' {
					w = 0x80
				}
			}
		}
	case "_yvpbroadcastmb2q", "_yvpmovb2m":
		index = rule.RowIndex
		if index < 0 || index >= 3 {
			return fail()
		}
		kind, carrier, length = "evex", 128<<uint(index), byte(index)
		zcase, offset, stride, payload, mapName, opcodeMap, pp = "Zevex_rm_v_r", index*3, 3, 9, "0F38", 2, 2
		vector := []string{"YxrEvex", "YyrEvex", "Yzr"}[index]
		classes = "Yk," + vector
		if table == "_yvpmovb2m" {
			classes, lane = vector+",Yk", name[5]
		}
		w = 0
		if lane == 'W' || lane == 'Q' {
			w = 0x80
		}
	default:
		return fail()
	}
	if rule.RowIndex != index || rule.EncodingOffset != offset || rule.ZOffset != stride ||
		rule.ZCase != zcase || strings.Join(rule.Classes, ",") != classes || len(rule.OpBytes) != payload {
		return fail()
	}
	encodedLength := 128 << uint(length)
	wName := "W0"
	if w != 0 {
		wName = "W1"
	}
	atoms := []string{"avxEscape", kind + strconv.Itoa(encodedLength), kind + mapName, kind + wName}
	if pp != 0 {
		atoms = append(atoms, kind+[]string{"", "66", "F3", "F2"}[pp])
	}
	if _, err := x86PackedEncodingAtoms(rule.OpBytes[offset], atoms, nil); err != nil {
		return fail()
	}
	if kind == "evex" && rule.OpBytes[offset+1] != "0" {
		return fail() // Register-only data: no tuple, BCST, mask, Z or SAE.
	}
	opcode, err := strconv.ParseUint(rule.OpBytes[offset+stride-1], 0, 8)
	if err != nil {
		return fail()
	}
	encoding := x86PackedAVXOpcode{kind: kind, mapByte: opcodeMap, wBit: w, pp: pp, length: length, opcode: byte(opcode)}
	type candidate struct {
		first, second, destination, text string
		vvvv, modrm                      byte
		memory                           bool
	}
	candidates := []candidate{{first: "K0", destination: "K3", text: "K0,K3", vvvv: 0x78, modrm: 0xd8}}
	switch table {
	case "_ykaddb":
		candidates[0].second, candidates[0].text, candidates[0].vvvv = "K7", "K0,K7,K3", 0x40
	case "_yknotb":
		if strings.Contains(name, "TEST") {
			candidates[0].second, candidates[0].destination, candidates[0].text, candidates[0].modrm = "K7", "", "K0,K7", 0xf8
		}
	case "_ykshiftlb":
		candidates[0].text = "$5,K0,K3"
	case "_ykmovb":
		switch index {
		case 0:
			candidates[0].destination, candidates[0].text, candidates[0].modrm = "0(AX)", "K0,0(AX)", 0
		case 1:
			candidates[0].destination, candidates[0].text = "BX", "K0,BX"
		case 2:
			candidates = append(candidates, candidate{first: "0(AX)", destination: "K3", text: "0(AX),K3", vvvv: 0x78, modrm: 0x18, memory: true})
		case 3:
			candidates[0].first, candidates[0].text = "AX", "AX,K3"
		}
	case "_yvpbroadcastmb2q":
		vector := fmt.Sprintf("%c1", "XYZ"[index])
		candidates[0].destination, candidates[0].text, candidates[0].modrm = vector, "K0,"+vector, 0xc8
	case "_yvpmovb2m":
		vector := fmt.Sprintf("%c1", "XYZ"[index])
		candidates[0].first, candidates[0].text, candidates[0].modrm = vector, vector+",K3", 0xd9
	}
	var witnesses []X86PackedBinaryWitness
	for _, c := range candidates {
		code := encoding.bytes(c.vvvv, 0xf0, 0x08|length<<5, c.modrm)
		if table == "_ykshiftlb" {
			code = append(code, 5)
		}
		witnesses = append(witnesses, X86PackedBinaryWitness{Instruction: name + " " + c.text, Generation: kind,
			First: c.first, Second: c.second, Destination: c.destination, Width: carrier,
			Memory: c.memory, MaskResult: strings.HasPrefix(c.destination, "K"), Encoding: code})
	}
	return witnesses, nil
}
