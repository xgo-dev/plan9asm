package goasmrules

import (
	"fmt"
	"strconv"
)

func x86LegacyMediaX87Schema(table string) []string {
	switch table {
	case "yxcvm1":
		return []string{"Zm_r_xm/2/Yxm,Yxr", "Zm_r_xm/2/Yxm,Ymr"}
	case "yxcvm2":
		return []string{"Zm_r_xm/2/Yxm,Yxr", "Zm_r_xm/2/Ymm,Yxr"}
	case "ylddqu":
		return []string{"Zm_r/1/Ym,Yxr"}
	case "yxr":
		return []string{"Zm_r_xm/1/Yxr,Yxr"}
	case "ymr":
		return []string{"Zm_r/1/Ymr,Ymr"}
	case "yxr_ml":
		return []string{"Zr_m_xm/1/Yxr,Yml"}
	case "ymr_ml":
		return []string{"Zr_m_xm/1/Ymr,Yml"}
	case "ymrxr":
		return []string{"Zm_r/1/Ymr,Yxr", "Zm_r_xm/1/Yxm,Yxr"}
	case "ymmxmm0f38":
		return []string{"Zlitm_r/3/Ymm,Ymr", "Zlitm_r/5/Yxm,Yxr"}
	case "ymshuf":
		return []string{"Zibm_r/2/Yi8,Ymm,Ymr"}
	case "yfxch":
		return []string{"Zo_m/2/Yf0,Yrf", "Zm_o/2/Yrf,Yf0"}
	case "ystsw":
		return []string{"Zo_m/2/Ym", "Zlit/1/Yax"}
	}
	return nil
}

// X86LegacyMediaX87Rows retains complete original source tables, including
// physical MMX, implicit-address, status and Go-accepted invalid-machine-code
// forms. Source bytes grant none of their numerical or native permissions.
func X86LegacyMediaX87Rows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("media/x87 source view requires an explicit Go x86 mode")
	}
	var result []X86ScalarRMWRow
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		if x86LegacyMediaX87Schema(entry.Ytab) == nil {
			continue
		}
		for _, row := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex)
			if seen[id] {
				return nil, fmt.Errorf("duplicate original media/x87 source row %s", id)
			}
			seen[id] = true
			witnesses, err := x86LegacyMediaX87RowWitnesses(entry, row)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			result = append(result, X86ScalarRMWRow{ID: id, Opcode: entry.Opcode, Witnesses: witnesses})
		}
	}
	if len(result) != 31 {
		return nil, fmt.Errorf("incomplete original media/x87 source tables: rows=%d", len(result))
	}
	return result, nil
}

// Complete-source validation precedes all offsets. Prefix roles, unmatched
// strides, consumed spans and carriers are independent of numerical semantics.
func x86LegacyMediaX87Encoding(entry X86LegacyOpcode, row X86LegacyOperand) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, fmt.Errorf("unmodeled complete media/x87 source grammar") }
	if entry.Kind != "encoding" || entry.Opcode == "" {
		return fail()
	}
	if err := x86ScalarCompleteOperandSchema(entry, row, x86LegacyMediaX87Schema(entry.Ytab)); err != nil {
		return nil, err
	}
	prefix, ok := map[string][]byte{"Px": {}, "Pm": {0x0f}, "Pe": {0x66},
		"Pf2": {0xf2, 0x0f}, "Pf3": {0xf3, 0x0f}, "Pq4": {0x66, 0x0f, 0x38}}[entry.Prefix]
	if !ok {
		return fail()
	}
	atoms := make([]byte, len(entry.OpBytes))
	for index, token := range entry.OpBytes {
		value, err := strconv.ParseUint(token, 0, 8)
		if err != nil && (entry.Ytab == "yxcvm1" || entry.Ytab == "yxcvm2") && entry.Prefix == "Px" && (index == 0 || index == 2) {
			var found bool
			atoms[index], found = map[string]byte{"Pe": 0x66, "Pm": 0x0f, "Pf2": 0xf2, "Pf3": 0xf3}[token]
			if !found {
				return fail()
			}
		} else if err != nil {
			return fail()
		} else {
			atoms[index] = byte(value)
		}
	}
	escape := 0
	if entry.Ytab == "ymmxmm0f38" {
		escape = 1
	}
	if len(atoms) == 0 || entry.EscapeAdjustment != escape || (atoms[0] == 0x0f) != (escape == 1) {
		return fail()
	}
	opcode := func(value byte) bool { return value != 0 && value != 0x0f }
	mediaPrefix := func(value byte) bool { return value == 0x66 || value == 0x0f || value == 0xf2 || value == 0xf3 }
	switch entry.Ytab {
	case "yxcvm1", "yxcvm2":
		if len(atoms) != 4 {
			return fail()
		}
		if entry.Prefix == "Px" && mediaPrefix(atoms[0]) && mediaPrefix(atoms[2]) && opcode(atoms[1]) && opcode(atoms[3]) {
			offset := row.UnmatchedOffset
			prefix = []byte{atoms[offset], 0x0f}
			if atoms[offset] == 0x0f {
				prefix = []byte{0x0f}
			}
			prefix = append(prefix, atoms[offset+1])
		} else if entry.Ytab == "yxcvm2" && entry.Prefix == "Pm" && atoms[1] == 0 && atoms[3] == 0 && opcode(atoms[0]) && opcode(atoms[2]) {
			prefix = append(prefix, atoms[row.UnmatchedOffset])
		} else {
			return fail()
		}
	case "ymmxmm0f38":
		if entry.Prefix != "Px" || len(atoms) != 9 || atoms[0] != 0x0f || atoms[1] != 0x38 || !opcode(atoms[2]) || atoms[3] != 0 ||
			atoms[4] != 0x66 || atoms[5] != 0x0f || atoms[6] != 0x38 || !opcode(atoms[7]) || atoms[8] != 0 {
			return fail()
		}
		end := row.UnmatchedOffset + row.ZOffset
		if row.RowIndex == 0 {
			end++ // The selected leading 0F is also part of the literal span.
		}
		prefix = atoms[row.UnmatchedOffset : end-1]
	case "ymshuf":
		if entry.Prefix != "Pm" || len(atoms) != 2 || !opcode(atoms[0]) || atoms[1] != 0 {
			return fail()
		}
		prefix = append(prefix, atoms[0])
	case "yfxch", "ystsw":
		if entry.Prefix != "Px" || len(atoms) != 4 || atoms[0] < 0xd8 || atoms[0] > 0xdf || atoms[1] > 7 || atoms[2] < 0xd8 || atoms[2] > 0xdf ||
			entry.Ytab == "yfxch" && atoms[3] > 7 || entry.Ytab == "ystsw" && atoms[3] == 0 {
			return fail()
		}
		return atoms[row.UnmatchedOffset : row.UnmatchedOffset+2], nil
	default:
		count := 1
		allowed := entry.Prefix == "Pm"
		switch entry.Ytab {
		case "ylddqu":
			allowed = entry.Prefix == "Pf2" || entry.Prefix == "Pq4"
		case "yxr", "yxr_ml":
			allowed = entry.Prefix == "Pe" || entry.Prefix == "Pm"
		case "ymrxr":
			count, allowed = 2, entry.Prefix == "Pf3"
		}
		if !allowed || len(atoms) != count {
			return fail()
		}
		for _, atom := range atoms {
			if !opcode(atom) {
				return fail()
			}
		}
		if entry.Prefix == "Pe" {
			prefix = append(prefix, 0x0f)
		}
		prefix = append(prefix, atoms[row.UnmatchedOffset])
	}
	return prefix, nil
}

func x86LegacyMediaX87RowWitnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86ScalarRMWWitness, error) {
	encoding, err := x86LegacyMediaX87Encoding(entry, row)
	if err != nil {
		return nil, err
	}
	if entry.Ytab == "yfxch" || entry.Ytab == "ystsw" {
		return x86X87CarrierWitnesses(entry.Opcode, row, encoding[0], encoding[1]), nil
	}
	classes := row.Classes
	immediate := classes[0] == "Yi8"
	if immediate {
		classes = classes[1:]
	}
	// The MMX-input conversion's memory alternative selects the earlier XMM
	// row. Other r/m source classes retain both physical carrier alternatives.
	memorySource := entry.Ytab != "yxcvm2" || row.RowIndex == 0
	packed := x86LegacyMediaCarrierWitnesses(entry.Opcode, classes, encoding, memorySource)
	var result []X86ScalarRMWWitness
	for _, witness := range packed {
		if immediate {
			witness.Instruction = entry.Opcode + " $7," + witness.First + "," + witness.Destination
			witness.Encoding = append(witness.Encoding, 7)
		}
		result = append(result, X86ScalarRMWWitness{Instruction: witness.Instruction, Destination: witness.Destination, Encoding: witness.Encoding})
	}
	return result, nil
}
