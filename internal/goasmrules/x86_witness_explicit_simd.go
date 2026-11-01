package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// This source-only projection shares literal/media transport across lane,
// compare, implicit-X0 and sign-mask families. It grants no operand values,
// memory tuple, MMX region, FLAGS or native-entry facts.
func X86LegacyExplicitSIMDRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("explicit SIMD source view requires a Go x86 mode")
	}
	var result []X86ScalarRMWRow
	for _, entry := range catalog.Optab {
		if !x86LegacyExplicitSIMDMember(entry) {
			continue
		}
		for _, original := range entry.Rows {
			witnesses, err := x86LegacyExplicitSIMDRowWitnesses(entry, original)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, original.RowIndex, err)
			}
			row := X86ScalarRMWRow{ID: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, original.RowIndex), Opcode: entry.Opcode, Witnesses: witnesses}
			if arch == "386" && entry.Prefix == "Pq3" {
				row.ModeFiltered, row.Witnesses = "original Go rejects legacy REX.W in mode386", nil
			}
			result = append(result, row)
		}
	}
	if len(result) != 28 {
		return nil, fmt.Errorf("incomplete original explicit SIMD source view: rows=%d", len(result))
	}
	return result, nil
}

func x86LegacyExplicitSIMDMember(entry X86LegacyOpcode) bool {
	switch entry.Ytab {
	case "yextractps", "yextrw", "yextr", "yinsrw", "yinsr", "yxcmpi", "yblendvpd", "ysha1rnds4", "ysha256rnds2", "yxrrl", "ymskb":
		return true
	case "yxr":
		return entry.Prefix == "Pm" // MASKMOVOU retains its implicit-address owner.
	case "yxm_q4":
		return entry.Opcode == "PHMINPOSUW" || entry.Opcode == "PTEST"
	case "yxshuf":
		return entry.Opcode == "INSERTPS" // Explicit overlap with the complete literal view.
	}
	return false
}

func x86LegacyExplicitSIMDEncoding(entry X86LegacyOpcode, row X86LegacyOperand) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, fmt.Errorf("unmodeled complete explicit SIMD source schema") }
	schemas := map[string][]string{
		"yextractps": {"Zibr_m/2/Yu2,Yxr,Yml"},
		"yextrw":     {"Zibm_r/2/Yu8,Yxr,Yrl", "Zibr_m/2/Yu8,Yxr,Yml"},
		"yextr":      {"Zibr_m/3/Yu8,Yxr,Ymm"}, "yinsrw": {"Zibm_r/2/Yu8,Yml,Yxr"}, "yinsr": {"Zibm_r/3/Yu8,Ymm,Yxr"},
		"yxcmpi": {"Zm_r_i_xm/2/Yxm,Yxr,Yi8"}, "yblendvpd": {"Z_m_r/1/Yxr0,Yxm,Yxr"},
		"ysha1rnds4": {"Zibm_r/2/Yu2,Yxm,Yxr"}, "ysha256rnds2": {"Zlit_m_r/0/Yxr0,Yxm,Yxr"},
		"yxrrl": {"Zm_r/1/Yxr,Yrl"}, "ymskb": {"Zm_r_xm/2/Yxr,Yrl", "Zm_r_xm/1/Ymr,Yrl"},
		"yxr": {"Zm_r_xm/1/Yxr,Yxr"}, "yxm_q4": {"Zm_r/1/Yxm,Yxr"},
	}
	if entry.Ytab == "yxshuf" {
		return x86LegacyLiteralSIMDEncoding(entry, row)
	}
	if entry.Kind != "encoding" {
		return fail()
	}
	if err := x86ScalarCompleteOperandSchema(entry, row, schemas[entry.Ytab]); err != nil {
		return nil, err
	}
	escape := 0
	if entry.Ytab == "ysha256rnds2" {
		escape = 1
	}
	if entry.EscapeAdjustment != escape {
		return fail()
	}
	// Symbolic mandatory-prefix atoms belong only to their media positions;
	// every other atom must be an actual byte before any span is selected.
	atoms := make([]byte, len(entry.OpBytes))
	for i, atom := range entry.OpBytes {
		if i == 0 && entry.Prefix == "Px" && (entry.Ytab == "yxcmpi" || entry.Ytab == "ymskb") {
			atoms[i] = map[string]byte{"Pe": 0x66, "Pf2": 0xf2, "Pf3": 0xf3}[atom]
			if atoms[i] == 0 {
				return fail()
			}
			continue
		}
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return fail()
		}
		atoms[i] = byte(value)
	}
	prefix := []byte{0x66, 0x0f}
	opcode := func(value byte) bool { return value != 0 && value != 0x0f }
	literal := func(start, end int) bool {
		if start < 0 || end <= start || end > len(atoms) || atoms[end-1] != 0 {
			return false
		}
		for _, value := range atoms[start : end-1] {
			if value == 0 {
				return false
			}
		}
		return true
	}
	var selected []byte
	switch entry.Ytab {
	case "yextractps", "yextr", "yinsr", "ysha1rnds4":
		if len(atoms) != 3 || !literal(0, 3) || atoms[0] != 0x3a || !opcode(atoms[1]) {
			return fail()
		}
		if entry.Ytab == "ysha1rnds4" {
			if entry.Prefix != "Pm" {
				return fail()
			}
			prefix = []byte{0x0f}
		} else {
			wide := strings.HasSuffix(entry.Opcode, "Q")
			if wide && (entry.Ytab != "yextr" && entry.Ytab != "yinsr" || entry.Prefix != "Pq3") || !wide && entry.Prefix != "Pq" {
				return fail()
			}
			if wide {
				prefix = []byte{0x66, 0x48, 0x0f}
			}
		}
		selected = atoms[:2]
	case "yextrw":
		if entry.Prefix != "Pq" || len(atoms) != 5 || !literal(0, 2) || !literal(2, 5) || !opcode(atoms[0]) || atoms[2] != 0x3a || !opcode(atoms[3]) {
			return fail()
		}
		selected = atoms[:1]
		if row.RowIndex == 1 {
			selected = atoms[2:4]
		}
	case "yinsrw":
		if entry.Prefix != "Pq" || len(atoms) != 2 || !literal(0, 2) || !opcode(atoms[0]) {
			return fail()
		}
		selected = atoms[:1]
	case "yxcmpi":
		if len(atoms) != 2 {
			return fail()
		}
		mandatory := map[string]byte{"PD": 0x66, "SD": 0xf2, "SS": 0xf3}[strings.TrimPrefix(entry.Opcode, "CMP")]
		if entry.Prefix == "Px" && mandatory != 0 && atoms[0] == mandatory {
			prefix = []byte{atoms[0], 0x0f}
			selected = atoms[1:]
		} else if entry.Prefix == "Pm" && entry.Opcode == "CMPPS" && atoms[1] == 0 {
			prefix = []byte{0x0f}
			selected = atoms[:1]
		} else {
			return fail()
		}
		if !opcode(selected[0]) {
			return fail()
		}
	case "ysha256rnds2":
		if entry.Prefix != "Px" || len(atoms) != 4 || !literal(0, 4) || atoms[0] != 0x0f || atoms[1] != 0x38 || !opcode(atoms[2]) {
			return fail()
		}
		prefix = nil
		selected = atoms[:3]
	case "yblendvpd", "yxm_q4":
		if entry.Prefix != "Pq4" || len(atoms) != 1 || !opcode(atoms[0]) {
			return fail()
		}
		prefix = append(prefix, 0x38)
		selected = atoms
	case "yxr", "yxrrl":
		if len(atoms) != 1 || !opcode(atoms[0]) {
			return fail()
		}
		if entry.Prefix == "Pm" {
			prefix = []byte{0x0f}
		} else if entry.Ytab != "yxrrl" || entry.Prefix != "Pq" {
			return fail()
		}
		selected = atoms
	case "ymskb":
		if entry.Prefix != "Px" || len(atoms) != 3 || atoms[0] != 0x66 || !opcode(atoms[1]) || atoms[1] != atoms[2] {
			return fail()
		}
		selected = atoms[1:2]
		if row.RowIndex == 1 {
			prefix = []byte{0x0f}
			selected = atoms[2:]
		}
	default:
		return fail()
	}
	return append(prefix, selected...), nil
}

func x86LegacyExplicitSIMDRowWitnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86ScalarRMWWitness, error) {
	encoding, err := x86LegacyExplicitSIMDEncoding(entry, row)
	if err != nil {
		return nil, err
	}
	sources, destinations := []string{"X0", "(AX)"}, []string{"X1", "X1"}
	if row.Classes[0] == "Yxr" || row.Classes[0] == "Ymr" {
		sources, destinations = []string{"X0"}, []string{"AX"}
		if row.Classes[0] == "Ymr" {
			sources[0] = "M0"
		}
		if row.Classes[1] == "Yxr" {
			destinations[0] = "X1"
		}
	}
	leadingImmediate := row.Classes[0] == "Yu8" || row.Classes[0] == "Yu2"
	extract := row.ZCase == "Zibr_m"
	if leadingImmediate {
		if extract {
			sources, destinations = []string{"X0", "X0"}, []string{"AX", "(AX)"}
		} else if row.Classes[1] == "Yxr" {
			sources, destinations = []string{"X0"}, []string{"AX"}
		} else if row.Classes[1] == "Yml" || row.Classes[1] == "Ymm" {
			sources[0] = "AX"
		}
		if entry.Ytab == "yextrw" && row.RowIndex == 1 {
			sources, destinations = []string{"X0"}, []string{"(AX)"}
		}
	}
	var result []X86ScalarRMWWitness
	for index, source := range sources {
		destination := destinations[index]
		modrm := byte(0xc8)
		if source == "(AX)" {
			modrm = 0x08
		}
		if destination == "AX" {
			modrm = 0xc0
		}
		if destination == "(AX)" {
			modrm = 0x00
		}
		instruction := entry.Opcode + " " + source + "," + destination
		code := append(append([]byte(nil), encoding...), modrm)
		if leadingImmediate {
			immediate := byte(7)
			if row.Classes[0] == "Yu2" {
				immediate = 3
			}
			instruction = fmt.Sprintf("%s $%d,%s,%s", entry.Opcode, immediate, source, destination)
			code = append(code, immediate)
		}
		if row.ZCase == "Zm_r_i_xm" {
			instruction += ",$7"
			code = append(code, 7)
		}
		if row.Classes[0] == "Yxr0" {
			instruction = entry.Opcode + " X0," + source + "," + destination
		}
		result = append(result, X86ScalarRMWWitness{Instruction: instruction, Destination: destination, Encoding: code})
	}
	return result, nil
}
