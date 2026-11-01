package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// X86LegacyMediaRow is an explicit carrier projection. The pre-existing
// packed projection intentionally continues to exclude physical MMX regions.
// Source bytes and syntax supply no numerical, memory or entry permission.
type X86LegacyMediaRow struct {
	ID, Opcode, ModeFiltered string
	Witnesses                []X86PackedBinaryWitness
}

func x86LegacyMediaRemainderMember(name string) bool {
	if name == "PSADBW" {
		return true
	}
	for _, stem := range []string{"ADDSUB", "HADD", "HSUB", "RCP", "RSQRT", "SQRT"} {
		if strings.HasPrefix(name, stem) {
			suffix := strings.TrimPrefix(name, stem)
			return suffix == "PS" || suffix == "PD" || suffix == "SS" || suffix == "SD"
		}
	}
	for _, stem := range []string{"COMI", "UCOMI"} {
		if strings.HasPrefix(name, stem) {
			return name == stem+"SS" || name == stem+"SD"
		}
	}
	return name == "CVTPD2PS" || name == "CVTPS2PD" || name == "CVTSD2SS" || name == "CVTSS2SD"
}

// X86LegacyMediaRemainderRows retains each of the original 96 source rows.
// A mode refusal remains an inventory row and cannot acquire a witness.
func X86LegacyMediaRemainderRows(catalog X86LegacyCatalog, arch string) ([]X86LegacyMediaRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("legacy media requires a Go x86 source mode")
	}
	var result []X86LegacyMediaRow
	for _, entry := range catalog.Optab {
		for _, operand := range entry.Rows {
			selected := entry.Ytab == "ymm" && operand.RowIndex == 0 ||
				entry.Ytab == "yps" && operand.RowIndex < 2 || entry.Ytab == "yxmov" ||
				entry.Ytab == "yxm" && x86LegacyMediaRemainderMember(entry.Opcode)
			if !selected {
				continue
			}
			witnesses, mmx, err := x86LegacyMediaRowWitnesses(entry, operand)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, operand.RowIndex, err)
			}
			row := X86LegacyMediaRow{
				ID:     fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex),
				Opcode: entry.Opcode, Witnesses: witnesses,
			}
			if mmx && arch == "386" {
				row.ModeFiltered, row.Witnesses = "original Go Py1/Py3 rejects named MMX in 386 mode", nil
			}
			result = append(result, row)
		}
	}
	if len(result) != 96 {
		return nil, fmt.Errorf("incomplete original legacy media closure: rows=%d", len(result))
	}
	return result, nil
}

// One transport models bank, direction and immediate roles independently of
// semantic families. Table offsets/payloads remain the only opcode source.
type x86LegacyMediaFormat struct {
	prefix           []byte
	opcode, digit    byte
	mmx, store, imm8 bool
}

// Pure carrier/ModRM emission is shared by the old XMM consumer and the
// complete mixed-bank source view. Callers own shape validation and source
// selection. The carrier width establishes neither a memory tuple nor NUM.
func x86LegacyMediaCarrierWitnesses(name string, classes []string, prefix []byte, memorySource bool) []X86PackedBinaryWitness {
	first, last, width := "X0", "X1", 128
	if classes[0] == "Ymm" || classes[0] == "Ymr" {
		first = "M0"
	}
	if classes[1] == "Ymr" {
		last, width = "M1", 64
	} else if classes[1] == "Yml" {
		last = "CX"
	}
	sources, destinations := []string{first}, []string{last}
	if classes[0] == "Ym" {
		sources = []string{"(AX)"}
	} else if memorySource && (classes[0] == "Yxm" || classes[0] == "Ymm") {
		sources = append(sources, "(AX)")
	}
	if classes[1] == "Yml" {
		destinations = append(destinations, "(AX)")
	}
	var result []X86PackedBinaryWitness
	for _, source := range sources {
		for _, destination := range destinations {
			modrm := byte(0xc8)
			if source == "(AX)" {
				modrm = 0x08
			} else if destination == "CX" {
				modrm = 0xc1
			} else if destination == "(AX)" {
				modrm = 0
			}
			result = append(result, X86PackedBinaryWitness{
				Instruction: name + " " + source + "," + destination, Generation: "legacy", Width: width,
				First: source, Second: destination, Destination: destination, Memory: source == "(AX)" || destination == "(AX)",
				Encoding: append(append([]byte(nil), prefix...), modrm),
			})
		}
	}
	return result
}

func x86LegacyMediaRowWitnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86PackedBinaryWitness, bool, error) {
	format, err := x86LegacyMediaFormatForRow(entry, row)
	if err != nil {
		return nil, false, err
	}
	register, width := "X", 128
	if format.mmx {
		register, width = "M", 64
	}
	firsts := []string{register + "0", "(AX)"}
	if entry.Ytab == "yxmov" {
		// A memory operand selects each direction unambiguously. Register
		// aliases and half-move encodings have their independent owners.
		firsts = []string{"(AX)"}
	}
	if format.imm8 {
		firsts = []string{""}
	}
	var result []X86PackedBinaryWitness
	for _, first := range firsts {
		destination, second, modrm := register+"1", register+"1", byte(0xc8)
		if first == "(AX)" {
			modrm = 0x08
		}
		if format.store {
			first, destination, second, modrm = "X1", "(AX)", "", 0x08
		}
		code := append(append([]byte(nil), format.prefix...), format.opcode, modrm)
		instruction := entry.Opcode + " " + first + "," + destination
		if format.imm8 {
			instruction = entry.Opcode + " $-1," + destination
			code[len(code)-1] = 0xc1 | format.digit<<3
			code = append(code, 255)
		}
		result = append(result, X86PackedBinaryWitness{
			Instruction: instruction, Generation: "legacy", Width: width,
			First: first, Second: second, Destination: destination,
			Memory: first == "(AX)" || destination == "(AX)", Encoding: code,
		})
	}
	return result, format.mmx, nil
}

func x86LegacyMediaFormatForRow(entry X86LegacyOpcode, row X86LegacyOperand) (x86LegacyMediaFormat, error) {
	format := x86LegacyMediaFormat{prefix: []byte{0x0f}}
	var schema []string
	offset := row.UnmatchedOffset
	switch entry.Ytab {
	case "ymm":
		if entry.Prefix != "Py1" || len(entry.OpBytes) != 3 || entry.OpBytes[1] != "Pe" || entry.OpBytes[0] != entry.OpBytes[2] || row.RowIndex != 0 {
			return format, fmt.Errorf("unmodeled complete Py1 MMX payload")
		}
		schema = []string{"Zm_r_xm/1/Ymm,Ymr", "Zm_r_xm/2/Yxm,Yxr"}
		format.mmx = true
	case "yps":
		if entry.Prefix != "Py3" || len(entry.OpBytes) != 8 || entry.OpBytes[3] != "Pe" || entry.OpBytes[5] != "Pe" ||
			entry.OpBytes[0] != entry.OpBytes[4] || entry.OpBytes[1] != entry.OpBytes[6] || entry.OpBytes[2] != entry.OpBytes[7] || row.RowIndex > 1 {
			return format, fmt.Errorf("unmodeled complete Py3 MMX payload")
		}
		schema = []string{"Zm_r_xm/1/Ymm,Ymr", "Zibo_m_xm/2/Yi8,Ymr", "Zm_r_xm/2/Yxm,Yxr", "Zibo_m_xm/3/Yi8,Yxr"}
		format.mmx, format.imm8 = true, row.RowIndex == 1
	case "yxmov":
		if len(entry.OpBytes) != 2 {
			return format, fmt.Errorf("unmodeled complete directional media payload")
		}
		schema = []string{"Zm_r_xm/1/Yxm,Yxr", "Zr_m_xm/1/Yxr,Yxm"}
		format.store = row.RowIndex == 1
	case "yxm":
		if !x86LegacyMediaRemainderMember(entry.Opcode) || len(entry.OpBytes) != 1 {
			return format, fmt.Errorf("foreign legacy media family")
		}
		schema = []string{"Zm_r_xm/1/Yxm,Yxr"}
	default:
		return format, fmt.Errorf("unmodeled legacy media table")
	}
	if entry.Kind != "encoding" || entry.EscapeAdjustment != 0 || len(entry.Rows) != len(schema) || row.RowIndex < 0 || row.RowIndex >= len(schema) {
		return format, fmt.Errorf("unmodeled complete media source schema")
	}
	position := 0
	for index, original := range entry.Rows {
		if original.RowIndex != index || original.UnmatchedOffset != position ||
			fmt.Sprintf("%s/%d/%s", original.ZCase, original.ZOffset, strings.Join(original.Classes, ",")) != schema[index] {
			return format, fmt.Errorf("media ordered source row changed")
		}
		position += original.ZOffset
	}
	if fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")) != schema[row.RowIndex] ||
		row.UnmatchedOffset != entry.Rows[row.RowIndex].UnmatchedOffset || position != len(entry.OpBytes) {
		return format, fmt.Errorf("media selected row/complete extent changed")
	}
	if !format.mmx {
		switch entry.Prefix {
		case "Pe", "Pq":
			format.prefix = []byte{0x66, 0x0f}
		case "Pm":
		case "Pf2":
			format.prefix = []byte{0xf2, 0x0f}
		case "Pf3":
			format.prefix = []byte{0xf3, 0x0f}
		default:
			return format, fmt.Errorf("unmodeled legacy media prefix")
		}
	}
	var payload [8]byte // The complete admitted schemas have at most eight atoms.
	for index, token := range entry.OpBytes {
		if token == "Pe" && (entry.Ytab == "ymm" && index == 1 || entry.Ytab == "yps" && (index == 3 || index == 5)) {
			continue // The complete Py1/Py3 schema already bound its positions.
		}
		value, err := strconv.ParseUint(token, 0, 8)
		if err != nil {
			return format, fmt.Errorf("media complete payload contains a non-byte atom")
		}
		payload[index] = byte(value)
	}
	if entry.Ytab == "yps" && payload[2] > 7 {
		return format, fmt.Errorf("media complete /digit is not three bits")
	}
	format.opcode = payload[offset]
	if format.imm8 {
		if payload[offset+1] > 7 {
			return format, fmt.Errorf("media immediate /digit is not three bits")
		}
		format.digit = payload[offset+1]
	}
	return format, nil
}
