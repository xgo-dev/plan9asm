package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// X86MovtabRemainderRows joins the five non-TLS fallback code groups.
// The eighteen double shifts keep their existing owner. TLS base loads need
// actual OS/shared/relocation observations and remain absent from this byte
// projection; their all-zero table payload is never a successful encoding.
func X86MovtabRemainderRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" || len(catalog.Movtab) != 113 {
		return nil, fmt.Errorf("movtab source view needs a complete table and explicit x86 mode")
	}
	var result []X86ScalarRMWRow
	seen := map[string]bool{}
	for index, original := range catalog.Movtab {
		if err := x86MoveTableRowStructure(original, index, len(catalog.Movtab)); err != nil {
			return nil, err
		}
		if original.Kind == "sentinel" || original.Code == "movDoubleShift" || original.Code == "movTLSReg" {
			continue
		}
		shape := original.Opcode + "/" + original.From + "/" + original.From3 + "/" + original.To + "/" + original.Code
		if seen[shape] {
			return nil, fmt.Errorf("duplicate original movtab source role: %s", shape)
		}
		seen[shape] = true
		witnesses, err := x86MovtabRemainderRowWitnesses(original)
		if err != nil {
			return nil, fmt.Errorf("movtab/%d: %w", index, err)
		}
		row := X86ScalarRMWRow{
			ID:     fmt.Sprintf("ymovtab/%d/%s/%s", index, original.Opcode, original.Code),
			Opcode: original.Opcode, Witnesses: witnesses,
		}
		if arch == "386" && (original.From == "Ycr8" || original.To == "Ycr8") {
			row.ModeFiltered, row.Witnesses = "original Go rejects CR8 REX.R in 386 mode", nil
		}
		result = append(result, row)
	}
	if len(result) != 92 {
		return nil, fmt.Errorf("incomplete non-TLS movtab source rows: %d", len(result))
	}
	return result, nil
}

func x86MovtabRemainderRowWitnesses(row X86MoveRule) ([]X86ScalarRMWWitness, error) {
	fail := func() ([]X86ScalarRMWWitness, error) {
		return nil, fmt.Errorf("unmodeled complete movtab source grammar")
	}
	if row.Kind != "encoding" || row.TableIndex < 0 || row.Opcode == "" || row.From3 != "Ynone" ||
		len(row.OpBytes) == 0 || len(row.OpBytes) > 4 {
		return fail()
	}
	if row.OpcodeExpression != "" {
		name, err := x86SourceOpcodeName(strings.TrimPrefix(row.OpcodeExpression, "obj."))
		if err != nil || name != row.Opcode {
			return fail()
		}
	}
	if row.Code == "movLit" {
		return x86MovtabStackLiteral(row)
	}
	span, toSpecial := 1, false
	switch row.Code {
	case "movRegMem":
	case "movMemReg":
		toSpecial = true
	case "movRegMem2op":
		span = 2
	case "movMemReg2op":
		span, toSpecial = 2, true
	default:
		return fail() // TLS has no target-independent literal; shifts keep their owner.
	}
	special, ordinary := row.From, row.To
	if toSpecial {
		special, ordinary = row.To, row.From
	}
	extension, valid := x86MovtabSpecialRegister(row.Opcode, special, ordinary, span, toSpecial)
	if !valid {
		return fail()
	}
	var payload [4]byte
	for index, atom := range row.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return fail()
		}
		payload[index] = byte(value)
	}
	if payload[0] == 0 || span == 2 && payload[0] != 0x0f || payload[span] != extension {
		return fail()
	}
	operands := []string{"BX"}
	if ordinary == "Yml" {
		operands = append(operands, "0(SI)")
	} else if ordinary == "Ym" {
		operands = []string{"0(SI)"}
	}
	prefix := append([]byte(nil), payload[:span-1]...)
	if extension == 8 {
		prefix = append([]byte{0x44}, prefix...) // Special-register REX.R; never REX.W.
	}
	var result []X86ScalarRMWWitness
	for _, operand := range operands {
		modrm := byte(0xc3) // BX
		if operand == "0(SI)" {
			modrm = 6
		}
		first, last := strings.ToUpper(strings.TrimPrefix(special, "Y")), operand
		if toSpecial {
			first, last = last, first
		}
		result = append(result, X86ScalarRMWWitness{
			Instruction: row.Opcode + " " + first + "," + last, Destination: last,
			Encoding: x86SourceModRMBytes(prefix, payload[span-1], modrm|(extension&7)<<3),
		})
	}
	return result, nil
}

// The special register determines the ModRM field and legal ordinary class.
// It does not determine opcode bytes, numeric values or native privileges.
func x86MovtabSpecialRegister(op, special, ordinary string, span int, toSpecial bool) (byte, bool) {
	if span == 1 && op == "MOVW" && ordinary == "Yml" {
		for index, class := range []string{"Yes", "Ycs", "Yss", "Yds", "Yfs", "Ygs"} {
			if special == class {
				return byte(index), true
			}
		}
	}
	if span != 2 {
		return 0, false
	}
	if ordinary == "Yrl" && (op == "MOVL" || op == "MOVQ") && len(special) == 4 {
		index := special[3] - '0'
		if special[:3] == "Ycr" && (index == 0 || index == 2 || index == 3 || index == 4 || index == 8) ||
			special[:3] == "Ydr" && (index == 0 || index == 6 || index == 7 || op == "MOVQ" && (index == 2 || index == 3)) {
			return index, true
		}
	}
	if op == "MOVL" && ordinary == "Yml" && (special == "Ytr6" || special == "Ytr7") {
		return special[3] - '0', true
	}
	if (op == "MOVL" || op == "MOVQ") && ordinary == "Ym" && (special == "Ygdtr" || special == "Yidtr") {
		field := byte(0)
		if special == "Yidtr" {
			field = 1
		}
		if toSpecial {
			field += 2
		}
		return field, true
	}
	if op == "MOVW" && ordinary == "Yml" {
		field, found := map[string]byte{"Yldtr": 0, "Ymsw": 4, "Ytask": 1}[special]
		if toSpecial {
			field += 2
		}
		return field, found
	}
	return 0, false
}

func x86MovtabStackLiteral(row X86MoveRule) ([]X86ScalarRMWWitness, error) {
	fail := func() ([]X86ScalarRMWWitness, error) { return nil, fmt.Errorf("unmodeled segment-stack literal") }
	width := row.Opcode[len(row.Opcode)-1]
	stem := row.Opcode[:len(row.Opcode)-1]
	if (stem != "PUSH" && stem != "POP") || !strings.ContainsRune("WLQ", rune(width)) {
		return fail()
	}
	class, empty := row.From, row.To
	if stem == "POP" {
		class, empty = row.To, row.From
	}
	if empty != "Ynone" || !strings.Contains(" Ycs Yss Yds Yes Yfs Ygs ", " "+class+" ") ||
		stem == "POP" && class == "Ycs" || width == 'Q' && class != "Yfs" && class != "Ygs" {
		return fail()
	}
	atoms := append([]string(nil), row.OpBytes...)
	if atoms[0] == "Pe" && width == 'W' {
		atoms[0] = "0x66"
	}
	code, err := x86SourceLiteralBytes(atoms, 4)
	if err != nil || (code[0] == 0x66) != (width == 'W') {
		return fail()
	}
	span := code
	if width == 'W' {
		span = span[1:]
	}
	if len(span) == 0 || span[0] == 0x0f && len(span) != 2 || span[0] != 0x0f && len(span) != 1 {
		return fail()
	}
	operand := strings.ToUpper(strings.TrimPrefix(class, "Y"))
	return []X86ScalarRMWWitness{{Instruction: row.Opcode + " " + operand, Destination: operand, Encoding: code}}, nil
}
