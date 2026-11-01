package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// X86ScalarShiftRotateRows retains Group2 and the separate double-shift
// fallback. Equal SAL/SHL bytes do not merge their original source records.
func X86ScalarShiftRotateRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("scalar shifts require a Go x86 mode")
	}
	var rows []X86ScalarRMWRow
	names := map[string]bool{}
	add := func(id, opcode string, witnesses []X86ScalarRMWWitness) {
		row := X86ScalarRMWRow{ID: id, Opcode: opcode, Witnesses: witnesses}
		if arch == "386" && strings.HasSuffix(opcode, "Q") {
			row.Witnesses, row.ModeFiltered = nil, "legacy Q requires amd64"
		}
		rows = append(rows, row)
	}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "yshb" && entry.Ytab != "yshl" {
			continue
		}
		names[entry.Opcode] = true
		for _, row := range entry.Rows {
			witnesses, err := x86ScalarGroup2Witnesses(entry, row)
			if err != nil {
				return nil, err
			}
			add(fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, row.RowIndex), entry.Opcode, witnesses)
		}
	}
	for _, row := range catalog.Movtab {
		if row.Code != "movDoubleShift" {
			continue
		}
		witnesses, err := x86ScalarDoubleShiftWitnesses(row)
		if err != nil || !names[row.Opcode] {
			return nil, fmt.Errorf("double-shift source roles: %v", err)
		}
		add(fmt.Sprintf("ymovtab/%d/%s/movDoubleShift", row.TableIndex, row.Opcode), row.Opcode, witnesses)
	}
	if len(names) != 32 || len(rows) != 138 {
		return nil, fmt.Errorf("incomplete scalar shift closure: names=%d records=%d", len(names), len(rows))
	}
	return rows, nil
}

func x86ScalarGroup2Witnesses(entry X86LegacyOpcode, row X86LegacyOperand) ([]X86ScalarRMWWitness, error) {
	fail := func() ([]X86ScalarRMWWitness, error) {
		return nil, fmt.Errorf("unmodeled complete Group2 schema/payload")
	}
	if entry.Kind != "encoding" || len(entry.Opcode) < 2 || entry.EscapeAdjustment != 0 {
		return fail()
	}
	width := entry.Opcode[len(entry.Opcode)-1]
	byteOperand := width == 'B'
	expectedPrefix := map[byte]string{'B': "Pb", 'W': "Pe", 'L': "Px", 'Q': "Pw"}[width]
	schema := []string{"Zo_m/2/Yi1,Yml", "Zibo_m/2/Yu8,Yml", "Zo_m/2/Ycl,Yml", "Zo_m/2/Ycx,Yml"}
	if byteOperand {
		schema = []string{"Zo_m/2/Yi1,Ymb", "Zibo_m/2/Yu8,Ymb", "Zo_m/2/Ycx,Ymb"}
	}
	if entry.Ytab != map[bool]string{true: "yshb", false: "yshl"}[byteOperand] ||
		expectedPrefix == "" || entry.Prefix != expectedPrefix ||
		len(entry.Rows) != len(schema) || len(entry.OpBytes) != len(schema)*2 || row.RowIndex < 0 || row.RowIndex >= len(schema) {
		return fail()
	}
	var payload []byte
	for _, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return fail()
		}
		payload = append(payload, byte(value))
	}
	for index, original := range entry.Rows {
		if original.RowIndex != index || original.UnmatchedOffset != index*2 ||
			fmt.Sprintf("%s/%d/%s", original.ZCase, original.ZOffset, strings.Join(original.Classes, ",")) != schema[index] ||
			payload[index*2+1] > 7 || payload[index*2+1] != payload[1] {
			return fail()
		}
	}
	if row.UnmatchedOffset != row.RowIndex*2 || fmt.Sprintf("%s/%d/%s", row.ZCase, row.ZOffset, strings.Join(row.Classes, ",")) != schema[row.RowIndex] {
		return fail()
	}
	counts := map[string][]string{"Yi1": {"$1"}, "Yu8": {"$0", "$7"}, "Ycl": {"CL"}, "Ycx": {"CX"}}[row.Classes[0]]
	if byteOperand && row.Classes[0] == "Ycx" {
		counts = append(counts, "CL") // Both spellings select this byte row.
	}
	var prefix []byte
	if width == 'W' {
		prefix = []byte{0x66}
	} else if width == 'Q' {
		prefix = []byte{0x48}
	}
	return x86ScalarShiftWitnesses(entry.Opcode, prefix, payload[row.UnmatchedOffset], payload[row.UnmatchedOffset+1], counts, byteOperand, false), nil
}

func x86ScalarDoubleShiftWitnesses(row X86MoveRule) ([]X86ScalarRMWWitness, error) {
	fail := func() ([]X86ScalarRMWWitness, error) {
		return nil, fmt.Errorf("unmodeled complete movDoubleShift schema/payload")
	}
	if row.Kind != "encoding" || row.Code != "movDoubleShift" || len(row.Opcode) < 2 || row.From3 != "Yrl" || row.To != "Yml" || len(row.OpBytes) != 4 {
		return fail()
	}
	width := row.Opcode[len(row.Opcode)-1]
	stem := row.Opcode[:len(row.Opcode)-1]
	if stem != "SHL" && stem != "SHR" {
		return fail()
	}
	offset, prefix := 0, []byte{0x0f}
	if width == 'W' || width == 'Q' {
		atom, value := "Pe", byte(0x66)
		if width == 'Q' {
			atom, value = "Pw", 0x48
		}
		if row.OpBytes[0] != atom {
			return fail()
		}
		offset, prefix = 1, []byte{value, 0x0f}
	} else if width != 'L' {
		return fail()
	}
	var opcodes []byte
	for _, atom := range row.OpBytes[offset:] {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return fail()
		}
		opcodes = append(opcodes, byte(value))
	}
	for _, padding := range opcodes[2:] {
		if padding != 0 {
			return fail()
		}
	}
	counts := map[string][]string{"Yi8": {"$1"}, "Ycl": {"CL"}, "Ycx": {"CX"}}[row.From]
	if len(counts) == 0 {
		return fail()
	}
	opcode := opcodes[0]
	if row.From != "Yi8" {
		opcode = opcodes[1]
	}
	return x86ScalarShiftWitnesses(row.Opcode, prefix, opcode, 0, counts, false, true), nil
}

// Source opcodes and /digit values remain literal Go payload, not another
// per-mnemonic table. Count kind, data width and ModRM roles stay independent.
func x86ScalarShiftWitnesses(opcode string, prefix []byte, op, extension byte, counts []string, byteOperand, double bool) []X86ScalarRMWWitness {
	destination := "BX"
	if byteOperand {
		destination = "BL"
	}
	var witnesses []X86ScalarRMWWitness
	for _, last := range []string{destination, "0(SI)"} {
		for _, count := range counts {
			operands, modrm := count+","+last, byte(0xc3)
			if last == "0(SI)" {
				modrm = 6
			}
			if double {
				operands = count + ",AX," + last
			} else {
				modrm |= extension << 3
			}
			encoded := x86SourceModRMBytes(prefix, op, modrm)
			if strings.HasPrefix(count, "$") && (double || count != "$1") {
				value, _ := strconv.Atoi(count[1:])
				encoded = append(encoded, byte(value))
			}
			witnesses = append(witnesses, X86ScalarRMWWitness{Instruction: opcode + " " + operands, Destination: last, Encoding: encoded})
		}
	}
	return witnesses
}

// Source-only ModRM emission. Grammar, register-bank and memory roles must
// be validated before callers supply the complete prefix/opcode and field.
func x86SourceModRMBytes(prefix []byte, opcode, modrm byte) []byte {
	return append(append([]byte(nil), prefix...), opcode, modrm)
}
