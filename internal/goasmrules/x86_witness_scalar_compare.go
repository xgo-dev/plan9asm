package goasmrules

import (
	"fmt"
	"strings"
)

// X86ScalarCompareRows reuses the ordered scalar transport. It supplies no
// data writes or FLAGS values; those belong to the typed read-only effects.
func X86ScalarCompareRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "386" && arch != "amd64" {
		return nil, fmt.Errorf("scalar compare requires a Go x86 source mode")
	}
	var result []X86ScalarRMWRow
	members := make(map[string]bool)
	for _, entry := range catalog.Optab {
		name := entry.Opcode
		if len(name) < 4 {
			continue
		}
		stem, width := name[:len(name)-1], name[len(name)-1]
		if (stem != "CMP" && stem != "TEST") || !strings.ContainsRune("BWLQ", rune(width)) {
			continue
		}
		// Select the semantic family before examining its operand grammar.
		// A new SDK table must produce an explicit gap, not disappear here.
		if members[name] || entry.Kind != "encoding" || len(entry.Rows) == 0 {
			return nil, fmt.Errorf("optab/%d/%s: duplicate or incomplete scalar compare member", entry.TableIndex, name)
		}
		members[name] = true
		for _, operand := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, name, entry.Ytab, operand.RowIndex)
			witnesses, err := x86ScalarRMWRowWitnesses(entry, operand, arch)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			if len(witnesses) == 0 {
				return nil, fmt.Errorf("%s: original scalar compare row has no witness grammar", id)
			}
			row := X86ScalarRMWRow{
				ID:        id,
				Opcode:    name,
				Witnesses: witnesses,
			}
			if arch == "386" && entry.Prefix == "Pw" {
				row.ModeFiltered, row.Witnesses = "original Go rejects REX.W in 386 mode", nil
			}
			result = append(result, row)
		}
	}
	if len(members) != 8 || len(result) != 35 {
		return nil, fmt.Errorf("incomplete original scalar compare closure: members=%d rows=%d", len(members), len(result))
	}
	return result, nil
}
