package goasmrules

import "fmt"

// X86ScalarCompareRows reuses the ordered scalar transport. It supplies no
// data writes or FLAGS values; those belong to the typed read-only effects.
func X86ScalarCompareRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "386" && arch != "amd64" {
		return nil, fmt.Errorf("scalar compare requires a Go x86 source mode")
	}
	var result []X86ScalarRMWRow
	for _, entry := range catalog.Optab {
		if entry.Ytab != "ycmpl" && entry.Ytab != "ycmpb" && entry.Ytab != "ytestl" {
			continue
		}
		for _, operand := range entry.Rows {
			witnesses, err := x86ScalarRMWRowWitnesses(entry, operand, arch)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, operand.RowIndex, err)
			}
			row := X86ScalarRMWRow{
				ID:     fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex),
				Opcode: entry.Opcode, Witnesses: witnesses,
			}
			if arch == "386" && entry.Prefix == "Pw" {
				row.ModeFiltered, row.Witnesses = "original Go rejects REX.W in 386 mode", nil
			}
			result = append(result, row)
		}
	}
	if len(result) != 31 {
		return nil, fmt.Errorf("incomplete original scalar compare closure: rows=%d", len(result))
	}
	return result, nil
}
