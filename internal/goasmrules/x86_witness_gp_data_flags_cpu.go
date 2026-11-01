package goasmrules

import (
	"fmt"
	"strings"
)

// Source families sharing a transport do not inherit each other's numerical,
// address, FLAGS, machine-state or native-entry contracts.
func x86GPDataFlagsCPUSourceMember(entry X86LegacyOpcode) bool {
	name := entry.Opcode
	if len(name) == 0 {
		return false
	}
	width, stem := name[len(name)-1], name[:len(name)-1]
	switch entry.Ytab {
	case "yxorb", "ytestl", "ybtl":
		return true // These complete tables own only the selected data families.
	case "ybswap":
		return stem == "BSWAP" && strings.ContainsRune("LQ", rune(width))
	case "ym_rl":
		return stem == "LEA" && strings.ContainsRune("WLQ", rune(width))
	case "yrb_mb":
		return width == 'B' && (stem == "XADD" || stem == "CMPXCHG")
	case "yrl_ml":
		return strings.ContainsRune("WLQ", rune(width)) && (stem == "XADD" || stem == "CMPXCHG") ||
			strings.ContainsRune("LQ", rune(width)) && stem == "MOVNTI" || name == "MOVQL"
	case "yscond":
		return name == "CMPXCHG8B" || name == "CMPXCHG16B"
	case "ycrc32b":
		return name == "CRC32B"
	case "ycrc32l":
		return (stem == "CRC32" || stem == "TZCNT") && strings.ContainsRune("WLQ", rune(width))
	case "yrdrand":
		return name == "RDPID" || (stem == "RDRAND" || stem == "RDSEED") && strings.ContainsRune("WLQ", rune(width))
	}
	return false
}

// X86GPDataFlagsCPURows retains original rows and mode refusals. Go also
// encodes CPU-invalid register destinations for MOVNTI and pair CMPXCHG;
// those source observations must never be treated as numerical positives.
func X86GPDataFlagsCPURows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("GP source view requires a Go x86 mode")
	}
	var result []X86ScalarRMWRow
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		if !x86GPDataFlagsCPUSourceMember(entry) {
			continue
		}
		for _, original := range entry.Rows {
			id := fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, original.RowIndex)
			if seen[id] {
				return nil, fmt.Errorf("duplicate GP source row %s", id)
			}
			seen[id] = true
			witnesses, err := x86ScalarRMWRowWitnesses(entry, original, arch)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", id, err)
			}
			row := X86ScalarRMWRow{ID: id, Opcode: entry.Opcode, Witnesses: witnesses}
			if arch == "386" && entry.Prefix == "Pw" {
				row.ModeFiltered, row.Witnesses = "original Go Pw requires amd64", nil
			}
			result = append(result, row)
		}
	}
	if len(result) != 99 && len(result) != 100 {
		return nil, fmt.Errorf("incomplete GP source view: rows=%d", len(result))
	}
	return result, nil
}
