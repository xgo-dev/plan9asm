package goasmrules

import (
	"fmt"
	"strconv"
)

// X86ZeroOperandRows projects Go's complete ynone/Zlit source family.
// Literal encodings grant no numerical, FLAGS, memory, stack, native-entry,
// privileged-state or floating-point precision facts to the translator.
func X86ZeroOperandRows(catalog X86LegacyCatalog, arch string) ([]X86ScalarRMWRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("zero-operand source view requires a Go x86 mode")
	}
	var result []X86ScalarRMWRow
	seen := map[string]bool{}
	for _, entry := range catalog.Optab {
		if entry.Ytab != "ynone" {
			continue
		}
		if seen[entry.Opcode] || len(entry.Rows) != 1 {
			return nil, fmt.Errorf("duplicate or incomplete zero-operand source entry")
		}
		seen[entry.Opcode] = true
		row, err := x86ZeroOperandSourceRow(entry, entry.Rows[0], arch, catalog.OpBytesSize)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", entry.Opcode, err)
		}
		result = append(result, row)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("missing zero-operand source entries")
	}
	return result, nil
}

func x86ZeroOperandSourceRow(entry X86LegacyOpcode, selected X86LegacyOperand, arch string, capacity int) (X86ScalarRMWRow, error) {
	var result X86ScalarRMWRow
	fail := func() (X86ScalarRMWRow, error) {
		return result, fmt.Errorf("unmodeled complete zero-operand source grammar")
	}
	if arch != "amd64" && arch != "386" || entry.Kind != "encoding" || entry.Ytab != "ynone" ||
		entry.Opcode == "" || entry.TableIndex < 0 || capacity <= 0 || len(entry.OpBytes) == 0 || len(entry.OpBytes) > capacity {
		return fail()
	}
	if err := x86ScalarCompleteOperandSchema(entry, selected, []string{"Zlit/1/"}); err != nil {
		return result, err
	}
	// PutOpBytesLit reads to the first zero, including implicit array padding.
	// Validate the entire original payload, even bytes after that terminator:
	// SAHF deliberately retains a later, currently unused sequence in Go.
	literal, err := x86SourceLiteralBytes(entry.OpBytes, capacity)
	if err != nil {
		return fail()
	}
	escape := 0
	if literal[0] == 0x0f {
		escape = 1
	}
	if entry.EscapeAdjustment != escape {
		return fail()
	}
	var prefix []byte
	switch entry.Prefix {
	case "Px", "Pb":
	case "Pm":
		prefix = []byte{0x0f}
	case "Pe":
		prefix = []byte{0x66}
	case "Pw":
		prefix = []byte{0x48}
		if arch == "386" {
			result.ModeFiltered = "original Go Pw requires amd64"
		}
	case "P32":
		if arch == "amd64" {
			result.ModeFiltered = "original Go P32 requires 386"
		}
	case "Py":
		if arch == "386" {
			result.ModeFiltered = "original Go Py requires amd64"
		}
	case "Pf3":
		prefix = []byte{0xf3, 0x0f}
	default:
		return fail()
	}
	result.ID = fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, selected.RowIndex)
	result.Opcode = entry.Opcode
	if result.ModeFiltered == "" {
		result.Witnesses = []X86ScalarRMWWitness{{Instruction: entry.Opcode, Encoding: append(prefix, literal...)}}
	}
	return result, nil
}

// Fixed-array literals stop at the first zero, including implicit padding.
// Every source atom remains validated even after emission stops.
func x86SourceLiteralBytes(atoms []string, capacity int) ([]byte, error) {
	if capacity <= 0 || len(atoms) == 0 || len(atoms) > capacity {
		return nil, fmt.Errorf("invalid source literal capacity")
	}
	literal := make([]byte, 0, len(atoms))
	terminated := false
	for _, atom := range atoms {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("source literal contains a non-byte atom")
		}
		if value == 0 {
			terminated = true
		}
		if !terminated {
			literal = append(literal, byte(value))
		}
	}
	if len(literal) == 0 || !terminated && len(atoms) == capacity {
		return nil, fmt.Errorf("empty or unterminated source literal")
	}
	return literal, nil
}
