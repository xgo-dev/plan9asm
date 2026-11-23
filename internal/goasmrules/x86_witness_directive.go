package goasmrules

import (
	"fmt"
	"strconv"
)

// X86DirectiveRow identifies a legacy directive row. Bytes is the number of
// bytes emitted by a raw integer directive. A zero width records a pseudo-op
// row and conveys no alignment, relocation or Go runtime metadata authority.
type X86DirectiveRow struct {
	ID, Opcode string
	Bytes      int
}

// X86DirectiveRows retains both TEXT arities and every ordered NOP row,
// including the second operand-position alternatives with the same classes.
// These source-table entries are shared by Go's 386 and amd64 backends.
func X86DirectiveRows(catalog X86LegacyCatalog) ([]X86DirectiveRow, error) {
	var result []X86DirectiveRow
	seen := map[string]bool{}
	for index, entry := range catalog.Optab {
		table, schema, width := x86DirectiveSchema(entry.Opcode)
		if table == "" {
			continue
		}
		if seen[entry.Opcode] || entry.TableIndex != index || entry.Kind != "encoding" ||
			entry.Ytab != table || entry.Prefix != "Px" || entry.EscapeAdjustment != 0 ||
			len(entry.Rows) != len(schema) {
			return nil, fmt.Errorf("invalid original x86 directive %s table or identity", entry.Opcode)
		}
		seen[entry.Opcode] = true

		if width != 0 && len(entry.OpBytes) != 1 {
			return nil, fmt.Errorf("invalid original %s directive width payload", entry.Opcode)
		}
		for _, atom := range entry.OpBytes {
			value, err := strconv.ParseUint(atom, 0, 8)
			if err != nil || int(value) != width {
				return nil, fmt.Errorf("invalid original %s directive payload: %s", entry.Opcode, atom)
			}
		}
		if err := x86ScalarCompleteOperandSchema(entry, entry.Rows[0], schema); err != nil {
			return nil, fmt.Errorf("original x86 directive %s: %w", entry.Opcode, err)
		}
		for _, operand := range entry.Rows {
			result = append(result, X86DirectiveRow{
				ID:     fmt.Sprintf("optab/%d/%s/%s/%d", index, entry.Opcode, entry.Ytab, operand.RowIndex),
				Opcode: entry.Opcode, Bytes: width,
			})
		}
	}
	if len(seen) != 8 {
		return nil, fmt.Errorf("incomplete original x86 directive members: %d", len(seen))
	}
	return result, nil
}

func x86DirectiveSchema(op string) (table string, rows []string, width int) {
	switch op {
	case "BYTE", "WORD", "LONG", "QUAD":
		width = map[string]int{"BYTE": 1, "WORD": 2, "LONG": 4, "QUAD": 8}[op]
		return "ybyte", []string{"Zbyte/1/Yi64"}, width
	case "NOP":
		return "ynop", []string{
			"Zpseudo/0/",
			"Zpseudo/0/Yiauto", "Zpseudo/0/Yml", "Zpseudo/0/Yrf", "Zpseudo/0/Yxr",
			"Zpseudo/0/Yiauto", "Zpseudo/0/Yml", "Zpseudo/0/Yrf", "Zpseudo/1/Yxr",
		}, 0
	case "TEXT":
		return "ytext", []string{"Zpseudo/0/Ymb,Ytextsize", "Zpseudo/1/Ymb,Yi32,Ytextsize"}, 0
	case "FUNCDATA":
		return "yfuncdata", []string{"Zpseudo/0/Yi32,Ym"}, 0
	case "PCDATA":
		return "ypcdata", []string{"Zpseudo/0/Yi32,Yi32"}, 0
	}
	return "", nil, 0
}
