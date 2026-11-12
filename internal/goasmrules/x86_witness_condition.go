package goasmrules

import (
	"fmt"
	"strconv"
	"strings"
)

// X86ConditionRow retains the Go source row. Branch layout and byte writes
// share condition inputs, not CFG, numerical, native or address authority.
type X86ConditionRow struct {
	ID, Opcode string
	Branch     bool
	Witnesses  []X86ConditionWitness
}

type X86ConditionWitness struct {
	Instruction, Layout string
	Encoding            []byte
}

// X86ConditionalRows covers both complete legacy condition families. The
// fixed closed layouts use known instruction lengths, never actual Go bytes
// as their expected displacement. Go remains the branch relaxation engine.
func X86ConditionalRows(catalog X86LegacyCatalog, arch string) ([]X86ConditionRow, error) {
	if arch != "amd64" && arch != "386" {
		return nil, fmt.Errorf("conditional rows require a Go x86 mode")
	}
	var result []X86ConditionRow
	names := map[string]bool{}
	for _, entry := range catalog.Optab {
		branch := entry.Ytab == "yjcond"
		if !branch && (entry.Ytab != "yscond" || !strings.HasPrefix(entry.Opcode, "SET")) {
			continue
		}
		if names[entry.Opcode] {
			return nil, fmt.Errorf("duplicate conditional member %s", entry.Opcode)
		}
		names[entry.Opcode] = true
		payload, err := x86ConditionPayload(entry, branch)
		if err != nil {
			return nil, err
		}
		for _, operand := range entry.Rows {
			row := X86ConditionRow{ID: fmt.Sprintf("optab/%d/%s/%s/%d", entry.TableIndex, entry.Opcode, entry.Ytab, operand.RowIndex), Opcode: entry.Opcode, Branch: branch}
			if branch {
				hint := ""
				if operand.RowIndex != 0 {
					hint = fmt.Sprintf("$%d,", operand.RowIndex-1)
				}
				move := 3 // MOVQ GP,GP and CMPQ GP,GP; no handwritten jump padding.
				if arch == "386" {
					move = 2
				}
				for _, layout := range []struct {
					name         string
					displacement int
				}{
					{"short-forward", move},
					{"near-forward", 128 + move},
					{"short-backward", -(2*move + 4)},
					{"near-backward", -(2*move + 139)},
				} {
					code := []byte{payload[0], byte(layout.displacement)}
					if strings.HasPrefix(layout.name, "near") {
						code = []byte{0x0f, payload[1]}
						for index := 0; index < 4; index++ {
							code = append(code, byte(uint32(layout.displacement)>>uint(index*8)))
						}
					}
					row.Witnesses = append(row.Witnesses, X86ConditionWitness{Instruction: entry.Opcode + " " + hint + "taken", Layout: layout.name, Encoding: code})
				}
			} else {
				for _, destination := range []struct {
					name  string
					modrm byte
				}{{"AX", 0xc0}, {"AH", 0xc4}, {"0(SI)", 0x06}} {
					code := append(append([]byte(nil), payload[:2]...), destination.modrm)
					row.Witnesses = append(row.Witnesses, X86ConditionWitness{Instruction: entry.Opcode + " " + destination.name, Layout: destination.name, Encoding: code})
				}
			}
			result = append(result, row)
		}
	}
	if len(names) != 32 || len(result) != 64 {
		return nil, fmt.Errorf("incomplete condition closure: names=%d rows=%d", len(names), len(result))
	}
	return result, nil
}

func x86ConditionPayload(entry X86LegacyOpcode, branch bool) ([]byte, error) {
	fail := func() ([]byte, error) {
		return nil, fmt.Errorf("unmodeled complete conditional schema/payload: %s", entry.Opcode)
	}
	var payload []byte
	for _, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return fail()
		}
		payload = append(payload, byte(value))
	}
	if entry.Kind != "encoding" {
		return fail()
	}
	if branch {
		if entry.Ytab != "yjcond" || entry.Prefix != "Px" || entry.EscapeAdjustment != 0 || len(entry.Rows) != 3 ||
			len(payload) != 2 && len(payload) != 3 || payload[0] < 0x70 || payload[0] > 0x7f ||
			payload[1] != payload[0]+0x10 || len(payload) == 3 && payload[2] != 0 {
			return fail()
		}
		for index, row := range entry.Rows {
			classes := []string{"Ybr", "Yi0,Ybr", "Yi1,Ybr"}[index]
			stride := 0
			if index == 2 {
				stride = 1
			}
			if row.RowIndex != index || row.ZCase != "Zbr" || row.ZOffset != stride || row.UnmatchedOffset != 0 || strings.Join(row.Classes, ",") != classes {
				return fail()
			}
		}
	} else {
		if entry.Ytab != "yscond" || entry.Prefix != "Pb" || entry.EscapeAdjustment != 1 || len(entry.Rows) != 1 ||
			len(payload) != 3 || payload[0] != 0x0f || payload[1] < 0x90 || payload[1] > 0x9f || payload[2] != 0 {
			return fail()
		}
		row := entry.Rows[0]
		if row.RowIndex != 0 || row.ZCase != "Zo_m" || row.ZOffset != 2 || row.UnmatchedOffset != 0 || strings.Join(row.Classes, ",") != "Ymb" {
			return fail()
		}
	}
	return payload, nil
}
