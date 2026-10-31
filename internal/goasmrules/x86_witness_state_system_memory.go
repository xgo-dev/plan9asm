package goasmrules

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
)

// X86StateSystemMemoryRow separates a stock frontend refusal from both mode
// restrictions and the backend's physical encoding. Neither grants numerical,
// storage, privileged-state, CFG or native-entry permission.
type X86StateSystemMemoryRow struct {
	X86ScalarRMWRow
	FrontendRejected string                `json:",omitempty"`
	BackendWitnesses []X86ScalarRMWWitness `json:",omitempty"`
}

// X86UnaryDestinations is immutable to callers; only the source loader can
// populate its complete role map. A zero value cannot classify source rows.
type X86UnaryDestinations struct{ roles map[string]bool }

// LoadX86UnaryDestinations captures the complete original frontend role map.
// It does not change the legacy catalog or its existing serialized views.
func LoadX86UnaryDestinations(goroot string) (X86UnaryDestinations, error) {
	var zero X86UnaryDestinations
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(goroot, "src/cmd/internal/obj/x86/obj6.go"), nil, 0)
	if err != nil {
		return zero, err
	}
	variables, err := x86TableVariables(file)
	if err != nil {
		return zero, err
	}
	literal := variables["unaryDst"]
	if literal == nil || expression(literal.Type) != "map[obj.As]bool" {
		return zero, fmt.Errorf("missing complete original unaryDst role map")
	}
	result := map[string]bool{}
	for _, element := range literal.Elts {
		pair, ok := element.(*ast.KeyValueExpr)
		if !ok {
			return zero, fmt.Errorf("nonliteral unaryDst source role")
		}
		name, err := x86SourceOpcodeName(strings.TrimPrefix(expression(pair.Key), "obj."))
		setting := expression(pair.Value)
		if _, exists := result[name]; exists || err != nil || setting != "true" && setting != "false" {
			return zero, fmt.Errorf("invalid or duplicate unaryDst source role")
		}
		result[name] = setting == "true"
	}
	if len(result) == 0 {
		return zero, fmt.Errorf("empty original unaryDst source roles")
	}
	return X86UnaryDestinations{roles: result}, nil
}

func x86StateSystemMemorySchema(table string) []string {
	switch table {
	case "yclflush", "ysvrs_om":
		return []string{"Zo_m/2/Ym"}
	case "ysvrs_mo", "yprefetch":
		return []string{"Zm_o/2/Ym"}
	case "ydivb":
		return []string{"Zm_o/2/Ymb"}
	case "ydivl":
		return []string{"Zm_o/2/Yml"}
	case "yincq":
		return []string{"Zo_m/2/Yml"}
	case "ywrfsbase":
		return []string{"Zm_o/2/Yrl"}
	case "yrdrand":
		return []string{"Zo_m/2/Yrl"}
	case "yrl_m":
		return []string{"Zr_m/1/Yrl,Ym"}
	case "yrl_ml":
		return []string{"Zr_m/1/Yrl,Yml"}
	case "ym_rl":
		return []string{"Zm_r/1/Ym,Yrl"}
	case "ycrc32l":
		return []string{"Zlitm_r/0/Yml,Yrl"}
	case "yin":
		return []string{"Zib_/1/Yi32", "Zlit/1/"}
	case "yint":
		return []string{"Zib_/1/Yi32"}
	case "yxabort":
		return []string{"Zib_/1/Yu8"}
	case "yxbegin":
		return []string{"Zjmp/1/Ybr"}
	}
	return nil
}

// X86StateSystemMemoryRows retains all original rows, including source
// frontend failures. Destination means the explicit To carrier; implicit
// architectural outputs remain with their independent semantic consumers.
func X86StateSystemMemoryRows(catalog X86LegacyCatalog, frontend X86UnaryDestinations, arch string) ([]X86StateSystemMemoryRow, error) {
	if arch != "amd64" && arch != "386" || len(frontend.roles) == 0 {
		return nil, fmt.Errorf("state source view requires an explicit x86 mode and frontend roles")
	}
	var result []X86StateSystemMemoryRow
	counts, names := map[string]int{}, map[string]bool{}
	for index, entry := range catalog.Optab {
		if x86StateSystemMemorySchema(entry.Ytab) == nil {
			continue
		}
		if entry.TableIndex != index || names[entry.Opcode] {
			return nil, fmt.Errorf("original state source index or unique opcode changed")
		}
		names[entry.Opcode] = true
		for _, original := range entry.Rows {
			counts[entry.Ytab]++
			witnesses, err := x86StateSystemMemoryWitnesses(entry, original, catalog.OpBytesSize)
			if err != nil {
				return nil, fmt.Errorf("%s/%d: %w", entry.Opcode, original.RowIndex, err)
			}
			row := X86StateSystemMemoryRow{X86ScalarRMWRow: X86ScalarRMWRow{
				ID: fmt.Sprintf("optab/%d/%s/%s/%d", index, entry.Opcode, entry.Ytab, original.RowIndex), Opcode: entry.Opcode}}
			if original.ZCase == "Zo_m" {
				if _, exists := frontend.roles[entry.Opcode]; !exists {
					return nil, fmt.Errorf("missing original unary destination role for %s", entry.Opcode)
				}
			}
			if (original.ZCase == "Zm_o" || original.ZCase == "Zo_m") && frontend.roles[entry.Opcode] != (original.ZCase == "Zo_m") {
				row.FrontendRejected = "original unaryDst operand slot disagrees with " + original.ZCase + "; stock asm reports asmand: bad address"
				row.BackendWitnesses = witnesses
			} else if arch == "amd64" && entry.Prefix == "P32" || arch == "386" && (entry.Prefix == "Pw" || entry.Prefix == "Pfw") {
				row.ModeFiltered = "original Go " + entry.Prefix + " rejects this source mode"
			} else {
				row.Witnesses = witnesses
			}
			result = append(result, row)
		}
	}
	want := map[string]int{
		"yclflush": 15, "ysvrs_mo": 9, "ysvrs_om": 6, "yin": 12,
		"yint": 1, "ydivl": 20, "ydivb": 5, "ywrfsbase": 7,
		"ycrc32l": 7, "yprefetch": 4, "yincq": 13, "yrdrand": 10,
		"ym_rl": 12, "yrl_m": 2, "yrl_ml": 10, "yxbegin": 1, "yxabort": 1,
	}
	_, hasRDPID := frontend.roles["RDPID"]
	if hasRDPID {
		want["yrdrand"]++
	}
	if names["RDPID"] != hasRDPID || len(counts) != len(want) {
		return nil, fmt.Errorf("state source/frontend inventory does not contain the complete tables")
	}
	for table, count := range want {
		if counts[table] != count {
			return nil, fmt.Errorf("incomplete state source table %s: %d/%d", table, counts[table], count)
		}
	}
	return result, nil
}

func x86StateSystemMemoryWitnesses(entry X86LegacyOpcode, row X86LegacyOperand, capacity int) ([]X86ScalarRMWWitness, error) {
	if entry.Kind != "encoding" || entry.Opcode == "" || entry.OpcodeExpression == "" || entry.TableIndex < 0 || capacity <= 0 || len(entry.OpBytes) == 0 || len(entry.OpBytes) > capacity {
		return nil, fmt.Errorf("invalid complete state source entry")
	}
	if err := x86ScalarCompleteOperandSchema(entry, row, x86StateSystemMemorySchema(entry.Ytab)); err != nil {
		return nil, err
	}
	var prefix []byte
	switch entry.Prefix {
	case "Px", "Pb", "P32":
	case "Pe":
		prefix = []byte{0x66}
	case "Pm":
		prefix = []byte{0x0f}
	case "Pq":
		prefix = []byte{0x66, 0x0f}
	case "Pf2", "Pf3", "Pfw":
		prefix = []byte{0xf3, 0x0f}
		if entry.Prefix == "Pf2" {
			prefix[0] = 0xf2
		} else if entry.Prefix == "Pfw" {
			prefix = []byte{0xf3, 0x48, 0x0f}
		}
	case "Pw":
		prefix = []byte{0x48}
	default:
		return nil, fmt.Errorf("unmodeled original state source prefix")
	}
	payload := make([]byte, len(entry.OpBytes))
	for index, atom := range entry.OpBytes {
		value, err := strconv.ParseUint(atom, 0, 8)
		if err != nil {
			return nil, fmt.Errorf("state source contains a non-byte atom")
		}
		payload[index] = byte(value)
	}
	if entry.EscapeAdjustment != 0 && payload[0] != 0x0f || entry.EscapeAdjustment == 0 && payload[0] == 0x0f {
		return nil, fmt.Errorf("state source escape and original leading atom differ")
	}
	offset := row.UnmatchedOffset
	if offset >= len(payload) {
		return nil, fmt.Errorf("state source selected span is missing")
	}
	code := append(append([]byte(nil), prefix...), payload[offset])
	if row.ZCase == "Zlit" || row.ZCase == "Zlitm_r" {
		literal, err := x86SourceLiteralBytes(entry.OpBytes[offset:], capacity-offset)
		if err != nil {
			return nil, err
		}
		code = append(append([]byte(nil), prefix...), literal...)
		if entry.Prefix == "Pw" {
			// Go inserts REX after mandatory literal prefixes, before 0F.
			code = code[1:]
			position := 0
			for position < len(code) && (code[position] == 0x66 || code[position] == 0xf2 || code[position] == 0xf3) {
				position++
			}
			code = append(code[:position], append([]byte{0x48}, code[position:]...)...)
		}
	} else if payload[offset] == 0x0f {
		offset++
		if offset >= len(payload) {
			return nil, fmt.Errorf("state source opcode is truncated")
		}
		code = append(code, payload[offset])
	}
	operands := [][2]string{{"", "BX"}}
	switch row.ZCase {
	case "Zm_o", "Zo_m":
		if row.Classes[0] == "Ymb" {
			operands[0][1] = "BL"
		}
		if row.Classes[0] == "Ym" {
			operands = nil
		}
		if row.Classes[0] != "Yrl" {
			operands = append(operands, [2]string{"", "0(SI)"})
		}
	case "Zr_m":
		operands = [][2]string{{"CX", "0(SI)"}}
		if row.Classes[1] == "Yml" {
			operands = append([][2]string{{"CX", "BX"}}, operands...)
		}
	case "Zm_r":
		operands = [][2]string{{"0(SI)", "BX"}}
	case "Zlitm_r":
		operands = [][2]string{{"CX", "BX"}, {"0(SI)", "BX"}}
	case "Zib_":
		operands = [][2]string{{"", "$7"}}
	case "Zlit":
		operands = [][2]string{{}}
	case "Zjmp":
		operands = [][2]string{{"", "1(PC)"}}
	}
	var result []X86ScalarRMWWitness
	for _, args := range operands {
		encoding := append([]byte(nil), code...)
		modrm := byte(0xc3)
		if args[0] == "0(SI)" || args[1] == "0(SI)" {
			modrm = 6
		}
		switch row.ZCase {
		case "Zm_o", "Zo_m":
			if offset+1 >= len(payload) || payload[offset+1] > 7 {
				return nil, fmt.Errorf("state source /digit is truncated or invalid")
			}
			encoding = x86SourceModRMBytes(code[:len(code)-1], code[len(code)-1], modrm|payload[offset+1]<<3)
		case "Zr_m":
			encoding = x86SourceModRMBytes(code[:len(code)-1], code[len(code)-1], modrm|1<<3)
		case "Zm_r", "Zlitm_r":
			if args[0] == "CX" {
				modrm = 0xc1
			}
			encoding = x86SourceModRMBytes(code[:len(code)-1], code[len(code)-1], modrm|3<<3)
		case "Zjmp", "Zib_":
			if entry.Ytab == "yxbegin" || entry.Ytab == "yxabort" {
				if len(payload) < offset+2 || entry.Opcode != map[string]string{"yxbegin": "XBEGIN", "yxabort": "XABORT"}[entry.Ytab] {
					return nil, fmt.Errorf("transaction source lost its original second opcode")
				}
				encoding = append(encoding, payload[offset+1])
			}
			if row.ZCase == "Zjmp" {
				encoding = append(encoding, 0, 0, 0, 0)
			} else {
				encoding = append(encoding, 7)
			}
		}
		instruction, destination := entry.Opcode, args[1]
		if args[0] != "" {
			instruction += " " + args[0] + "," + args[1]
		} else if args[1] != "" {
			instruction += " " + args[1]
		}
		if row.ZCase == "Zm_o" || row.ZCase == "Zib_" {
			destination = ""
		}
		result = append(result, X86ScalarRMWWitness{Instruction: instruction, Destination: destination, Encoding: encoding})
	}
	return result, nil
}
