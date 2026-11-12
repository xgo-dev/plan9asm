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

// X86LegacyCatalog retains both ordered source tables, including their dummy,
// nil-ytab and terminating entries. It is an encoder inventory, not a claim of
// frontend acceptance, selected machine encoding, translation or execution.
type X86LegacyCatalog struct {
	OpBytesSize int               `json:"op_bytes_size"`
	Optab       []X86LegacyOpcode `json:"optab"`
	Movtab      []X86MoveRule     `json:"ymovtab"`
}

type X86LegacyOpcode struct {
	Kind             string             `json:"kind"`
	TableIndex       int                `json:"table_index"`
	Opcode           string             `json:"opcode"`
	OpcodeExpression string             `json:"opcode_expression"`
	Ytab             string             `json:"ytab"`
	Prefix           string             `json:"prefix"`
	OpBytes          []string           `json:"op_bytes"`
	EscapeAdjustment int                `json:"escape_adjustment"`
	Rows             []X86LegacyOperand `json:"rows"`
}

type X86LegacyOperand struct {
	RowIndex int      `json:"row_index"`
	Classes  []string `json:"operand_classes"`
	ZCase    string   `json:"zcase"`
	ZOffset  int      `json:"zoffset"`
	// UnmatchedOffset follows doasm's unmatched-row traversal, including xo
	// for a leading 0x0f. It is not a final byte offset or row-selection proof:
	// suffix/mode filters and zcase-specific consumption remain independent.
	// Keep the complete opcode array; zoffset is not its row payload length.
	UnmatchedOffset int `json:"unmatched_offset"`
}

type X86MoveRule struct {
	Kind             string   `json:"kind"`
	TableIndex       int      `json:"table_index"`
	Opcode           string   `json:"opcode"`
	OpcodeExpression string   `json:"opcode_expression"`
	From             string   `json:"from"`
	From3            string   `json:"from3"`
	To               string   `json:"to"`
	Code             string   `json:"code"`
	OpBytes          []string `json:"op_bytes"`
}

func LoadX86LegacyRules(goroot string) (X86LegacyCatalog, error) {
	path := filepath.Join(goroot, "src/cmd/internal/obj/x86/asm6.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		return X86LegacyCatalog{}, fmt.Errorf("parse Go legacy rules: %w", err)
	}
	return X86LegacyRules(file)
}

func X86LegacyRules(file *ast.File) (X86LegacyCatalog, error) {
	var result X86LegacyCatalog
	variables, err := x86TableVariables(file)
	if err != nil {
		return result, err
	}
	constants := map[string]ast.Expr{}
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range general.Specs {
			switch value := spec.(type) {
			case *ast.TypeSpec:
				if value.Name.Name == "opBytes" {
					array, ok := value.Type.(*ast.ArrayType)
					if !ok || expression(array.Elt) != "uint8" {
						return result, fmt.Errorf("unrecognized opBytes type")
					}
					size, err := strconv.ParseUint(expression(array.Len), 0, 16)
					if err != nil || size == 0 || result.OpBytesSize != 0 {
						return result, fmt.Errorf("unrecognized or repeated opBytes capacity")
					}
					result.OpBytesSize = int(size)
				}
			case *ast.ValueSpec:
				if general.Tok == token.CONST {
					for i, name := range value.Names {
						if i < len(value.Values) {
							constants[name.Name] = value.Values[i]
						}
					}
				}
			}
		}
	}
	optab, movtab := variables["optab"], variables["ymovtab"]
	if result.OpBytesSize == 0 || optab == nil || expression(optab.Type) != "[...]Optab" || len(optab.Elts) < 2 ||
		movtab == nil || expression(movtab.Type) != "[]movtab" || len(movtab.Elts) == 0 {
		return result, fmt.Errorf("missing complete legacy table schema")
	}
	for index, node := range optab.Elts {
		row, ok := node.(*ast.CompositeLit)
		if !ok {
			return result, fmt.Errorf("optab entry %d is not literal", index)
		}
		values, err := x86Fields(row, "as", "ytab", "prefix", "op")
		if err != nil {
			return result, fmt.Errorf("optab entry %d: %w", index, err)
		}
		entry, err := readX86LegacyOpcode(values, index, result.OpBytesSize, variables, constants)
		if err != nil {
			return result, fmt.Errorf("optab entry %d: %w", index, err)
		}
		if (entry.Kind == "reserved") != (index == 0) || (entry.Kind == "sentinel") != (index == len(optab.Elts)-1) {
			return result, fmt.Errorf("optab entry %d has misplaced/missing dummy or sentinel", index)
		}
		result.Optab = append(result.Optab, entry)
	}
	for index, node := range movtab.Elts {
		row, ok := node.(*ast.CompositeLit)
		if !ok {
			return result, fmt.Errorf("ymovtab entry %d is not literal", index)
		}
		values, err := x86Fields(row, "as", "ft", "f3t", "tt", "code", "op")
		if err != nil {
			return result, fmt.Errorf("ymovtab entry %d: %w", index, err)
		}
		entry, err := readX86MoveRule(values, index)
		if err != nil {
			return result, fmt.Errorf("ymovtab entry %d: %w", index, err)
		}
		if err := x86MoveTableRowStructure(entry, index, len(movtab.Elts)); err != nil {
			return result, err
		}
		result.Movtab = append(result.Movtab, entry)
	}
	return result, nil
}

// Captured catalogs and original AST reads share the same complete-table
// structure. An excluded semantic group still cannot hide a forged sentinel.
func x86MoveTableRowStructure(row X86MoveRule, index, count int) error {
	if index < 0 || index >= count || row.TableIndex != index {
		return fmt.Errorf("ymovtab entry %d lost its original table position", index)
	}
	if index == count-1 {
		if row.Kind != "sentinel" || row.Opcode != "" || row.OpcodeExpression != "0" ||
			row.From != "0" || row.From3 != "0" || row.To != "0" || row.Code != "0" || len(row.OpBytes) != 0 {
			return fmt.Errorf("ymovtab entry %d lost its complete zero sentinel", index)
		}
	} else if row.Kind != "encoding" || row.Opcode == "" {
		return fmt.Errorf("ymovtab entry %d is not an original encoding row", index)
	}
	return nil
}

func readX86LegacyOpcode(values []ast.Expr, index, capacity int, variables map[string]*ast.CompositeLit, constants map[string]ast.Expr) (X86LegacyOpcode, error) {
	entry := X86LegacyOpcode{Kind: "encoding", TableIndex: index,
		OpcodeExpression: expression(values[0]), Ytab: expression(values[1]), Prefix: expression(values[2])}
	opcode, err := x86SourceOpcode(values[0])
	if err != nil {
		return entry, err
	}
	entry.Opcode = opcode
	bytes, ok := values[3].(*ast.CompositeLit)
	if !ok || expression(bytes.Type) != "opBytes" || len(bytes.Elts) > capacity {
		return entry, fmt.Errorf("unrecognized opcode array")
	}
	entry.OpBytes, err = x86EncodingBytes(bytes)
	if err != nil {
		return entry, err
	}
	if _, ok := values[1].(*ast.Ident); !ok {
		return entry, fmt.Errorf("unrecognized ytab reference")
	}
	if _, ok := values[2].(*ast.Ident); !ok && entry.Prefix != "0" {
		return entry, fmt.Errorf("unrecognized prefix")
	}
	if opcode == "" || entry.OpcodeExpression == "obj.AXXX" {
		if entry.Ytab != "nil" || entry.Prefix != "0" || len(entry.OpBytes) != 0 {
			return entry, fmt.Errorf("nonzero dummy/sentinel")
		}
		entry.Kind = "sentinel"
		if opcode != "" {
			entry.Kind = "reserved"
		}
		return entry, nil
	}
	if entry.Ytab == "nil" {
		entry.Kind = "special"
		return entry, nil
	}
	rows, err := x86OperandRules(variables[entry.Ytab])
	if err != nil {
		return entry, fmt.Errorf("%s: %w", entry.Ytab, err)
	}
	if len(bytes.Elts) != 0 {
		first := bytes.Elts[0]
		if name, ok := first.(*ast.Ident); ok {
			first = constants[name.Name]
		}
		value, err := strconv.ParseUint(expression(first), 0, 8)
		if err != nil {
			return entry, fmt.Errorf("cannot observe leading opcode byte for xo")
		}
		if value == 0x0f {
			entry.EscapeAdjustment = 1
		}
	}
	offset := 0
	for index, row := range rows {
		entry.Rows = append(entry.Rows, X86LegacyOperand{RowIndex: index, Classes: row.classes,
			ZCase: row.zcase, ZOffset: row.zoffset, UnmatchedOffset: offset})
		offset += row.zoffset + entry.EscapeAdjustment
	}
	return entry, nil
}

func readX86MoveRule(values []ast.Expr, index int) (X86MoveRule, error) {
	entry := X86MoveRule{Kind: "encoding", TableIndex: index, OpcodeExpression: expression(values[0]),
		From: expression(values[1]), From3: expression(values[2]), To: expression(values[3]), Code: expression(values[4])}
	opcode, err := x86SourceOpcode(values[0])
	if err != nil {
		return entry, err
	}
	entry.Opcode = opcode
	bytes, ok := values[5].(*ast.CompositeLit)
	if !ok || expression(bytes.Type) != "[4]uint8" || len(bytes.Elts) > 4 {
		return entry, fmt.Errorf("unrecognized move opcode array")
	}
	entry.OpBytes, err = x86EncodingBytes(bytes)
	if err != nil {
		return entry, err
	}
	for _, value := range values[1:5] {
		if opcode == "" {
			if expression(value) != "0" {
				return entry, fmt.Errorf("nonzero movtab sentinel")
			}
		} else if _, ok := value.(*ast.Ident); !ok {
			return entry, fmt.Errorf("unrecognized move role/code")
		}
	}
	if opcode == "" {
		if len(entry.OpBytes) != 0 {
			return entry, fmt.Errorf("nonzero movtab sentinel bytes")
		}
		entry.Kind = "sentinel"
	}
	return entry, nil
}

func x86SourceOpcode(value ast.Expr) (string, error) {
	name := expression(value)
	if name == "0" {
		return "", nil
	}
	if selector, ok := value.(*ast.SelectorExpr); ok {
		if expression(selector.X) != "obj" {
			return "", fmt.Errorf("foreign opcode %s", name)
		}
		name = selector.Sel.Name
	} else if _, ok := value.(*ast.Ident); !ok {
		return "", fmt.Errorf("unrecognized opcode %s", name)
	}
	return x86SourceOpcodeName(name)
}

// Keep captured enum spelling and its canonical opcode on one conversion
// path. Source projections may validate this redundant identity without
// reparsing expressions or introducing another opcode-name registry.
func x86SourceOpcodeName(name string) (string, error) {
	if !strings.HasPrefix(name, "A") || len(name) == 1 {
		return "", fmt.Errorf("unrecognized opcode %s", name)
	}
	return name[1:], nil
}
