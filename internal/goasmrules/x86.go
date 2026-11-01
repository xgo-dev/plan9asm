// Package goasmrules reads the selected Go assembler's source rules for
// independent coverage checks. These are inventories, not translation, runtime
// or ABI certificates.
package goasmrules

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// X86AVXRule retains a complete operand-class row and its opcode-specific
// encoding table. Shared ytabs alone cannot establish broadcast, rounding,
// SAE, zeroing, tuple widths or the actual encoding generation.
type X86AVXRule struct {
	Opcode         string   `json:"opcode"`
	Ytab           string   `json:"ytab"`
	Prefix         string   `json:"prefix"`
	Classes        []string `json:"operand_classes"`
	RowIndex       int      `json:"row_index"`
	ZCase          string   `json:"zcase"`
	ZOffset        int      `json:"zoffset"`
	EncodingOffset int      `json:"encoding_offset"`
	OpBytes        []string `json:"op_bytes"`
}

func LoadX86AVXRules(goroot string) ([]X86AVXRule, error) {
	path := filepath.Join(goroot, "src", "cmd", "internal", "obj", "x86", "avx_optabs.go")
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read Go AVX rules: %w", err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "avx_optabs.go", source, 0)
	if err != nil {
		return nil, fmt.Errorf("parse Go AVX rules: %w", err)
	}
	return X86AVXRules(file)
}

// X86AVXRules preserves source row order, including rows with equal operand
// classes or zero offsets. It intentionally does not infer frontend acceptance
// or physical register identities from the table.
func X86AVXRules(file *ast.File) ([]X86AVXRule, error) {
	variables, err := x86TableVariables(file)
	if err != nil {
		return nil, err
	}
	entries := variables["avxOptab"]
	if entries == nil {
		return nil, fmt.Errorf("Go AVX source has no literal avxOptab")
	}
	var rules []X86AVXRule
	for index, entry := range entries.Elts {
		row, ok := entry.(*ast.CompositeLit)
		if !ok {
			return nil, fmt.Errorf("AVX entry %d is not a literal rule", index)
		}
		values, err := x86Fields(row, "as", "ytab", "prefix", "op")
		if err != nil {
			return nil, fmt.Errorf("AVX entry %d: %w", index, err)
		}
		opcode := expression(values[0])
		ytab := expression(values[1])
		prefix := expression(values[2])
		encoding, ok := values[3].(*ast.CompositeLit)
		if !strings.HasPrefix(opcode, "A") || len(opcode) < 2 || prefix == "" ||
			!ok || expression(encoding.Type) != "opBytes" {
			return nil, fmt.Errorf("AVX entry %d has an unrecognized opcode/prefix/encoding", index)
		}
		operands := variables[ytab]
		if operands == nil || len(operands.Elts) == 0 {
			return nil, fmt.Errorf("%s has no complete literal ytab %q", opcode, ytab)
		}
		data, err := x86EncodingBytes(encoding)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", opcode, err)
		}
		operandRows, err := x86OperandRules(operands)
		if err != nil {
			return nil, fmt.Errorf("%s/%s: %w", opcode, ytab, err)
		}
		offset := 0
		for operandIndex, operand := range operandRows {
			rules = append(rules, X86AVXRule{
				Opcode: strings.TrimPrefix(opcode, "A"), Ytab: ytab, Prefix: prefix,
				Classes: operand.classes, RowIndex: operandIndex, ZCase: operand.zcase,
				ZOffset: operand.zoffset, EncodingOffset: offset,
				OpBytes: append([]string(nil), data...),
			})
			offset += operand.zoffset
		}
	}
	return rules, nil
}

func expression(value ast.Expr) string {
	if value == nil {
		return ""
	}
	var output bytes.Buffer
	if err := format.Node(&output, token.NewFileSet(), value); err != nil {
		return ""
	}
	return output.String()
}

func encodingExpression(value ast.Expr) bool {
	switch node := value.(type) {
	case *ast.Ident:
		return true
	case *ast.BasicLit:
		_, err := strconv.ParseUint(node.Value, 0, 8)
		return node.Kind == token.INT && err == nil
	case *ast.ParenExpr:
		return encodingExpression(node.X)
	case *ast.BinaryExpr:
		return node.Op == token.OR && encodingExpression(node.X) && encodingExpression(node.Y)
	}
	return false
}
