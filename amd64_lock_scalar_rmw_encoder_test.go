package plan9asm

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// This independent carrier binds every ordered row, operand class, zcase,
// offset, prefix and opcode byte. It does not establish an address permission
// or assert which overlapping row an actual source instruction selects.
func x86LockScalarEncoderCarrier(source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), "asm6.go", source, 0)
	if err != nil {
		return err
	}
	variables := make(map[string]*ast.CompositeLit)
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.VAR {
			continue
		}
		for _, spec := range general.Specs {
			value := spec.(*ast.ValueSpec)
			for index, name := range value.Names {
				if index < len(value.Values) {
					if literal, ok := value.Values[index].(*ast.CompositeLit); ok {
						variables[name.Name] = literal
					}
				}
			}
		}
	}
	canonical := func(node ast.Node) string {
		var output bytes.Buffer
		if err := format.Node(&output, token.NewFileSet(), node); err != nil {
			return ""
		}
		return output.String()
	}
	parse := func(source string) (ast.Expr, error) {
		return parser.ParseExpr(source)
	}
	tables := map[string]string{
		"yxorb": `[]ytab{
			{Zib_, 1, argList{Yi32, Yal}},
			{Zibo_m, 2, argList{Yi32, Ymb}},
			{Zr_m, 1, argList{Yrb, Ymb}},
			{Zm_r, 1, argList{Ymb, Yrb}},
		}`,
		"yaddl": `[]ytab{
			{Zibo_m, 2, argList{Yi8, Yml}},
			{Zil_, 1, argList{Yi32, Yax}},
			{Zilo_m, 2, argList{Yi32, Yml}},
			{Zr_m, 1, argList{Yrl, Yml}},
			{Zm_r, 1, argList{Yml, Yrl}},
		}`,
		"yincl":  `[]ytab{{Z_rp, 1, argList{Yrl}}, {Zo_m, 2, argList{Yml}}}`,
		"yincq":  `[]ytab{{Zo_m, 2, argList{Yml}}}`,
		"yscond": `[]ytab{{Zo_m, 2, argList{Ymb}}}`,
		"ybtl":   `[]ytab{{Zibo_m, 2, argList{Yi8, Yml}}, {Zr_m, 1, argList{Yrl, Yml}}}`,
	}
	for name, text := range tables {
		want, err := parse(text)
		if err != nil {
			return err
		}
		actual := variables[name]
		if actual == nil || canonical(actual) != canonical(want) {
			return fmt.Errorf("complete ordered Go encoder table changed: %s", name)
		}
	}
	optab := variables["optab"]
	if optab == nil {
		return fmt.Errorf("Go encoder has no complete optab")
	}
	pattern := regexp.MustCompile(`^A(?:ADC|ADD|AND|OR|SBB|SUB|XOR|INC|DEC|NEG|NOT|BTC|BTR|BTS)[BWLQ]$`)
	rows := make(map[string]string)
	for _, entry := range optab.Elts {
		row, ok := entry.(*ast.CompositeLit)
		if !ok || len(row.Elts) == 0 {
			continue
		}
		name := canonical(row.Elts[0])
		if !pattern.MatchString(name) {
			continue
		}
		if _, exists := rows[name]; exists {
			return fmt.Errorf("duplicate encoder row: %s", name)
		}
		rows[name] = canonical(row)
	}
	if len(rows) != 53 {
		return fmt.Errorf("complete opcode carrier has %d rows, want 53", len(rows))
	}
	// The native byte formulas below are independent of the typed production
	// spec. Group numbers are written in the actual Go table's octal spelling.
	for _, stem := range []string{"ADC", "ADD", "AND", "OR", "SBB", "SUB", "XOR", "INC", "DEC", "NEG", "NOT", "BTC", "BTR", "BTS"} {
		for _, width := range "BWLQ" {
			if strings.HasPrefix(stem, "BT") && width == 'B' {
				continue
			}
			name := "A" + stem + string(width)
			table, prefix := "yaddl", map[rune]string{'B': "Pb", 'W': "Pe", 'L': "Px", 'Q': "Pw"}[width]
			encoding := ""
			switch stem {
			case "INC", "DEC":
				group, short := 0, 0x40
				if stem == "DEC" {
					group, short = 1, 0x48
				}
				table = "yincq"
				encoding = fmt.Sprintf("0xff, %02o", group)
				if width == 'B' {
					table, encoding = "yscond", fmt.Sprintf("0xfe, %02o", group)
				} else if width == 'L' {
					table, prefix, encoding = "yincl", "Px1", fmt.Sprintf("0x%02x, 0xff, %02o", short, group)
				}
			case "NEG", "NOT":
				group, opcode := 3, 0xf7
				if stem == "NOT" {
					group = 2
				}
				if width == 'B' {
					opcode = 0xf6
				}
				table, encoding = "yscond", fmt.Sprintf("0x%02x, %02o", opcode, group)
			case "BTC", "BTR", "BTS":
				group, opcode := map[string]int{"BTC": 7, "BTR": 6, "BTS": 5}[stem], map[string]int{"BTC": 0xbb, "BTR": 0xb3, "BTS": 0xab}[stem]
				table, encoding = "ybtl", fmt.Sprintf("0xba, %02o, 0x%02x", group, opcode)
				prefix = "Pm"
				if width == 'W' {
					prefix = "Pq"
				} else if width == 'Q' {
					prefix, encoding = "Pw", fmt.Sprintf("0x0f, 0xba, %02o, 0x0f, 0x%02x", group, opcode)
				}
			default:
				group := map[string]int{"ADD": 0, "OR": 1, "ADC": 2, "SBB": 3, "AND": 4, "SUB": 5, "XOR": 6}[stem]
				base := group * 8
				encoding = fmt.Sprintf("0x83, %02o, 0x%02x, 0x81, %02o, 0x%02x, 0x%02x", group, base+5, group, base+1, base+3)
				if width == 'B' {
					table, encoding = "yxorb", fmt.Sprintf("0x%02x, 0x80, %02o, 0x%02x, 0x%02x", base+4, group, base, base+2)
				}
			}
			want, err := parse("[]Optab{{" + name + ", " + table + ", " + prefix + ", opBytes{" + encoding + "}}}")
			if err != nil {
				return err
			}
			if rows[name] != canonical(want.(*ast.CompositeLit).Elts[0]) {
				return fmt.Errorf("opcode-specific complete encoder attributes changed: %s", name)
			}
		}
	}
	return nil
}

func TestX86LockScalarRMWEncoderCarrierRejectsRuleMutation(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	if err := x86LockScalarEncoderCarrier(source); err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ name, from, to string }{
		{"class", "{Zib_, 1, argList{Yi32, Yal}}", "{Zib_, 1, argList{Yi8, Yal}}"},
		{"operand-count", "{Zib_, 1, argList{Yi32, Yal}}", "{Zib_, 1, argList{Yi32, Yal, Ymb}}"},
		{"zcase", "{Zib_, 1, argList{Yi32, Yal}}", "{Zil_, 1, argList{Yi32, Yal}}"},
		{"zoffset", "{Zib_, 1, argList{Yi32, Yal}}", "{Zib_, 2, argList{Yi32, Yal}}"},
		{"row-order", "{Zib_, 1, argList{Yi32, Yal}},\n\t{Zibo_m, 2, argList{Yi32, Ymb}}", "{Zibo_m, 2, argList{Yi32, Ymb}},\n\t{Zib_, 1, argList{Yi32, Yal}}"},
		{"extra-row", "var yincq = []ytab{", "var yincq = []ytab{\n{Zo_m, 2, argList{Ymb}},"},
		{"prefix", "{AADCB, yxorb, Pb,", "{AADCB, yxorb, Px,"},
		{"opcode-bytes", "{AADCB, yxorb, Pb, opBytes{0x14,", "{AADCB, yxorb, Pb, opBytes{0x15,"},
		{"table-binding", "{AADCB, yxorb, Pb,", "{AADCB, yaddl, Pb,"},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			if !strings.Contains(string(source), mutation.from) {
				t.Fatal("mutation no longer binds its actual Go source")
			}
			changed := strings.Replace(string(source), mutation.from, mutation.to, 1)
			if err := x86LockScalarEncoderCarrier([]byte(changed)); err == nil {
				t.Fatal("full Go encoder carrier admitted a changed rule")
			}
		})
	}
}
