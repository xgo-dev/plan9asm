package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/goasmrules"
)

// encoderFormReport is an architecture encoder-table row, expressed with the
// operand classes used by cmd/internal/obj. Unlike assembler testdata, these
// rows enumerate the accepted operand-class surface even when no concrete
// positive test happens to exercise it.
type encoderFormReport struct {
	Opcode         string                  `json:"opcode"`
	OperandClasses []string                `json:"operand_classes"`
	Form           string                  `json:"form"`
	Tables         []string                `json:"tables"`
	AliasedFrom    string                  `json:"aliased_from,omitempty"`
	EncodingRules  []goasmrules.X86AVXRule `json:"encoding_rules,omitempty"`
}

type encoderFormSet struct {
	forms map[string]*encoderFormReport
}

func newEncoderFormSet() *encoderFormSet {
	return &encoderFormSet{forms: map[string]*encoderFormReport{}}
}

func (s *encoderFormSet) add(op string, classes []string, table, alias string) {
	op = strings.ToUpper(strings.TrimSpace(op))
	if op == "" || op == "XXX" || op == "LAST" {
		return
	}
	clean := make([]string, 0, len(classes))
	for _, class := range classes {
		class = strings.TrimSpace(class)
		if class != "" && class != "Ynone" && class != "C_NONE" {
			clean = append(clean, class)
		}
	}
	form := op
	if len(clean) > 0 {
		form += " " + strings.Join(clean, ",")
	}
	key := form
	item := s.forms[key]
	if item == nil {
		item = &encoderFormReport{
			Opcode:         op,
			OperandClasses: append([]string(nil), clean...),
			Form:           form,
			AliasedFrom:    alias,
		}
		s.forms[key] = item
	}
	if table != "" && !containsString(item.Tables, table) {
		item.Tables = append(item.Tables, table)
		sort.Strings(item.Tables)
	}
}

func (s *encoderFormSet) list() []encoderFormReport {
	out := make([]encoderFormReport, 0, len(s.forms))
	for _, item := range s.forms {
		out = append(out, *item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Opcode != out[j].Opcode {
			return out[i].Opcode < out[j].Opcode
		}
		return out[i].Form < out[j].Form
	})
	return out
}

// fingerprintEncoderRules complements, rather than changes, the historical
// operand-class fingerprint. Canonical rows preserve opcode-specific encoding
// attributes and source row positions even after class-bucket grouping. Keep
// duplicates: a repeated matching rule is still part of the original table.
func fingerprintEncoderRules(catalog []encoderFormReport) (int, string) {
	var rows []string
	for _, form := range catalog {
		for _, rule := range form.EncodingRules {
			var row strings.Builder
			fmt.Fprintf(&row, "x86-avx %q %q %q %q %d %d %d",
				rule.Opcode, rule.Ytab, rule.Prefix, rule.ZCase,
				rule.RowIndex, rule.ZOffset, rule.EncodingOffset)
			fmt.Fprintf(&row, " classes:%d", len(rule.Classes))
			for _, class := range rule.Classes {
				fmt.Fprintf(&row, " %q", class)
			}
			fmt.Fprintf(&row, " bytes:%d", len(rule.OpBytes))
			for _, value := range rule.OpBytes {
				fmt.Fprintf(&row, " %q", value)
			}
			rows = append(rows, row.String())
		}
	}
	if len(rows) == 0 {
		// No retained rule metadata means unknown, not an empty-table proof.
		return 0, ""
	}
	sort.Strings(rows)
	data := "go-encoding-rules-v1\n" + strings.Join(rows, "\n")
	return len(rows), fmt.Sprintf("%x", sha256.Sum256([]byte(data)))
}

type parsedEncoderFile struct {
	name string
	file *ast.File
}

func loadEncoderForms(goroot, goarch string) ([]encoderFormReport, error) {
	var dir string
	switch goarch {
	case "386", "amd64":
		dir = "x86"
	case "arm", "arm64":
		dir = goarch
	case "wasm":
		dir = goarch
	default:
		return nil, fmt.Errorf("unsupported encoder architecture %q", goarch)
	}
	base := filepath.Join(goroot, "src", "cmd", "internal", "obj", dir)
	paths, err := filepath.Glob(filepath.Join(base, "*.go"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no Go encoder sources under %s", base)
	}
	if goarch == "wasm" {
		return loadWASMOpcodeForms(base)
	}
	sort.Strings(paths)
	files := make([]parsedEncoderFile, 0, len(paths))
	fset := token.NewFileSet()
	for _, path := range paths {
		name := filepath.Base(path)
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "anames") || strings.HasPrefix(name, "aenum") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil, fmt.Errorf("parse encoder source %s: %w", path, err)
		}
		files = append(files, parsedEncoderFile{name: name, file: file})
	}
	forms := newEncoderFormSet()
	switch goarch {
	case "386", "amd64":
		scanX86EncoderTables(files, forms)
		for _, source := range files {
			if compositeVars(source.file)["avxOptab"] == nil {
				continue
			}
			rules, err := goasmrules.X86AVXRules(source.file)
			if err != nil {
				return nil, fmt.Errorf("read complete AVX rules in %s: %w", source.name, err)
			}
			for _, rule := range rules {
				key := rule.Opcode
				if len(rule.Classes) > 0 {
					key += " " + strings.Join(rule.Classes, ",")
				}
				item := forms.forms[key]
				if item == nil {
					return nil, fmt.Errorf("complete AVX rule %s has no operand-class inventory", key)
				}
				item.EncodingRules = append(item.EncodingRules, rule)
			}
		}
	case "arm":
		scanFixedEncoderTable(files, forms, "optab", []string{"from", "reg", "to"})
		expandEncoderAliases(files, forms, "opset")
	case "arm64":
		scanFixedEncoderTable(files, forms, "optab", []string{"from", "reg", "from3", "to", "to2"})
		expandEncoderAliases(files, forms, "oprangeset")
		scanARM64GeneratedEncoderTables(files, forms)
	}
	return forms.list(), nil
}

// loadWASMOpcodeForms returns the opcode inventory from Go's generated wasm
// name table. Unlike x86 and ARM, cmd/internal/obj/wasm has no operand-class
// encoder table: wasm instructions are emitted directly by wasmobj.go. These
// opcode-only rows therefore complement, rather than pretend to replace, the
// concrete operand forms scanned from GOROOT's selected wasm assembly.
func loadWASMOpcodeForms(base string) ([]encoderFormReport, error) {
	paths, err := filepath.Glob(filepath.Join(base, "anames*.go"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no Go wasm opcode tables under %s", base)
	}
	sort.Strings(paths)
	forms := newEncoderFormSet()
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		for _, match := range reOpcodeName.FindAllSubmatch(src, -1) {
			op := normalizeOp(string(match[1]))
			if op == "" || op == "LAST" || strings.HasPrefix(op, "RESERVED") {
				continue
			}
			forms.add(op, nil, filepath.Base(path)+":opcode-namespace", "")
		}
	}
	return forms.list(), nil
}

func scanX86EncoderTables(files []parsedEncoderFile, forms *encoderFormSet) {
	ytabs := map[string][][]string{}
	for _, src := range files {
		for name, lit := range compositeVars(src.file) {
			if rows, ok := x86YtabRows(lit); ok {
				ytabs[name] = rows
			}
		}
	}
	for _, src := range files {
		vars := compositeVars(src.file)
		for _, table := range []string{"optab", "avxOptab"} {
			lit := vars[table]
			if lit == nil {
				continue
			}
			for _, elt := range lit.Elts {
				row, ok := elt.(*ast.CompositeLit)
				if !ok {
					continue
				}
				opExpr := compositeField(row, "as", 0)
				ytabExpr := compositeField(row, "ytab", 1)
				op := encoderOpcodeName(exprText(opExpr))
				ytab := exprText(ytabExpr)
				rows, found := ytabs[ytab]
				if !found {
					// nil ytab entries are internal/special encodings. Retain them
					// explicitly rather than silently treating them as no form.
					forms.add(op, []string{"@special"}, src.name+":"+table, "")
					continue
				}
				for _, classes := range rows {
					forms.add(op, classes, src.name+":"+table, "")
				}
			}
		}
		if lit := vars["ymovtab"]; lit != nil {
			for _, elt := range lit.Elts {
				row, ok := elt.(*ast.CompositeLit)
				if !ok || len(row.Elts) < 4 {
					continue
				}
				classes := []string{exprText(row.Elts[1]), exprText(row.Elts[2]), exprText(row.Elts[3])}
				forms.add(encoderOpcodeName(exprText(row.Elts[0])), classes, src.name+":ymovtab", "")
			}
		}
	}
}

func x86YtabRows(lit *ast.CompositeLit) ([][]string, bool) {
	rows := make([][]string, 0, len(lit.Elts))
	for _, elt := range lit.Elts {
		row, ok := elt.(*ast.CompositeLit)
		if !ok {
			return nil, false
		}
		var args ast.Expr
		for i, field := range row.Elts {
			if kv, ok := field.(*ast.KeyValueExpr); ok {
				if exprText(kv.Key) == "args" {
					args = kv.Value
					break
				}
				continue
			}
			if i == 2 {
				args = field
			}
		}
		argList, ok := args.(*ast.CompositeLit)
		if !ok || exprText(argList.Type) != "argList" {
			return nil, false
		}
		classes := make([]string, 0, len(argList.Elts))
		for _, arg := range argList.Elts {
			classes = append(classes, exprText(arg))
		}
		rows = append(rows, classes)
	}
	return rows, len(rows) > 0
}

func scanFixedEncoderTable(files []parsedEncoderFile, forms *encoderFormSet, table string, roles []string) {
	for _, src := range files {
		lit := compositeVars(src.file)[table]
		if lit == nil {
			continue
		}
		for _, elt := range lit.Elts {
			row, ok := elt.(*ast.CompositeLit)
			if !ok || len(row.Elts) < len(roles)+1 {
				continue
			}
			classes := make([]string, 0, len(roles))
			for i, role := range roles {
				class := exprText(row.Elts[i+1])
				if class != "C_NONE" {
					classes = append(classes, role+"="+class)
				}
			}
			forms.add(encoderOpcodeName(exprText(row.Elts[0])), classes, src.name+":"+table, "")
		}
	}
}

func expandEncoderAliases(files []parsedEncoderFile, forms *encoderFormSet, helper string) {
	aliases := map[string]string{}
	for _, src := range files {
		for _, decl := range src.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "buildop" || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				clause, ok := node.(*ast.CaseClause)
				if !ok || len(clause.List) == 0 {
					return true
				}
				base := encoderOpcodeName(exprText(clause.List[0]))
				if base == "" {
					return true
				}
				for _, stmt := range clause.Body {
					ast.Inspect(stmt, func(n ast.Node) bool {
						call, ok := n.(*ast.CallExpr)
						if !ok || exprText(call.Fun) != helper || len(call.Args) == 0 {
							return true
						}
						alias := encoderOpcodeName(exprText(call.Args[0]))
						if alias != "" && alias != base {
							aliases[alias] = base
						}
						return true
					})
				}
				return false
			})
		}
	}
	baseForms := forms.list()
	byOpcode := map[string][]encoderFormReport{}
	for _, form := range baseForms {
		byOpcode[form.Opcode] = append(byOpcode[form.Opcode], form)
	}
	for alias, base := range aliases {
		for _, form := range byOpcode[base] {
			forms.add(alias, form.OperandClasses, strings.Join(form.Tables, "+"), base)
		}
	}
}

func scanARM64GeneratedEncoderTables(files []parsedEncoderFile, forms *encoderFormSet) {
	for _, src := range files {
		if !strings.HasPrefix(src.name, "inst") {
			continue
		}
		ast.Inspect(src.file, func(node ast.Node) bool {
			lit, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			var opExpr, argsExpr ast.Expr
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				switch exprText(kv.Key) {
				case "goOp":
					opExpr = kv.Value
				case "args":
					argsExpr = kv.Value
				}
			}
			if opExpr != nil && argsExpr != nil {
				forms.add(encoderOpcodeName(exprText(opExpr)), []string{"args=" + exprText(argsExpr)}, src.name+":insts", "")
			}
			return true
		})
	}
}

func compositeVars(file *ast.File) map[string]*ast.CompositeLit {
	out := map[string]*ast.CompositeLit{}
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			value, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range value.Names {
				if i >= len(value.Values) {
					continue
				}
				if lit, ok := value.Values[i].(*ast.CompositeLit); ok {
					out[name.Name] = lit
				}
			}
		}
	}
	return out
}

func compositeField(row *ast.CompositeLit, key string, index int) ast.Expr {
	for _, elt := range row.Elts {
		if kv, ok := elt.(*ast.KeyValueExpr); ok && exprText(kv.Key) == key {
			return kv.Value
		}
	}
	if index >= 0 && index < len(row.Elts) {
		if _, keyed := row.Elts[index].(*ast.KeyValueExpr); !keyed {
			return row.Elts[index]
		}
	}
	return nil
}

func encoderOpcodeName(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "obj.")
	if len(value) < 2 || value[0] != 'A' {
		return ""
	}
	return strings.TrimPrefix(value, "A")
}

var encoderFileSet = token.NewFileSet()

func exprText(expr ast.Expr) string {
	if expr == nil {
		return ""
	}
	var b bytes.Buffer
	if err := format.Node(&b, encoderFileSet, expr); err != nil {
		return ""
	}
	return b.String()
}
