package goasmrules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestX86AVXRulesRetainAllActualSourceRows(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/avx_optabs.go"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "original.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	var entries *ast.CompositeLit
	rowCounts := map[string]int{}
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		literal, ok := value.Values[0].(*ast.CompositeLit)
		if !ok {
			return true
		}
		rowCounts[value.Names[0].Name] = len(literal.Elts)
		if value.Names[0].Name == "avxOptab" {
			entries = literal
		}
		return true
	})
	if entries == nil {
		t.Fatal("actual Go source lacks avxOptab")
	}
	want := 0
	for _, entry := range entries.Elts {
		row := entry.(*ast.CompositeLit)
		var table string
		for _, entry := range row.Elts {
			if pair, ok := entry.(*ast.KeyValueExpr); ok && pair.Key.(*ast.Ident).Name == "ytab" {
				table = pair.Value.(*ast.Ident).Name
			}
		}
		if table == "" && len(row.Elts) > 1 {
			if name, ok := row.Elts[1].(*ast.Ident); ok {
				table = name.Name
			}
		}
		if rowCounts[table] == 0 {
			t.Fatalf("actual opcode has an unbound ytab %q", table)
		}
		want += rowCounts[table]
	}
	if len(rules) != want || want < 1000 {
		t.Fatalf("lost original encoder rules: got %d, source defines %d", len(rules), want)
	}
	for _, rule := range rules {
		if rule.Opcode == "" || rule.Prefix == "" || rule.ZCase == "" || rule.Classes == nil || len(rule.OpBytes) == 0 {
			t.Fatalf("incomplete actual source rule: %+v", rule)
		}
	}
	t.Logf("all %d original AVX operand/encoding rules retained", want)
}

func TestX86AVXRulesRejectUnrecognizedSourceInsteadOfDroppingIt(t *testing.T) {
	const source = `package x86
var operands = []ytab{{zcase: Zvex_rm_v_r, zoffset: 2, args: argList{Yxm, Yxr, Yxr}}}
var avxOptab = []Optab{{as: AVXORPS, ytab: operands, prefix: Pavx, op: opBytes{vex128 | vex66, 0x57}}}
`
	for _, mutation := range []struct{ before, after string }{
		{"var avxOptab", "var other"},
		{"ytab: operands", "ytab: absent"},
		{"prefix: Pavx,", ""},
		{"zoffset: 2", "zoffset: 1+1"},
		{"args: argList", "args: unknown"},
		{"vex128 | vex66", "makePrefix()"},
		{"0x57", "256"},
		{"Yxm, Yxr, Yxr", "operand(), Yxr, Yxr"},
	} {
		t.Run(mutation.before, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "fixture.go", strings.Replace(source, mutation.before, mutation.after, 1), 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := X86AVXRules(file); err == nil {
				t.Fatal("unrecognized rule was silently inventoried")
			}
		})
	}
}

func TestX86PackedBinaryWitnessesFollowCompleteCurrentTable(t *testing.T) {
	rules, err := LoadX86AVXRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	opcodes := map[string]bool{}
	rows, witnesses := 0, 0
	for _, rule := range rules {
		if rule.Ytab != "_yvandnpd" {
			continue
		}
		cases, err := X86PackedBinarySyntaxWitnesses(rule)
		if err != nil {
			t.Fatal(err)
		}
		if len(cases) < 2 {
			t.Fatal("every rule requires register and memory witnesses")
		}
		opcodes[rule.Opcode] = true
		rows++
		witnesses += len(cases)
	}
	if len(opcodes) < 60 || rows != len(opcodes)*8 {
		t.Fatalf("unexpected complete packed-binary denominator: %d opcodes/%d rules", len(opcodes), rows)
	}
	t.Logf("generated %d source-syntax witnesses from all %d rules/%d opcodes; not object/runtime coverage", witnesses, rows, len(opcodes))
}

func TestX86PackedBinaryWitnessesKeepAttributesIndependent(t *testing.T) {
	rule := X86AVXRule{
		Opcode: "VPMULLW", Ytab: "_yvandnpd", Prefix: "Pavx",
		Classes: []string{"Yzm", "Yzr", "Yknot0", "Yzr"}, ZCase: "Zevex_rm_v_k_r",
		OpBytes: []string{"avxEscape | evex512 | evex66 | evex0F | evexW0", "evexN64 | evexZeroingEnabled", "0xD5"},
	}
	want := []string{"VPMULLW Z0,Z1,K1,Z2", "VPMULLW.Z Z0,Z1,K1,Z2", "VPMULLW (AX),Z1,K1,Z2", "VPMULLW.Z (AX),Z1,K1,Z2"}
	got, err := X86PackedBinarySyntaxWitnesses(rule)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("complete zeroing witness: %v/%v", got, err)
	}
	rule.OpBytes[1] += " | evexBcstN4"
	got, err = X86PackedBinarySyntaxWitnesses(rule)
	want = append(want, "VPMULLW.BCST (AX),Z1,K1,Z2", "VPMULLW.BCST.Z (AX),Z1,K1,Z2")
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("independent broadcast witness: %v/%v", got, err)
	}
	for _, attribute := range []string{"evexRoundingEnabled", "evexSaeEnabled"} {
		local := rule
		local.OpBytes = append([]string(nil), rule.OpBytes...)
		local.OpBytes[1] += " | " + attribute
		if _, err := X86PackedBinarySyntaxWitnesses(local); err == nil {
			t.Fatal("future unaudited suffix silently disappeared")
		}
	}
}
