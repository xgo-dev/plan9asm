package goasmrules

import (
	"encoding/json"
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

const legacyRulesFixture = `package x86
type opBytes [31]uint8
const Pm = 0x0f
var shared = []ytab{
	{Zm_r, 0, argList{Yml, Yrl}},
	{Zm_r, 2, argList{Yml, Yrl}},
	{Zr_m, 1, argList{Yrl, Yml}},
}
var pseudo = []ytab{{Zpseudo, 0, argList{}}}
var optab = [...]Optab{
	{obj.AXXX, nil, 0, opBytes{}},
	{ATEST, shared, Px, opBytes{0x0f, 0x01, 0x02, 0x03, 0x04}},
	{AOTHER, shared, Px1, opBytes{0x83, 0x01, 0x02, 0x03}},
	{obj.ATEXT, pseudo, Px, opBytes{}},
	{AENTER, nil, 0, opBytes{}},
	{0, nil, 0, opBytes{}},
}
var ymovtab = []movtab{
	{AMOVW, Yml, Ynone, Ytask, movMemReg2op, [4]uint8{0x0f, 0x00, 3, 0}},
	{AMOVW, Yml, Ynone, Ytask, movMemReg2op, [4]uint8{0x0f, 0x00, 3, 0}},
	{0, 0, 0, 0, 0, [4]uint8{}},
}
`

func parseLegacyRulesFixture(t *testing.T, source string) *ast.File {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "asm6.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func TestX86LegacyRulesPreserveCompleteEntriesAndOffsets(t *testing.T) {
	got, err := X86LegacyRules(parseLegacyRulesFixture(t, legacyRulesFixture))
	if err != nil {
		t.Fatal(err)
	}
	if got.OpBytesSize != 31 || len(got.Optab) != 6 || len(got.Movtab) != 3 {
		t.Fatal("lost original table entries or array capacity", got)
	}
	for index, kind := range []string{"reserved", "encoding", "encoding", "encoding", "special", "sentinel"} {
		entry := got.Optab[index]
		if entry.Kind != kind || entry.TableIndex != index {
			t.Fatal("lost source order or explicit classification", entry)
		}
	}
	if got.Optab[3].Opcode != "TEXT" || got.Optab[3].OpcodeExpression != "obj.ATEXT" ||
		len(got.Optab[3].Rows) != 1 || got.Optab[3].Rows[0].ZCase != "Zpseudo" ||
		len(got.Optab[3].Rows[0].Classes) != 0 || len(got.Optab[3].OpBytes) != 0 {
		t.Fatal("pseudo/no-operand/implicit-zero roles collapsed", got.Optab[3])
	}
	for index, wantOffsets := range [][]int{{0, 1, 4}, {0, 0, 2}} {
		entry := got.Optab[index+1]
		if entry.EscapeAdjustment != 1-index || entry.Ytab != "shared" || len(entry.Rows) != 3 {
			t.Fatal("lost shared table or leading 0x0f adjustment", entry)
		}
		for rowIndex, offset := range wantOffsets {
			row := entry.Rows[rowIndex]
			if row.RowIndex != rowIndex || row.UnmatchedOffset != offset {
				t.Fatal("legacy skip offset differs from original encoder", row)
			}
		}
		if !reflect.DeepEqual(entry.Rows[0].Classes, entry.Rows[1].Classes) {
			t.Fatal("duplicate operand rows were dropped")
		}
	}
	if !reflect.DeepEqual(got.Optab[1].OpBytes, []string{"0x0f", "0x01", "0x02", "0x03", "0x04"}) {
		t.Fatal("zoffset incorrectly cropped the opcode data", got.Optab[1])
	}
	for index, row := range got.Movtab {
		if row.TableIndex != index {
			t.Fatal("movtab source order lost", row)
		}
	}
	move := got.Movtab[0]
	if move.Kind != "encoding" || move.From != "Yml" || move.From3 != "Ynone" || move.To != "Ytask" ||
		move.Code != "movMemReg2op" || !reflect.DeepEqual(move.OpBytes, []string{"0x0f", "0x00", "3", "0"}) ||
		got.Movtab[2].Kind != "sentinel" {
		t.Fatal("movtab roles/code/complete bytes were lost", got.Movtab)
	}
}

func TestX86LegacyRulesObserveEveryEncodingAttribute(t *testing.T) {
	before, err := X86LegacyRules(parseLegacyRulesFixture(t, legacyRulesFixture))
	if err != nil {
		t.Fatal(err)
	}
	original, err := json.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutation := range []struct{ before, after string }{
		{"{Zm_r, 0", "{Zm_r, 1"},
		{"{Zm_r, 0", "{Zr_m, 0"},
		{"Yml, Yrl", "Yxm, Yxr"},
		{"shared, Px,", "shared, P32,"},
		{"0x04}", "0x05}"},
		{"Yml, Ynone, Ytask", "Yml, Yrl, Ytask"},
		{"movMemReg2op,", "movRegMem2op,"},
		{"0x00, 3, 0", "0x00, 4, 0"},
	} {
		t.Run(mutation.after, func(t *testing.T) {
			changed := strings.Replace(legacyRulesFixture, mutation.before, mutation.after, 1)
			got, err := X86LegacyRules(parseLegacyRulesFixture(t, changed))
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(got)
			if err != nil || string(data) == string(original) {
				t.Fatal("original encoding attribute disappeared", err)
			}
		})
	}
	aliased := strings.Replace(legacyRulesFixture, "opBytes{0x0f", "opBytes{Pm", 1)
	got, err := X86LegacyRules(parseLegacyRulesFixture(t, aliased))
	if err != nil || got.Optab[1].EscapeAdjustment != 1 {
		t.Fatal("xo lost the actual named byte value", got, err)
	}
	keyed := strings.Replace(legacyRulesFixture,
		"{Zm_r, 0, argList{Yml, Yrl}}", "{args: argList{Yml, Yrl}, zoffset: 0, zcase: Zm_r}", 1)
	got, err = X86LegacyRules(parseLegacyRulesFixture(t, keyed))
	if err != nil || !reflect.DeepEqual(got, before) {
		t.Fatal("keyed and positional source rules differ", got, err)
	}
}

func TestX86LegacyRulesFailClosedOnUnknownSource(t *testing.T) {
	for _, mutation := range []struct{ before, after string }{
		{"var optab", "var unknown"},
		{"var optab", "var shared = []ytab{{Zm_r, 1, argList{Yml, Yrl}}}; var optab"},
		{"var ymovtab", "var unknown"},
		{"[31]uint8", "[30+1]uint8"},
		{"ATEST, shared", "ATEST, missing"},
		{"ATEST, shared", "external.ATEST, shared"},
		{"{Zm_r, 0, argList", "{Zm_r, 0, extra, argList"},
		{"{Zm_r, 0, argList{Yml, Yrl}}", "{zcase: Zm_r, zoffset: 0, extra: argList{Yml, Yrl}}"},
		{"{Zm_r, 0, argList{Yml, Yrl}}", "{zcase: Zm_r, zcase: Zr_m, args: argList{Yml, Yrl}}"},
		{"{Zm_r, 0, argList{Yml, Yrl}}", "{zcase: Zm_r, 0, argList{Yml, Yrl}}"},
		{"{Zm_r, 0, argList", "{Zm_r, 1+1, argList"},
		{"argList{Yml, Yrl}", "argList{operand(), Yrl}"},
		{"Px, opBytes{0x0f", "Px, opBytes{makeByte()"},
		{"Px, opBytes{0x0f", "Px, opBytes{256"},
		{"{AENTER, nil, 0, opBytes{}}", "{AENTER, absent, 0, opBytes{}}"},
		{"{0, nil, 0, opBytes{}}", "{0, nil, 1, opBytes{}}"},
		{"{0, nil, 0, opBytes{}}", "{0, nil, 0, opBytes{1}}"},
		{"{0, nil, 0, opBytes{}},", "{0, nil, 0, opBytes{}}, {AENTER, nil, 0, opBytes{}},"},
		{"{obj.AXXX, nil, 0, opBytes{}}", "{AENTER, nil, 0, opBytes{}}"},
		{"{0, 0, 0, 0, 0, [4]uint8{}}", "{0, Ynone, 0, 0, 0, [4]uint8{}}"},
		{"[4]uint8{0x0f", "[5]uint8{0x0f"},
		{"movMemReg2op,", "computeCode(),"},
		{"Yml, Ynone, Ytask", "Yml, role(), Ytask"},
	} {
		t.Run(mutation.after, func(t *testing.T) {
			changed := strings.Replace(legacyRulesFixture, mutation.before, mutation.after, 1)
			if changed == legacyRulesFixture {
				t.Fatal("ineffective mutation")
			}
			if _, err := X86LegacyRules(parseLegacyRulesFixture(t, changed)); err == nil {
				t.Fatal("unrecognized or incomplete source was accepted")
			}
		})
	}
}

func TestX86LegacyRulesRetainEveryActualSourceRow(t *testing.T) {
	got, err := LoadX86LegacyRules(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go"))
	if err != nil {
		t.Fatal(err)
	}
	file := parseLegacyRulesFixture(t, string(source))
	// Independently count actual AST literals, without the reader's field,
	// variable-index or row helpers and without a production opcode registry.
	variables := map[string]*ast.CompositeLit{}
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if ok && len(value.Names) == 1 && len(value.Values) == 1 {
			if literal, ok := value.Values[0].(*ast.CompositeLit); ok {
				variables[value.Names[0].Name] = literal
			}
		}
		return true
	})
	if len(got.Optab) != len(variables["optab"].Elts) || len(got.Movtab) != len(variables["ymovtab"].Elts) {
		t.Fatal("original table entry lost")
	}
	rows := 0
	for index, node := range variables["optab"].Elts {
		entry := node.(*ast.CompositeLit)
		table := entry.Elts[1].(*ast.Ident).Name
		if table == "nil" {
			if len(got.Optab[index].Rows) != 0 || got.Optab[index].Kind == "encoding" {
				t.Fatal("special table invented rows", got.Optab[index])
			}
			continue
		}
		want := len(variables[table].Elts)
		if len(got.Optab[index].Rows) != want || got.Optab[index].TableIndex != index {
			t.Fatal("lost shared or repeated operand rows", table, want, got.Optab[index])
		}
		rows += want
	}
	if rows < 1000 || len(got.Movtab) < 100 {
		t.Fatal("unexpectedly small original legacy inventory", rows, len(got.Movtab))
	}
	t.Logf("retained %d optab entries/%d operand rows and %d movtab entries, including explicit sentinels; inventory only", len(got.Optab), rows, len(got.Movtab))
}
