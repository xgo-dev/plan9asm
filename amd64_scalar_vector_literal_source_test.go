package plan9asm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

// This is a test oracle for the invoked stock assembler, not an alternative
// translator grammar. Inspect the actual GOROOT rather than guessing a version
// boundary: Go 1.20 rewrites only MOVSS/SD, while current Go also rewrites VMOV.
func x86ScalarLiteralActualGoRewriteSet(t *testing.T) bool {
	t.Helper()
	root, err := filepath.EvalSymlinks(runtime.GOROOT())
	if err != nil {
		t.Fatal(err)
	}
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	driver, err = filepath.EvalSymlinks(driver)
	if err != nil || driver != filepath.Join(root, "bin", gotoolchain.HostExecutable("go")) {
		t.Fatalf("literal oracle requires this toolchain's stock Go driver: %v", err)
	}
	run := func(arguments ...string) string {
		stage, cancelStage := runtimeOracleStageContext(t)
		defer cancelStage()
		ctx, cancel := context.WithTimeout(stage, 30*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, driver, arguments...)
		command.Env = append(os.Environ(), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local")
		output, err := runtimeOracleCombinedOutput(ctx, command)
		if err != nil {
			t.Fatalf("actual Go literal driver failed: %v\n%s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	environment := strings.Split(run("env", "GOROOT", "GOVERSION"), "\n")
	if len(environment) != 2 || environment[1] != runtime.Version() {
		t.Fatalf("actual Go literal driver/toolchain mismatch: %q", environment)
	}
	actualRoot, err := filepath.EvalSymlinks(environment[0])
	if err != nil || actualRoot != root {
		t.Fatalf("actual Go literal GOROOT mismatch: %v", err)
	}
	assembler := run("tool", "-n", "asm")
	if !filepath.IsAbs(assembler) {
		t.Fatalf("unrecognized actual assembler route: %q", assembler)
	}
	paths := map[string]string{
		"go": driver, "asm": assembler,
		"obj6.go":       filepath.Join(root, "src", "cmd", "internal", "obj", "x86", "obj6.go"),
		"asm6.go":       filepath.Join(root, "src", "cmd", "internal", "obj", "x86", "asm6.go"),
		"avx_optabs.go": filepath.Join(root, "src", "cmd", "internal", "obj", "x86", "avx_optabs.go"),
	}
	digests := make(map[string][sha256.Size]byte)
	var source []byte
	for _, name := range []string{"go", "asm", "obj6.go", "asm6.go", "avx_optabs.go"} {
		data, err := os.ReadFile(paths[name])
		if err != nil || len(data) == 0 {
			t.Fatalf("missing literal oracle input %s: %v", name, err)
		}
		digests[name] = sha256.Sum256(data)
		t.Logf("actual %s %s SHA256=%x", runtime.Version(), name, digests[name])
		if name == "obj6.go" {
			source = data
		}
	}
	t.Cleanup(func() {
		for name, path := range paths {
			data, err := os.ReadFile(path)
			if err != nil || sha256.Sum256(data) != digests[name] {
				t.Errorf("actual literal oracle input %s changed during object checks: %v", name, err)
			}
		}
	})
	vector, err := x86ScalarLiteralRewriteSet(source)
	if err != nil {
		t.Fatal(err)
	}
	return vector
}

const x86ScalarLiteralZeroRewriteBody = `
if p.From.Type == obj.TYPE_FCONST {
	if f := p.From.Val.(float64); math.Float64bits(f) == 0 {
		if p.To.Type == obj.TYPE_REG && REG_X0 <= p.To.Reg && p.To.Reg <= REG_X15 {
			p.As = AXORPS
			p.From = p.To
			break
		}
	}
}
fallthrough
`

func x86ScalarLiteralRewriteSet(source []byte) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), "actual-obj6.go", source, 0)
	if err != nil {
		return false, err
	}
	var progedit *ast.FuncDecl
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "progedit" {
			continue
		}
		if progedit != nil || function.Body == nil {
			return false, fmt.Errorf("missing or duplicate actual Go progedit body")
		}
		progedit = function
	}
	if progedit == nil {
		return false, fmt.Errorf("actual Go progedit missing")
	}
	known := map[string]bool{"AMOVSS": true, "AMOVSD": true, "AVMOVSS": true, "AVMOVSD": true}
	cases := make(map[string]*ast.CaseClause)
	for _, statement := range progedit.Body.List {
		switchStatement, ok := statement.(*ast.SwitchStmt)
		if !ok || switchStatement.Init != nil {
			continue
		}
		selector, ok := switchStatement.Tag.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "As" {
			continue
		}
		base, ok := selector.X.(*ast.Ident)
		if !ok || base.Name != "p" {
			continue
		}
		for _, statement := range switchStatement.Body.List {
			clause, ok := statement.(*ast.CaseClause)
			if !ok {
				return false, fmt.Errorf("unrecognized progedit switch entry")
			}
			for _, expression := range clause.List {
				name, ok := expression.(*ast.Ident)
				if !ok || !known[name.Name] {
					continue
				}
				if cases[name.Name] != nil {
					return false, fmt.Errorf("duplicate actual Go literal case %s", name.Name)
				}
				cases[name.Name] = clause
			}
		}
	}
	vector := cases["AVMOVSS"] != nil
	if vector != (cases["AVMOVSD"] != nil) {
		return false, fmt.Errorf("partial actual Go V literal rewrite family")
	}
	// A newly nested or conditional registration cannot silently inherit the
	// reviewed top-level cases. Account for every literal case in progedit.
	allCases := make(map[string]int)
	ast.Inspect(progedit.Body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expression := range clause.List {
			name, ok := expression.(*ast.Ident)
			if ok && known[name.Name] {
				allCases[name.Name]++
			}
		}
		return true
	})
	for name := range known {
		want := 0
		if cases[name] != nil {
			want = 1
		}
		if allCases[name] != want {
			return false, fmt.Errorf("unrecognized conditional/nested literal case %s", name)
		}
	}
	for _, legacy := range []string{"AMOVSS", "AMOVSD"} {
		clause := cases[legacy]
		if clause == nil {
			return false, fmt.Errorf("unrecognized actual Go literal case %s", legacy)
		}
		expected := []string{legacy}
		if vector {
			expected = append(expected, "AV"+legacy[1:])
		}
		if len(clause.List) != len(expected) {
			return false, fmt.Errorf("unknown actual Go literal case members %s", legacy)
		}
		for index, expression := range clause.List {
			name, ok := expression.(*ast.Ident)
			if !ok || name.Name != expected[index] || cases[name.Name] != clause {
				return false, fmt.Errorf("unknown actual Go literal case membership %s", legacy)
			}
		}
		actual, err := x86ScalarLiteralBodySyntax(clause.Body)
		if err != nil {
			return false, err
		}
		fixture, err := parser.ParseFile(token.NewFileSet(), "known-rewrite.go", "package p\nfunc progedit() {\n"+x86ScalarLiteralZeroRewriteBody+"}\n", 0)
		if err != nil {
			return false, err
		}
		expectedBody, err := x86ScalarLiteralBodySyntax(fixture.Decls[0].(*ast.FuncDecl).Body.List)
		if err != nil || actual != expectedBody {
			return false, fmt.Errorf("unknown actual Go zero/literal rewrite body %s: %v", legacy, err)
		}
	}
	return vector, nil
}

func x86ScalarLiteralBodySyntax(statements []ast.Stmt) (string, error) {
	var text bytes.Buffer
	err := format.Node(&text, token.NewFileSet(), &ast.BlockStmt{List: statements})
	return text.String(), err
}

func TestX86ScalarLiteralRewriteSourceIsFailClosed(t *testing.T) {
	fixture := func(ss, sd, body string) string {
		return "package x86\nfunc progedit() { switch p.As { case " + ss + ":\n" + body + "case " + sd + ":\n" + body + "} }\n"
	}
	legacy := fixture("AMOVSS", "AMOVSD", x86ScalarLiteralZeroRewriteBody)
	current := fixture("AMOVSS, AVMOVSS", "AMOVSD, AVMOVSD", x86ScalarLiteralZeroRewriteBody)
	for _, test := range []struct {
		name, source  string
		vector, valid bool
	}{
		{name: "legacy", source: legacy, valid: true},
		{name: "current", source: current, vector: true, valid: true},
		{name: "partial", source: fixture("AMOVSS, AVMOVSS", "AMOVSD", x86ScalarLiteralZeroRewriteBody)},
		{name: "wrong family", source: fixture("AMOVSS, AVMOVSD", "AMOVSD, AVMOVSS", x86ScalarLiteralZeroRewriteBody)},
		{name: "extra case", source: fixture("AMOVSS, AVMOVSS, AOTHER", "AMOVSD, AVMOVSD", x86ScalarLiteralZeroRewriteBody)},
		{name: "nonidentifier", source: fixture("AMOVSS, obj.AVMOVSS", "AMOVSD", x86ScalarLiteralZeroRewriteBody)},
		{name: "duplicate function", source: current + strings.TrimPrefix(current, "package x86\n")},
		{name: "duplicate clause", source: strings.Replace(current, "switch p.As {", "switch p.As { case AMOVSS: "+x86ScalarLiteralZeroRewriteBody, 1)},
		{name: "nested registration", source: strings.Replace(current, "switch p.As {", "if condition { switch p.As { case AVMOVSS: break } }; switch p.As {", 1)},
		{name: "wrong function", source: strings.Replace(current, "func progedit", "func other", 1)},
		{name: "wrong switch", source: strings.Replace(current, "switch p.As", "switch q.As", 1)},
		{name: "missing legacy", source: strings.Replace(current, "AMOVSS, AVMOVSS", "AVMOVSS", 1)},
		{name: "negative zero washed", source: strings.Replace(current, "math.Float64bits(f) == 0", "f == 0", 1)},
		{name: "high bank rewrite", source: strings.Replace(current, "REG_X15", "REG_X31", 1)},
		{name: "different zero opcode", source: strings.Replace(current, "AXORPS", "AVXORPS", 1)},
		{name: "missing fallthrough", source: strings.Replace(current, "fallthrough", "break", 1)},
		{name: "malformed", source: "package x86\nfunc progedit( {"},
	} {
		t.Run(test.name, func(t *testing.T) {
			vector, err := x86ScalarLiteralRewriteSet([]byte(test.source))
			if (err == nil) != test.valid || test.valid && vector != test.vector {
				t.Fatalf("rewrite classification vector=%t err=%v, expected vector=%t valid=%t", vector, err, test.vector, test.valid)
			}
		})
	}
}

func TestX86ScalarLiteralActualInventoryCannotSkipHistoricalAssembler(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_scalar_vector_literal_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86ScalarLiteralActualGoRewriteInventory" {
			continue
		}
		found = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if ok && (selector.Sel.Name == "Skip" || selector.Sel.Name == "Skipf" || selector.Sel.Name == "SkipNow") {
				t.Error("actual Go literal inventory must observe historical accepted and rejected source forms, not skip the toolchain")
			}
			return true
		})
	}
	if !found {
		t.Fatal("actual Go inventory consumer missing")
	}
}
