package plan9asm

import (
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestRuntimeOracleCommandAuditDistinguishesTestingRun(t *testing.T) {
	for _, row := range []struct {
		name    string
		imports string
		source  string
		unowned []string
	}{
		{"test", `"testing"`, `func f(t *testing.T) { t.Run("x", func(t *testing.T) {}) }`, nil},
		{"benchmark", `"testing"`, `func f(b *testing.B) { b.Run("x", func(b *testing.B) {}) }`, nil},
		{"renamed_test", `"testing"`, `func f(subject *testing.T) { subject.Run("x", func(t *testing.T) {}) }`, nil},
		{"renamed_benchmark", `"testing"`, `func f(bench *testing.B) { bench.Run("x", func(b *testing.B) {}) }`, nil},
		{"import_alias", `unit "testing"`, `func f(bench *unit.B) { bench.Run("x", func(b *unit.B) {}) }`, nil},
		{"nested_benchmark", `"testing"`, `func f(b *testing.B) { b.Run("x", func(nested *testing.B) { nested.Run("y", func(b *testing.B) {}) }) }`, nil},
		{"parenthesized_test", `"testing"`, `func f(t *testing.T) { (t).Run("x", func(t *testing.T) {}) }`, nil},
		{"command_named_test", `"os/exec"`, `func f(t *exec.Cmd) { t.Run() }`, []string{"Run"}},
		{"command_named_benchmark", `"os/exec"`, `func f(b *exec.Cmd) { b.Run() }`, []string{"Run"}},
		{"command_methods", `"os/exec"`, `func f(t *exec.Cmd) { t.Output(); t.CombinedOutput(); t.Start() }`, []string{"Output", "CombinedOutput", "Start"}},
		{"shadow_test", `"testing"; "os/exec"`, `func f(t *testing.T) { { t := exec.Command("x"); t.Run() } }`, []string{"Run"}},
		{"shadow_benchmark", `"testing"; "os/exec"`, `func f(b *testing.B) { { b := exec.Command("x"); b.Run() } }`, []string{"Run"}},
		{"command_type_alias", `"os/exec"`, `type B = exec.Cmd; func f(t *B) { t.Run() }`, []string{"Run"}},
		{"other_testing_package", `testing "example.invalid/testing"`, `func f(t *testing.T) { t.Run() }`, []string{"Run"}},
		{"local_testing_name", `"os/exec"`, `func f() { testing := struct{ B *exec.Cmd }{exec.Command("x")}; testing.B.Run() }`, []string{"Run"}},
		{"command_expression", `"os/exec"`, `func f() { exec.Command("x").Run() }`, []string{"Run"}},
	} {
		t.Run(row.name, func(t *testing.T) {
			source := "package oracle\nimport (" + row.imports + ")\n" + row.source + "\nfunc owned() { runtimeOracleCombinedOutput(nil, nil) }"
			file, err := parser.ParseFile(token.NewFileSet(), "oracle_test.go", source, 0)
			if err != nil {
				t.Fatal(err)
			}
			consumers, unowned := runtimeOracleCommandConsumers(file)
			if consumers != 1 || !reflect.DeepEqual(unowned, row.unowned) {
				t.Fatalf("consumers=%d, unowned=%v; want 1, %v", consumers, unowned, row.unowned)
			}
		})
	}
}
