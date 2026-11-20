//go:build go1.27

package plan9asm

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86AliasTableCompleteActualSDK(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src", "cmd", "asm", "internal", "arch", "arch.go")
	data, ok := goasmoracle.ReadSource(path)
	if !ok {
		t.Fatal("complete original Go alias source unavailable")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Name.Name == "archX86" {
			if body != nil {
				t.Fatal("duplicate original archX86 declaration")
			}
			body = function.Body
		}
	}
	if body == nil {
		t.Fatal("original archX86 declaration absent")
	}
	aliases, identities := make(map[string]string), make(map[string]string)
	ast.Inspect(body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		index, ok := assignment.Lhs[0].(*ast.IndexExpr)
		if !ok {
			return true
		}
		mapName, ok := index.X.(*ast.Ident)
		key, literal := index.Index.(*ast.BasicLit)
		if !ok || mapName.Name != "instructions" || !literal || key.Kind != token.STRING {
			return true
		}
		value, ok := assignment.Rhs[0].(*ast.SelectorExpr)
		if !ok {
			t.Fatalf("unmodeled original explicit alias assignment: %#v", assignment)
		}
		owner, ok := value.X.(*ast.Ident)
		name, err := strconv.Unquote(key.Value)
		if !ok || owner.Name != "x86" || err != nil || !strings.HasPrefix(value.Sel.Name, "A") {
			t.Fatal("unmodeled original alias identity")
		}
		canonical := strings.TrimPrefix(value.Sel.Name, "A")
		if _, duplicate := aliases[name]; duplicate {
			t.Fatal("duplicate original nonidentity alias")
		}
		if _, duplicate := identities[name]; duplicate {
			t.Fatal("duplicate original identity alias")
		}
		if name == canonical {
			identities[name] = canonical
		} else {
			aliases[name] = canonical
		}
		return true
	})
	wantIdentity := map[string]string{}
	for _, name := range []string{"JCC", "JCS", "JEQ", "JGE", "JGT", "JHI", "JLE", "JLS", "JLT", "JMI", "JNE", "JOC", "JOS", "JPC", "JPL", "JPS"} {
		wantIdentity[name] = name
	}
	if !reflect.DeepEqual(aliases, goAssemblerOracleX86Aliases) || !reflect.DeepEqual(identities, wantIdentity) {
		t.Fatalf("complete original 40 nonidentity/16 identity aliases differ: %v / %v", aliases, identities)
	}
}

func TestGoAssemblerOracleActualX86ScalarZeroListingFamily(t *testing.T) {
	for _, arch := range []string{"amd64", "386"} {
		for _, opcode := range []string{"MOVSS", "MOVSD", "VMOVSS", "VMOVSD"} {
			for _, test := range []struct{ name, operand string }{
				{"zero", "$0.0,X0"},
				{"negative-zero", "$-0.0,X0"},
				{"mask-zero", "$0.0,K1,X0"},
				{"unary-zero", "$+(-( -0.0)),K1,X0"},
			} {
				t.Run(arch+"_"+opcode+"_"+test.name, func(t *testing.T) {
					source := x86DiagnosticFixture(t, opcode+" "+test.operand)
					object := filepath.Join(filepath.Dir(source), "forms.o")
					stage, cancelStage := runtimeOracleStageContext(t)
					defer cancelStage()
					ctx, cancel := context.WithTimeout(stage, time.Minute)
					defer cancel()
					observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
						append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH="+arch),
						"go", "tool", "asm", "-S", "-o", object, source)
					encoded, encodeErr := json.Marshal(observed)
					if encodeErr != nil {
						t.Fatal(encodeErr)
					}
					t.Logf("ORACLE_CHILD %s", encoded)
					accepted := test.name == "zero" || test.name == "negative-zero"
					if !observed.Waited || observed.ExitCode != map[bool]int{true: 0, false: 1}[accepted] {
						t.Fatalf("actual scalar outcome differs: %+v %v", observed, err)
					}
					additional := func(source, output string) bool {
						return goAssemblerOracleX86SourceDiagnostic(source, arch, output)
					}
					if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
						err, ctx.Err(), accepted, 2, additional); failure != nil {
						t.Fatalf("actual complete scalar observation lost: %v\n%s\n%s", failure, observed.Stdout, observed.Stderr)
					}
					if test.name != "negative-zero" && !strings.Contains(string(observed.Stdout)+string(observed.Stderr), "XORPS") {
						t.Fatal("actual Go positive-zero rewrite absent")
					}
					if test.name == "negative-zero" && strings.Contains(string(observed.Stdout)+string(observed.Stderr), "XORPS") {
						t.Fatal("actual Go negative zero borrowed the positive-zero rewrite")
					}
				})
			}
		}
	}
}
