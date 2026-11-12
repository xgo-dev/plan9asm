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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func TestGoAssemblerOracleX86Mode32CompleteActualClassDirectory(t *testing.T) {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/x86/asm6.go")
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, declaration := range file.Decls {
		group, ok := declaration.(*ast.GenDecl)
		if !ok || group.Tok != token.CONST || len(group.Specs) == 0 {
			continue
		}
		first := group.Specs[0].(*ast.ValueSpec)
		if len(first.Names) != 1 || first.Names[0].Name != "Yxxx" {
			continue
		}
		if len(first.Values) != 1 {
			t.Fatal("original operand-class initializer changed")
		}
		initial, ok := first.Values[0].(*ast.Ident)
		if !ok || initial.Name != "iota" {
			t.Fatal("original operand-class ordinal rule changed")
		}
		for index, raw := range group.Specs {
			entry := raw.(*ast.ValueSpec)
			if len(entry.Names) != 1 || index > 0 && len(entry.Values) != 0 {
				t.Fatal("original operand-class ordinal overridden")
			}
			names = append(names, entry.Names[0].Name)
		}
	}
	if len(names) != 91 || names[len(names)-1] != "Ymax" || names[len(names)-2] != "Yindir" {
		t.Fatalf("complete actual operand-class directory changed: %v", names)
	}
}

func TestGoAssemblerOracleActualX86Mode32ClassTails(t *testing.T) {
	for _, test := range []struct{ name, instruction string }{
		{"alias-high-destination", "PADDD X0,X8"},
		{"alias-high-source", "PADDD X8,X0"},
		{"alias-high-address", "PADDD 8(R9),X0"},
		{"scalar-single", "MOVSS $0.0,X8"},
		{"scalar-double", "MOVSD $0.0,X8"},
		{"vector-single", "VMOVSS $0.0,X8"},
		{"vector-double", "VMOVSD $0.0,X8"},
	} {
		t.Run(test.name, func(t *testing.T) {
			source := x86DiagnosticFixture(t, test.instruction)
			object := filepath.Join(filepath.Dir(source), "forms.o")
			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, time.Minute)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, filepath.Dir(source),
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=386"),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil ||
				!strings.Contains(string(observed.Stderr), "asmins: illegal in mode 32:") {
				t.Fatalf("actual mode-32 source refusal absent: %+v %v", observed, err)
			}
			additional := func(source, output string) bool {
				return goAssemblerOracleX86SourceDiagnostic(source, "386", output)
			}
			if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
				err, ctx.Err(), false, 2, additional); failure != nil {
				t.Fatalf("actual original class-tail refusal lost: %v\n%s", failure, observed.Stderr)
			}
		})
	}
}
