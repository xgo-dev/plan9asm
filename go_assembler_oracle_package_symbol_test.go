package plan9asm

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func goAssemblerOracleX86PackageDiagnostic(source, arch, output, packagePrefix string) bool {
	if arch != "386" && arch != "amd64" || packagePrefix == "" {
		return false
	}
	return goasmoracle.SourceDiagnosticLineWithListing(source, output, 0,
		func(original, listing []string) bool {
			if len(original) == 0 {
				return false
			}
			canonical := append([]string(nil), original...)
			if alias, present := goAssemblerOracleX86Aliases[canonical[0]]; present {
				canonical[0] = alias
			}
			return goasmoracle.PackageQualifiedListing(canonical, listing, packagePrefix)
		})
}

func goAssemblerOracleX86ObservedPackageDiagnostic(source, arch, output, packagePrefix string) bool {
	if packagePrefix == "" {
		return false
	}
	if goAssemblerOracleLegacyPackageSymbol() {
		packagePrefix = `""`
	}
	return goAssemblerOracleX86PackageDiagnostic(source, arch, output, packagePrefix)
}

// Historical Go's lexer rewrites the local prefix to "" before parsing,
// independently of -p. Bind that exact selected producer, not a Go-version
// guess or an arbitrary package suffix in an error message.
func goAssemblerOracleLegacyPackageSymbol() bool {
	path := filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/lex/lex.go")
	data, valid := goasmoracle.ReadSource(path)
	if !valid {
		return false
	}
	files := token.NewFileSet()
	actual, err := parser.ParseFile(files, path, data, 0)
	if err != nil {
		return false
	}
	expected, err := parser.ParseFile(files, "expected.go", `package lex
func Make(token ScanToken, text string) Token {
 if token == scanner.Ident && strings.HasPrefix(text, "\u00B7") {
  text = `+"`\"\"`"+` + text
 }
 text = strings.Replace(text, "\u00B7", ".", -1)
 text = strings.Replace(text, "\u2215", "/", -1)
 return Token{ScanToken: token, text: text}
}`, 0)
	if err != nil {
		return false
	}
	// Ignore source positions and parser symbol-table pointers, but retain
	// every AST node, operation and literal byte. Comment layout is not a
	// producer difference; changing a string literal still is.
	semanticField := func(name string, value reflect.Value) bool {
		return name != "Obj" && value.Type() != reflect.TypeOf(token.NoPos)
	}
	var want bytes.Buffer
	if ast.Fprint(&want, nil, expected.Decls[0], semanticField) != nil {
		return false
	}
	matched := 0
	for _, declaration := range actual.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "Make" {
			continue
		}
		var got bytes.Buffer
		if ast.Fprint(&got, nil, function, semanticField) != nil || got.String() != want.String() {
			return false
		}
		matched++
	}
	return matched == 1
}

func TestGoAssemblerOracleX86BoundPackageQualification(t *testing.T) {
	for _, alias := range []string{"MOVD", "MOVDQ2Q"} {
		for _, suffix := range []string{"", "+3", "-1"} {
			source := x86DiagnosticFixture(t, alias+" $·value"+suffix+"(SB),AX")
			listing := "MOVQ $example.com/forms.value" + suffix + "(SB),AX"
			output := x86DiagnosticListing(source, listing)
			if !goAssemblerOracleX86PackageDiagnostic(source, "386", output, "example.com/forms") {
				t.Fatal("exact source/command package qualification lost")
			}
			for _, changed := range []string{
				"MOVQ $other.example/forms.value" + suffix + "(SB),AX",
				"MOVQ $example.com/forms.other" + suffix + "(SB),AX",
				"MOVQ $example.com/forms.value+9(SB),AX",
				"MOVQ $example.com/forms.value" + suffix + "(SB),BX",
				"MOVQ $example.com/forms.value" + suffix + "(SB)",
				"MOVL $example.com/forms.value" + suffix + "(SB),AX",
			} {
				if goAssemblerOracleX86PackageDiagnostic(source, "386", x86DiagnosticListing(source, changed), "example.com/forms") {
					t.Fatal("changed complete listing acquired package role", changed)
				}
			}
			if goAssemblerOracleX86PackageDiagnostic(source, "386", output, "") ||
				goAssemblerOracleX86PackageDiagnostic(source, "arm64", output, "example.com/forms") {
				t.Fatal("missing command package or foreign architecture borrowed qualification")
			}
		}
	}
}
