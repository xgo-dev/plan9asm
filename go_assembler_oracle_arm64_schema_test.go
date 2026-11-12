package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmoracle"
)

func arm64OracleOriginalSDKFile(t *testing.T, name string) *ast.File {
	t.Helper()
	path := filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/arm64", name)
	data, valid := goasmoracle.ReadSource(path)
	if !valid {
		t.Fatalf("original bounded SDK source unavailable: %s", name)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	return file
}

// This independently reads the selected SDK's complete namespace and Diag
// argument schema. These are diagnostic roles, not accepted instruction forms.
func TestGoAssemblerOracleARM64ActualSelectedDiagnosticSchema(t *testing.T) {
	var names []string
	ast.Inspect(arm64OracleOriginalSDKFile(t, "anames7.go"), func(node ast.Node) bool {
		declaration, ok := node.(*ast.ValueSpec)
		if !ok || len(declaration.Names) != 1 || declaration.Names[0].Name != "cnames7" {
			return true
		}
		if len(declaration.Values) != 1 {
			t.Fatal("complete original class directory shape changed")
		}
		array, ok := declaration.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("complete original class directory is not a literal")
		}
		seen := make(map[string]bool)
		for _, value := range array.Elts {
			literal, ok := value.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				t.Fatal("original class name is not a literal")
			}
			name, err := strconv.Unquote(literal.Value)
			if err != nil || name != "" && seen[name] {
				t.Fatal("original class name is invalid or duplicated")
			}
			if name != "" {
				seen[name] = true
				names = append(names, name)
			}
		}
		return false
	})
	if len(names) == 0 || names[0] != "NONE" || names[len(names)-1] != "NCLASS" {
		t.Fatal("complete original class bounds absent")
	}

	var slots, formats int
	ast.Inspect(arm64OracleOriginalSDKFile(t, "asm7.go"), func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		method, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || method.Sel.Name != "Diag" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		format, err := strconv.Unquote(literal.Value)
		if err != nil || !strings.HasPrefix(format, "illegal combination: %v %v ") {
			return true
		}
		current := len(call.Args) - 4 // format, Prog, From.Type and To.Type.
		if current != 4 && current != 5 || format != "illegal combination: %v"+strings.Repeat(" %v", current)+", %d %d" {
			t.Fatal("unmodeled original DRconv schema")
		}
		for position := 0; position < current; position++ {
			convert, ok := call.Args[position+2].(*ast.CallExpr)
			if !ok || len(convert.Args) != 1 {
				t.Fatal("original class conversion shape changed")
			}
			function, ok := convert.Fun.(*ast.Ident)
			argument, argOK := convert.Args[0].(*ast.Ident)
			if !ok || !argOK || function.Name != "DRconv" || argument.Name != fmt.Sprintf("a%d", position+1) {
				t.Fatal("original diagnostic class order changed")
			}
		}
		for position, field := range []string{"From", "To"} {
			kind, ok := call.Args[current+2+position].(*ast.SelectorExpr)
			if !ok || kind.Sel.Name != "Type" {
				t.Fatal("original address-type field changed")
			}
			address, ok := kind.X.(*ast.SelectorExpr)
			if !ok || address.Sel.Name != field {
				t.Fatal("original address-type order changed")
			}
			prog, ok := address.X.(*ast.Ident)
			if !ok || prog.Name != "p" {
				t.Fatal("original address-type owner changed")
			}
		}
		slots, formats = current, formats+1
		return false
	})
	if formats != 1 {
		t.Fatal("complete original diagnostic schema is not unique")
	}
	t.Logf("ORIGINAL_ARM64_DIAGNOSTIC_SCHEMA classes=%d slots=%d", len(names), slots)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			source := x86DiagnosticFixture(t, "BL R0")
			for position := 0; position < slots; position++ {
				classes := make([]string, slots)
				for i := range classes {
					classes[i] = "NONE"
				}
				classes[position] = name
				if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
					"CALL R0", strings.Join(classes, " ")+", 0 7")) {
					t.Errorf("complete original class/slot lost: %s/%d", name, position)
				}
			}
		})
	}
}

func TestGoAssemblerOracleARM64HistoricalDiagnosticMetadata(t *testing.T) {
	for _, alias := range []struct{ source, listing string }{{"B", "JMP"}, {"BL", "CALL"}} {
		t.Run(alias.source, func(t *testing.T) {
			source := x86DiagnosticFixture(t, alias.source+" R0")
			for _, class := range []string{"NONE", "REG", "UAUTO32K_8", "LAUTO", "LOREG"} {
				for position := 0; position < 4; position++ {
					classes := []string{"NONE", "NONE", "NONE", "REG"}
					classes[position] = class
					if !goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
						alias.listing+" R0", strings.Join(classes, " ")+", 0 7")) {
						t.Errorf("original four-class metadata lost: %s/%d", class, position)
					}
				}
			}
			for _, tail := range []string{
				"NONE NONE REG, 0 7", "NONE NONE NONE REG NONE NONE, 0 7",
				"NONE NONE UNKNOWN REG, 0 7", "NONE NONE LAUTOPOOL REG, 0 7",
				"NONE NONE LOREGPOOL REG, 0 7", "NONE NONE UAUTO32K_16 REG, 0 7",
				"NONE NONE REG REG, -1 7", "NONE NONE REG REG, 0 15",
				"NONE NONE REG REG, 00 7", "NONE NONE REG REG, 0 7 extra",
			} {
				if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
					alias.listing+" R0", tail)) {
					t.Errorf("unmodeled historical metadata accepted: %q", tail)
				}
			}
		})
	}
}

func TestGoAssemblerOracleARM64TransitionalDiagnosticMetadata(t *testing.T) {
	source := x86DiagnosticFixture(t, "BL R0")
	for _, test := range []struct {
		tail string
		want bool
	}{
		{"NONE NONE NONE UAUTO32K_8 REG, 0 7", true},
		{"LAUTOPOOL LOREGPOOL NONE UAUTO32K_8 REG, 0 7", true},
		{"LAUTOPOOL LOREGPOOL NONE UAUTO32K_16 REG, 0 7", true},
		{"UAUTO32K_8 UAUTO32K_16 NONE NONE REG, 0 7", false},
		{"LAUTOPOOL NONE UAUTO32K_8 REG, 0 7", false},
		{"NONE NONE NONE UAUTO32K_8 REG NONE, 0 7", false},
	} {
		got := goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source, "CALL R0", test.tail))
		if got != test.want {
			t.Errorf("complete producer schema %q: got %t, want %t", test.tail, got, test.want)
		}
	}
}
