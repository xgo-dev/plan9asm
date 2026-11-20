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

func TestGoAssemblerOracleARM64SelectedRegisterNamespace(t *testing.T) {
	expected := map[string]bool{"RSP": true, "ZR": true, "LR": true, "R18_PLATFORM": true,
		"g": true, "SB": true, "FP": true, "PC": true, "SP": true}
	for number := 0; number < 32; number++ {
		if number < 31 && number != 18 && number != 28 {
			expected["R"+strconv.Itoa(number)] = true
		}
		expected["F"+strconv.Itoa(number)] = true
		expected["V"+strconv.Itoa(number)] = true
	}
	path := filepath.Join(runtime.GOROOT(), "src/cmd/asm/internal/arch/arch.go")
	data, valid := goasmoracle.ReadSource(path)
	if !valid {
		t.Fatal("original selected arch namespace unavailable")
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "archArm64" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || len(assignment.Lhs) != 1 || arm64OracleASTText(assignment.Lhs[0]) != "registerPrefix" {
				return true
			}
			literal := assignment.Rhs[0].(*ast.CompositeLit)
			for _, element := range literal.Elts {
				pair := element.(*ast.KeyValueExpr)
				prefix, err := strconv.Unquote(pair.Key.(*ast.BasicLit).Value)
				if err != nil {
					t.Fatal(err)
				}
				maximum := 0
				switch prefix {
				case "Z":
					maximum = 32
				case "P", "PN":
					maximum = 16
				case "F", "R", "V":
				default:
					t.Fatalf("unmodeled original namespace bank %s", prefix)
				}
				for number := 0; number < maximum; number++ {
					expected[prefix+strconv.Itoa(number)] = true
				}
			}
			return false
		})
	}
	ast.Inspect(arm64OracleOriginalSDKFile(t, "sysRegEnc.go"), func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "SystemReg" {
			return true
		}
		for _, element := range value.Values[0].(*ast.CompositeLit).Elts {
			name, err := strconv.Unquote(element.(*ast.CompositeLit).Elts[0].(*ast.BasicLit).Value)
			if err != nil || expected[name] {
				t.Fatal("duplicate or malformed original system-register name")
			}
			expected[name] = true
		}
		return false
	})
	arm64OracleLoadLexicalNames()
	if !reflect.DeepEqual(expected, arm64OracleLexicalNames.registers) {
		t.Fatalf("complete actual cmd/asm namespace differs: %v / %v", expected, arm64OracleLexicalNames.registers)
	}
	for name := range expected {
		if goAssemblerOracleARM64BareSymbol(name) {
			t.Fatalf("registered name %s borrowed bare symbol formatting", name)
		}
	}
}

func TestGoAssemblerOracleARM64SelectedSpecialNamespace(t *testing.T) {
	file := arm64OracleOriginalSDKFile(t, "specialoperand_string.go")
	var names string
	var offsets []int
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || len(value.Values) != 1 {
			return true
		}
		switch value.Names[0].Name {
		case "_SpecialOperand_name":
			literal, ok := value.Values[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || names != "" {
				t.Fatal("original complete special string directory changed")
			}
			var err error
			names, err = strconv.Unquote(literal.Value)
			if err != nil {
				t.Fatal(err)
			}
		case "_SpecialOperand_index":
			array, ok := value.Values[0].(*ast.CompositeLit)
			if !ok || len(offsets) != 0 {
				t.Fatal("original complete special index directory changed")
			}
			for _, element := range array.Elts {
				literal, ok := element.(*ast.BasicLit)
				if !ok || literal.Kind != token.INT {
					t.Fatal("original special index is not a literal")
				}
				offset, err := strconv.Atoi(literal.Value)
				if err != nil || len(offsets) > 0 && offset <= offsets[len(offsets)-1] {
					t.Fatal("original special index is not increasing")
				}
				offsets = append(offsets, offset)
			}
		}
		return false
	})
	if len(offsets) < 3 || offsets[0] != 0 || offsets[len(offsets)-1] != len(names) ||
		names[offsets[len(offsets)-2]:] != "END" {
		t.Fatal("complete original special directory bounds absent")
	}
	arm64OracleLoadLexicalNames()
	expected := make(map[string]bool)
	for name := range arm64OracleLexicalNames.registers {
		expected[name] = true
	}
	expected["CS"], expected["CC"] = true, true
	for index := 0; index < len(offsets)-2; index++ {
		name := names[offsets[index]:offsets[index+1]]
		if expected[name] {
			t.Fatal("duplicate original lexical name")
		}
		expected[name] = true
		t.Run(name, func(t *testing.T) {
			source := x86DiagnosticFixture(t, "BL "+name+",R1")
			if goAssemblerOracleARM64SourceDiagnostic(source, "arm64", arm64BranchDiagnostic(source,
				"CALL 0,R1", "ZOREG NONE NONE REG NONE, 3 7")) {
				t.Fatal("actual special name borrowed bare symbol formatting")
			}
		})
	}
	if !reflect.DeepEqual(expected, arm64OracleLexicalNames.reserved) {
		t.Fatalf("complete original special namespace differs: %v / %v", expected, arm64OracleLexicalNames.reserved)
	}
}

func TestGoAssemblerOracleARM64SelectedBareSpellingsActual(t *testing.T) {
	for _, name := range []string{"R18", "R28", "R31", "BEGIN", "END", "F", "Z0", "P0", "PN0"} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			source := filepath.Join(directory, "forms.s")
			object := filepath.Join(directory, "forms.o")
			if err := os.WriteFile(source, []byte("TEXT bad(SB),$0-0\n\tBL "+name+",R1\n\tRET\n"), 0600); err != nil {
				t.Fatal(err)
			}
			stage, cancelStage := runtimeOracleStageContext(t)
			defer cancelStage()
			ctx, cancel := context.WithTimeout(stage, 5*time.Second)
			defer cancel()
			observed, err := goasmcmd.Observe(ctx, directory,
				append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64"),
				"go", "tool", "asm", "-o", object, source)
			encoded, encodeErr := json.Marshal(observed)
			if encodeErr != nil {
				t.Fatal(encodeErr)
			}
			t.Logf("ORACLE_CHILD %s", encoded)
			if !observed.Waited || observed.ExitCode != 1 || ctx.Err() != nil || len(observed.Stdout) != 0 {
				t.Fatalf("actual source kind oracle failed: %+v %v", observed, err)
			}
			bare := strings.Contains(string(observed.Stderr), source+":2)\tCALL\t0, R1 ZOREG NONE NONE REG") &&
				strings.Contains(string(observed.Stderr), ", 3 7\n")
			if bare != goAssemblerOracleARM64BareSymbol(name) {
				t.Fatalf("selected original operand role differs for %s:\n%s", name, observed.Stderr)
			}
			if failure := goasmoracle.CheckOutcome(source, object, observed.Stdout, observed.Stderr,
				err, ctx.Err(), false, 2, func(source, diagnostic string) bool {
					return goAssemblerOracleARM64SourceDiagnostic(source, "arm64", diagnostic)
				}); failure != nil {
				t.Fatalf("actual namespace diagnostic join lost: %v\n%s", failure, observed.Stderr)
			}
		})
	}
}
