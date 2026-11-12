package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestX86PackedStringFaultRequiredNativeOwner(t *testing.T) {
	source, err := os.ReadFile("amd64_packed_string_fault_linux_amd64_test.go")
	if err != nil {
		t.Fatal("complete original-Go/LLVM packed-string fault owner absent", err)
	}
	if err := x86PackedStringFaultNativePolicy(source); err != nil {
		t.Fatal(err)
	}
}

type x86PackedStringFaultCase struct {
	op         string
	zero, dead bool
}

// Independent source axes, not the production descriptor or a shortened SDK
// function. Each original spelling retains both live/dead and empty/full cases.
func x86PackedStringFaultCases() []x86PackedStringFaultCase {
	var cases []x86PackedStringFaultCase
	for _, op := range []string{"PCMPESTRI", "PCMPESTRM", "PCMPISTRI", "PCMPISTRM",
		"VPCMPESTRI", "VPCMPESTRM", "VPCMPISTRI", "VPCMPISTRM"} {
		for _, zero := range []bool{false, true} {
			for _, dead := range []bool{false, true} {
				cases = append(cases, x86PackedStringFaultCase{op, zero, dead})
			}
		}
	}
	return cases
}

func x86PackedStringFaultBody(row x86PackedStringFaultCase) string {
	body := "PXOR X1,X1\n"
	if !row.zero {
		body += "PCMPEQB X1,X1\n"
	}
	if strings.Contains(row.op, "E") {
		length := 16
		if row.zero {
			length = 0
		}
		body += fmt.Sprintf("MOVL $%d,AX\nMOVL $%d,DX\n", length, length)
	}
	body += row.op + " $12,(DI),X1\n"
	if row.dead {
		body += "MOVL $7,AX\n"
	} else if strings.HasSuffix(row.op, "M") {
		body += "MOVL X0,AX\n"
	} else {
		body += "MOVL CX,AX\n"
	}
	return body
}

func x86PackedStringFaultFixture(cases []x86PackedStringFaultCase, arch string) (string, string) {
	move, word := "MOVQ", 8
	if arch == "386" {
		move, word = "MOVL", 4
	}
	var source, declarations strings.Builder
	for index, row := range cases {
		name := fmt.Sprintf("stringfault%d", index)
		fmt.Fprintf(&declarations, "func %s(p *byte) uint32\n", name)
		fmt.Fprintf(&source, "TEXT ·%s(SB),4,$0-%d\n%s p+0(FP),DI\n%sMOVL AX,ret+%d(FP)\nRET\n",
			name, word+4, move, x86PackedStringFaultBody(row), word)
	}
	return source.String(), declarations.String()
}

func TestX86PackedStringFaultCompleteSourceReadBeforeDeadResults(t *testing.T) {
	cases := x86PackedStringFaultCases()
	if len(cases) != 32 {
		t.Fatal("eight complete spellings require independent empty/full and live/dead cases")
	}
	for _, arch := range []string{"amd64", "386"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		source, declarations := x86PackedStringFaultFixture(cases, arch)
		for _, api := range []string{"text", "module", "Go"} {
			t.Run(arch+"/"+api, func(t *testing.T) {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, optimized := range []bool{false, true} {
					text := ir
					if optimized {
						text = x86UndefinedTrapOptimizedIR(t, ir)
					}
					if strings.Count(text, "load volatile <16 x i8>") != len(cases) ||
						strings.Count(text, "define ") != len(cases) {
						t.Fatal("empty lengths, EOS or dead results erased a complete observable m128 read", optimized)
					}
				}
			})
		}
	}
}

func TestX86PackedStringFaultReadOracleRejectsLostVolatility(t *testing.T) {
	source, declarations := x86PackedStringFaultFixture(x86PackedStringFaultCases(), "amd64")
	ir, err := x86ScalarFPBitViewAPI(t, source, declarations, "amd64", "x86_64-unknown-linux-gnu", "Go")
	if err != nil {
		t.Fatal(err)
	}
	mutation := strings.ReplaceAll(ir, "load volatile <16 x i8>", "load <16 x i8>")
	if mutation == ir || strings.Count(x86UndefinedTrapOptimizedIR(t, mutation), "load <16 x i8>") == 32 {
		t.Fatal("read oracle cannot detect historical dead/zero-length nonvolatile access loss")
	}
}

func x86PackedStringFaultMainSource(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "amd64_packed_string_fault_runtime_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var source string
	ast.Inspect(file, func(node ast.Node) bool {
		value, ok := node.(*ast.ValueSpec)
		if !ok || len(value.Names) != 1 || value.Names[0].Name != "x86PackedStringFaultMainC" || len(value.Values) != 1 {
			return true
		}
		literal, ok := value.Values[0].(*ast.BasicLit)
		if !ok {
			t.Fatal("fault observer must retain its complete registered C template")
		}
		source, err = strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatal(err)
		}
		return false
	})
	if source == "" {
		t.Fatal("actual fault observer template absent")
	}
	return source
}

// This checks the fixed, registered test template, not arbitrary C programs.
// Primary failure must precede any reference call or success/canary receipt.
func x86PackedStringFaultObserverPolicy(source string) error {
	previous := -1
	for _, component := range []string{
		"printf(\"memory enter %u %u %u\\n\",row,probe,original);",
		"uint32_t value = original ? kernel->original(input) : kernel->translated(input);",
		"if (probe == 0 || probe == 1 || probe >= 19) return 93;",
		"if (value != kernel->original(input) || (kernel->dead && value != 7)) return 91;",
		"if (guard[i] != fill) return 92;",
		"if (free_guard()) return 84;",
		"puts(\"memory complete\");",
	} {
		position := strings.Index(source, component)
		if position <= previous || strings.Count(source, component) != 1 {
			return fmt.Errorf("primary fault, independent reference and completion order changed")
		}
		previous = position
	}
	return nil
}

func TestX86PackedStringFaultObserverCannotBorrowReferenceFault(t *testing.T) {
	source := x86PackedStringFaultMainSource(t)
	if err := x86PackedStringFaultObserverPolicy(source); err != nil {
		t.Fatal(err)
	}
	const guard = "if (probe == 0 || probe == 1 || probe >= 19) return 93;"
	const reference = "if (value != kernel->original(input) || (kernel->dead && value != 7)) return 91;"
	for name, mutation := range map[string]string{
		"no primary failure":       strings.Replace(source, guard, "", 1),
		"reference supplies fault": strings.Replace(strings.Replace(source, guard, "", 1), reference, reference+"\n"+guard, 1),
		"NULL lost":                strings.Replace(source, guard, "if (probe == 1 || probe >= 19) return 93;", 1),
		"tail lost":                strings.Replace(source, guard, "if (probe == 0 || probe >= 19) return 93;", 1),
		"partial matrix lost":      strings.Replace(source, guard, "if (probe == 0 || probe == 1) return 93;", 1),
		"success on missing read":  strings.Replace(source, guard, strings.Replace(guard, "93", "0", 1), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if mutation == source || x86PackedStringFaultObserverPolicy(mutation) == nil {
				t.Fatal("missing primary access could borrow a reference fault")
			}
		})
	}
}

func TestX86PackedStringFaultCompleteFiveTargetOriginalGoAndLLVMObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("complete packed-string fault objects require LLVM22")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			source, declarations := x86PackedStringFaultFixture(x86PackedStringFaultCases(), target.arch)
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source)
			for _, api := range []string{"text", "module", "Go"} {
				ir, err := x86ScalarFPBitViewAPI(t, source, declarations, target.arch, target.triple, api)
				if err != nil {
					t.Fatal(err)
				}
				for _, level := range []string{"-O0", "-O2"} {
					input := ir
					if level == "-O2" {
						input = x86UndefinedTrapOptimizedIR(t, input)
					}
					x86PackedStringCompileObject(t, llc, target.triple, input, level)
				}
			}
		})
	}
}

func x86PackedStringFaultNativePolicy(source []byte) error {
	source = normalizeNativeOwnerPolicySource(source)
	if !strings.HasPrefix(string(source), "//go:build linux && amd64\n") {
		return fmt.Errorf("packed-string faults need the required native Linux/AMD64 owner")
	}
	file, err := parser.ParseFile(token.NewFileSet(), "native.go", source, 0)
	if err != nil {
		return err
	}
	roots := 0
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "TestCrossLinuxRuntimeMatrixX86PackedStringOriginalNativeMemoryFaults" {
			continue
		}
		roots++
		var gates []token.Pos
		var run token.Pos
		runs := 0
		top := map[*ast.CallExpr]bool{}
		for _, statement := range fn.Body.List {
			if expr, ok := statement.(*ast.ExprStmt); ok {
				if call, ok := expr.X.(*ast.CallExpr); ok {
					top[call] = true
				}
			}
		}
		var failure error
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.CallExpr:
				if selector, ok := node.Fun.(*ast.SelectorExpr); ok && strings.HasPrefix(selector.Sel.Name, "Skip") {
					failure = fmt.Errorf("required execution cannot skip")
				}
				if name, ok := node.Fun.(*ast.Ident); ok {
					if name.Name == "x87IA32RequireNativeHost" {
						gates = append(gates, node.Pos())
						if !top[node] {
							failure = fmt.Errorf("native gate must be unconditional")
						}
					}
					if name.Name == "x86PackedStringRunMemoryFaults" {
						runs++
						run = node.Pos()
						if !top[node] || len(node.Args) != 3 {
							failure = fmt.Errorf("whole fault execution must be unconditional")
						} else if value, ok := node.Args[2].(*ast.Ident); !ok || value.Name != "true" {
							failure = fmt.Errorf("all original native spellings must execute")
						}
					}
				}
			case *ast.KeyValueExpr:
				if name, ok := node.Key.(*ast.Ident); ok && (name.Name == "prefix" || name.Name == "preserveArgv0") {
					failure = fmt.Errorf("required native execution cannot use a guest prefix")
				}
			case *ast.ReturnStmt:
				failure = fmt.Errorf("native owner cannot return early")
			}
			return true
		})
		if failure != nil {
			return failure
		}
		if len(gates) != 2 || runs != 1 || !(gates[0] < run && run < gates[1]) {
			return fmt.Errorf("native observations must surround exactly one complete execution")
		}
	}
	if roots != 1 {
		return fmt.Errorf("native root missing or duplicated")
	}
	return nil
}

func x86PackedStringFaultNativeMutations(text string) map[string]string {
	const run = "\tx86PackedStringRunMemoryFaults(t, execution, true)"
	const gate = "\tx87IA32RequireNativeHost(t)"
	return map[string]string{
		"missing after":   strings.Replace(text, run+"\n"+gate, run, 1),
		"both before":     strings.Replace(text, run+"\n"+gate, gate+"\n"+run, 1),
		"conditional run": strings.Replace(text, run, "\tif false {\n"+run+"\n\t}", 1),
		"skip":            strings.Replace(text, run, "\tt.Skip(\"tool\")\n"+run, 1),
		"early return":    strings.Replace(text, run, "\treturn\n"+run, 1),
		"guest prefix":    strings.Replace(text, "{llc: llc,", "{prefix: []string{\"guest\"}, llc: llc,", 1),
		"legacy only":     strings.Replace(text, run, strings.Replace(run, "true", "false", 1), 1),
		"wrong host":      strings.Replace(text, "linux && amd64", "darwin && amd64", 1),
		"missing root":    strings.Replace(text, "TestCrossLinuxRuntimeMatrixX86PackedStringOriginalNativeMemoryFaults", "NoNativeOwner", 1),
	}
}

func TestX86PackedStringFaultNativePolicyRejectsMutation(t *testing.T) {
	source, err := os.ReadFile("amd64_packed_string_fault_linux_amd64_test.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(normalizeNativeOwnerPolicySource(source))
	for name, mutation := range x86PackedStringFaultNativeMutations(text) {
		t.Run(name, func(t *testing.T) {
			if mutation == text || x86PackedStringFaultNativePolicy([]byte(mutation)) == nil {
				t.Fatal("native lifecycle mutation not rejected")
			}
		})
	}
}
