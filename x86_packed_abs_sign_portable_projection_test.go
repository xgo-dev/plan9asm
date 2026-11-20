package plan9asm

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// This private mathematical driver accepts only the complete generated kernels,
// including every original input/output/FLAGS transport. It removes ISA choices,
// never operations. The separate original-native/alignment owners are unchanged.
func x86PackedAbsSignPortableIR(source, ir, arch string) (string, error) {
	if arch != "386" && arch != "amd64" {
		return "", fmt.Errorf("portable ABS/sign source has an unknown x86 mode")
	}
	file, err := Parse(ArchAMD64, source)
	if err != nil || len(file.Funcs) == 0 {
		return "", fmt.Errorf("portable ABS/sign source has no complete kernels: %v", err)
	}
	rows := x86PackedAbsSignOracleRows()
	profiles := make(map[string]string)
	var expected strings.Builder
	for _, function := range file.Funcs {
		name := strings.TrimPrefix(function.Sym, "·")
		index, err := strconv.Atoi(strings.TrimPrefix(name, "AbsSign"))
		if err != nil || index < 0 || index >= len(rows) || name != fmt.Sprint("AbsSign", index) {
			return "", fmt.Errorf("portable ABS/sign source has an unobserved kernel: %s", name)
		}
		if _, duplicate := profiles[name]; duplicate {
			return "", fmt.Errorf("portable ABS/sign source repeats a kernel: %s", name)
		}
		row := rows[index]
		body, _ := x86PackedAbsSignInitializedSource(index, row, arch)
		if row.legacy && row.memory {
			base := "AX"
			if row.sign {
				base = "BX"
			}
			// These fixtures use only banks 0..2. Their existing, independently
			// checked legacy-memory instrumentation selects unused X3 exactly.
			replacement := fmt.Sprintf("VMOVDQU 0(%s),X3\n%s X3,X2", base, row.op)
			body = strings.Replace(body, row.instruction(), replacement, 1)
		}
		expected.WriteString(body)
		profiles[name] = inferFuncTargetFeaturesForGOARCH(ArchAMD64, arch, function)
	}
	if source != expected.String() {
		return "", fmt.Errorf("portable ABS/sign source changed its complete mathematical/transport effects")
	}
	// Reuse the existing exact group/reference and inert-declaration observer.
	// It rejects actual native calls/assembly instead of deleting their effects.
	return x86PackedShiftPortableFeatureProjection(ir, profiles)
}

func x86PackedAbsSignPortableFixture(t *testing.T, start, end int, arch string) (string, string) {
	t.Helper()
	rows := x86PackedAbsSignOracleRows()
	var source, declarations strings.Builder
	legacyMemory := 0
	for index := start; index < end; index++ {
		body, declaration := x86PackedAbsSignInitializedSource(index, rows[index], arch)
		source.WriteString(body)
		declarations.WriteString(declaration)
		if rows[index].legacy && rows[index].memory {
			legacyMemory++
		}
	}
	instrumented := x86PackedAbsSignPortableMemoryInstrumentation(t, source.String(), legacyMemory)
	return instrumented, declarations.String()
}

func TestX86PackedAbsSignPortableProjectionCompletePrograms(t *testing.T) {
	x86PackedAbsSignOriginalProgramUnchanged(t)
	rows, members := x86PackedAbsSignOracleRows(), make(map[string]bool)
	for _, row := range rows {
		members[row.op] = true
	}
	if len(rows) != 114 || len(members) != 13 {
		t.Fatal("independent ABS/sign mathematical denominator changed", len(rows), len(members))
	}
	for _, arch := range []string{"386", "amd64"} {
		for start := 0; start < len(rows); start += 48 {
			end := start + 48
			if end > len(rows) {
				end = len(rows)
			}
			t.Run(fmt.Sprintf("%s/%d-%d", arch, start, end), func(t *testing.T) {
				source, declarations := x86PackedAbsSignPortableFixture(t, start, end, arch)
				triple := "x86_64-pc-windows-msvc"
				if arch == "386" {
					triple = "i686-pc-windows-msvc"
				}
				x86LEAActualTargetGoObject(t, arch, triple, source)
				for _, api := range []string{"text", "module", "Go"} {
					t.Run(api, func(t *testing.T) {
						ir, err := x86ScalarFPBitViewAPI(t, source, declarations, arch, triple, api)
						if err != nil || !strings.Contains(ir, `"target-features"=`) {
							t.Fatal("actual initialized x86 IR lost its independent rare-ISA prerequisite", err)
						}
						projected, err := x86PackedAbsSignPortableIR(source, ir, arch)
						if err != nil || projected == "" || strings.Contains(projected, "target-features") {
							t.Fatal("actual-host mathematics still selects the original rare x86 ISA", err)
						}
						// Independently permit only complete feature-group lines and
						// their definition-header references to change. All memory,
						// arithmetic, constants, declarations and generic attrs stay.
						groups := regexp.MustCompile(`(?m)^attributes (#[0-9]+) = \{ "target-features"="[^"]+" \}\r?\n`)
						want := groups.ReplaceAllString(ir, "")
						for _, group := range groups.FindAllStringSubmatch(ir, -1) {
							headers := regexp.MustCompile(`(?m)^(define [^\r\n]*) ` + regexp.QuoteMeta(group[1]) + ` \{`)
							want = headers.ReplaceAllString(want, "${1} {")
						}
						if projected != want {
							t.Fatal("portable projection changed more than its exact owned ISA selection")
						}
					})
				}
			})
		}
	}
}

func TestX86PackedAbsSignPortableProjectionRejectsForeignSourceAndIR(t *testing.T) {
	source, declaration := x86PackedAbsSignPortableFixture(t, 1, 2, "amd64")
	ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", "x86_64-pc-windows-msvc", "Go")
	if err != nil {
		t.Fatal("complete initialized legacy mathematical prerequisite failed", err)
	}
	header := regexp.MustCompile(`(?m)^define [^\r\n]*\{`).FindString(ir)
	group := regexp.MustCompile(`(?m)^attributes (#[0-9]+) = \{ "target-features"="([^"]+)" \}\r?\n`).FindStringSubmatch(ir)
	if header == "" || len(group) != 3 {
		t.Fatal("actual production IR has no unique observed definition/ISA group")
	}
	inBody := func(line string) string { return strings.Replace(ir, header, header+"\n  "+line, 1) }
	for name, changed := range map[string]string{
		"unknown-body-operation":  strings.Replace(source, "\nRET", "\nVZEROUPPER\nRET", 1),
		"missing-input-transport": strings.Replace(source, "VMOVDQU64 (BX),Z1\n", "", 1),
		"changed-output-address":  strings.Replace(source, "VMOVDQU64 Z2,(DI)", "VMOVDQU64 Z2,1(DI)", 1),
		"missing-carry-producer":  strings.Replace(source, "STC\n", "", 1),
		"duplicate-family-effect": strings.Replace(source, "PABSB X3,X2", "PABSB X3,X2\nPABSB X3,X2", 1),
		"unknown-extra-function":  source + "TEXT ·Foreign(SB),4,$0-0\nRET\n",
	} {
		t.Run("source/"+name, func(t *testing.T) {
			if changed == source {
				t.Fatal("independent source mutation was not applied")
			}
			x86LEAActualTargetGoObject(t, "amd64", "x86_64-pc-windows-msvc", changed)
			if output, err := x86PackedAbsSignPortableIR(changed, ir, "amd64"); err == nil || output != "" {
				t.Fatal("portable owner accepted different source effects or input transports", err)
			}
		})
	}
	for name, changed := range map[string]string{
		"inline-assembly":            inBody(`call void asm sideeffect "nop", ""()`),
		"native-call":                inBody("%foreign = call i32 @llvm.x86.rdpid()"),
		"extra-definition":           ir + "define void @Foreign() {\n  ret void\n}\n",
		"foreign-group-reference":    inBody("call void @Foreign() " + group[1]),
		"duplicated-feature-group":   ir + group[0],
		"unobserved-feature-profile": strings.Replace(ir, group[2], group[2]+",+avx512vnni", 1),
	} {
		t.Run("IR/"+name, func(t *testing.T) {
			if changed == ir {
				t.Fatal("independent IR mutation was not applied")
			}
			if output, err := x86PackedAbsSignPortableIR(source, changed, "amd64"); err == nil || output != "" {
				t.Fatal("portable projection accepted native behavior or unowned ISA references", err)
			}
		})
	}
}

func TestX86PackedAbsSignPortableRuntimeConsumesCheckedIR(t *testing.T) {
	data, err := os.ReadFile("x86_packed_abs_sign_runtime_tdd_test.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "runtime.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	projections, executions := 0, 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestX86PackedAbsSignWholeBytesMinimumWrapAndFlags" {
			continue
		}
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if assignment, ok := node.(*ast.AssignStmt); ok && len(assignment.Rhs) == 1 {
				call, ok := assignment.Rhs[0].(*ast.CallExpr)
				if ok && fmt.Sprint(call.Fun) == "x86PackedAbsSignPortableIR" && len(call.Args) == 3 &&
					fmt.Sprint(call.Args[0]) == "instrumented" && fmt.Sprint(call.Args[1]) == "ir" &&
					fmt.Sprint(call.Args[2]) == "arch" && len(assignment.Lhs) == 2 && fmt.Sprint(assignment.Lhs[0]) == "ir" {
					projections++
				}
			}
			if call, ok := node.(*ast.CallExpr); ok && fmt.Sprint(call.Fun) == "x86ConflictFunnelPortableRuntime" &&
				len(call.Args) == 7 && fmt.Sprint(call.Args[5]) == "ir" {
				executions++
			}
			return true
		})
	}
	if projections != 1 || executions != 1 {
		t.Fatal("original actual-host driver no longer consumes the checked mathematical IR", projections, executions)
	}
}
