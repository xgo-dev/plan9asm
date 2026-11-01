package plan9asm

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestX86UnsignedScalarOriginalRuntimeOwnsAllocationPreflight(t *testing.T) {
	// These are the existing complete literal pins, not a digest of mutable
	// test-driver formatting. The separate object matrix owns the original Go
	// bytes and all three initialized public APIs on each x86 target.
	x86UnsignedScalarIntegerFloatOriginal(t)
	_, file, set := x86OriginalFloatingPolicyFile(t, "amd64_lower_scalar_integer_float_test.go")
	owner := x86OriginalFloatingPolicyFunction(t, file, "TestAMD64ScalarIntegerFloatRuntimeSemantics")
	var calls []*ast.CallExpr
	boundary := owner.End()
	ast.Inspect(owner.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name, ok := call.Fun.(*ast.Ident)
		if !ok {
			return true
		}
		if name.Name == "x86OriginalFloatingRuntimeRequireCPU" {
			calls = append(calls, call)
		}
		if name.Name == "compileAndRunRuntimeTestForTarget" && call.Pos() < boundary {
			boundary = call.Pos()
		}
		return true
	})
	if len(calls) != 1 || boundary == owner.End() || calls[0].End() >= boundary {
		t.Fatal("original unsigned runtime must own one actual-allocation CPU/opcode preflight before execution")
	}
	topLevel := false
	for _, statement := range owner.Body.List {
		if expression, ok := statement.(*ast.ExprStmt); ok && expression.X == calls[0] {
			topLevel = true
		}
	}
	if !topLevel {
		t.Fatal("unsigned allocation preflight must not be conditional, deferred or delegated to another owner")
	}
	var actual bytes.Buffer
	if err := format.Node(&actual, set, calls[0]); err != nil {
		t.Fatal(err)
	}
	const want = `x86OriginalFloatingRuntimeRequireCPU(t, "unsigned-scalar-integer", clang, triple, runPrefix)`
	if actual.String() != want {
		t.Fatal("unsigned preflight substituted its own profile, compiler, target or execution route", actual.String())
	}
}

func TestX86UnsignedScalarOriginalRuntimeCompleteOpcodeProfile(t *testing.T) {
	_, file, _ := x86OriginalFloatingPolicyFile(t, "x86_original_floating_runtime_preflight_test.go")
	driver := x86OriginalFloatingPolicyFunction(t, file, "x86OriginalFloatingRuntimeRequireCPU")
	profiles := 0
	ast.Inspect(driver.Body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expression := range clause.List {
			literal, ok := expression.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || value != "unsigned-scalar-integer" {
				continue
			}
			profiles++
			var body bytes.Buffer
			for _, statement := range clause.Body {
				if err := format.Node(&body, token.NewFileSet(), statement); err != nil {
					t.Fatal(err)
				}
			}
			if strings.Join(strings.Fields(body.String()), "") != "required=3" {
				t.Fatal("unsigned opcode diagnostic borrowed another capability profile", body.String())
			}
		}
		return true
	})
	if profiles != 1 {
		t.Fatal("independent unsigned scalar execution profile is missing or duplicated", profiles)
	}
	_, opcodes := x86OriginalFloatingPolicyDriver(t)
	const opening = "__attribute__((target(\"avx512f\")))\nstatic int original_unsigned_scalar_integer(void) {"
	start := strings.Index(opcodes, opening)
	if start < 0 || strings.Count(opcodes, "static int original_unsigned_scalar_integer(void)") != 1 {
		t.Fatal("unsigned scalar original-opcode probe must have its own exact F-only target function")
	}
	rest := opcodes[start+len(opening):]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("complete unsigned scalar original-opcode function disappeared")
	}
	probe := rest[:end]
	for _, required := range []string{
		"vcvtusi2sdl ", "vcvtusi2sdq ", "vcvtusi2ssl ", "vcvtusi2ssq ",
		"%{rz-sae%}", "%{rd-sae%}", "%{rn-sae%}",
		"vmovss ", "vmovsd ",
	} {
		if !strings.Contains(probe, required) {
			t.Fatal("unsigned profile lost an original width, actual opcode, result observation or embedded control", required)
		}
	}
	mainStart := strings.LastIndex(opcodes, "int main(void)")
	if mainStart < 0 {
		t.Fatal("actual unsigned allocation preflight main is missing")
	}
	main := opcodes[mainStart:]
	guard := strings.Index(main, "if (!original_floating_required_state(")
	probeCall := strings.Index(main, "if (profile==3 && !original_unsigned_scalar_integer()) return 81;")
	if guard < 0 || probeCall <= guard {
		t.Fatal("unsigned original opcodes must execute only after their own actual CPUID/XCR0 guard and fail on wrong results")
	}
}
