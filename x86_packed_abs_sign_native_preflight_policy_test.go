package plan9asm

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func x86PackedAbsSignOriginalRuntimeSource(t *testing.T) string {
	t.Helper()
	data, file, _ := x86OriginalFloatingPolicyFile(t, "amd64_lower_abs_sign_test.go")
	hashes, err := x86PackedAbsSignOriginalPayloadHashes(data)
	if err != nil || hashes["source"] != "2c3660ebcce2c3d76fcc556f987f5cddd480557965ad4005c41ef6f4749f9218" ||
		hashes["mainC"] != "b2867b9896c8afaab063d25ab65aeff74bd4ffa3645791febac92ec62fd19c60" {
		t.Fatal("complete original ABS/sign ASM, C inputs or observations changed", err)
	}
	owner := x86OriginalFloatingPolicyFunction(t, file, "TestAMD64PackedAbsSignRuntimeSemantics")
	var source string
	ast.Inspect(owner.Body, func(node ast.Node) bool {
		assignment, ok := node.(*ast.AssignStmt)
		if !ok || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
			return true
		}
		name, ok := assignment.Lhs[0].(*ast.Ident)
		if !ok || name.Name != "source" {
			return true
		}
		literal, ok := assignment.Rhs[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING || source != "" {
			t.Fatal("original ABS/sign source lost its unique literal")
		}
		source, err = strconv.Unquote(literal.Value)
		return false
	})
	if err != nil || source == "" {
		t.Fatal("complete original ABS/sign source disappeared", err)
	}
	return source
}

func TestX86PackedAbsSignOriginalRuntimeOwnsAllocationPreflight(t *testing.T) {
	x86PackedAbsSignOriginalRuntimeSource(t)
	_, file, set := x86OriginalFloatingPolicyFile(t, "amd64_lower_abs_sign_test.go")
	owner := x86OriginalFloatingPolicyFunction(t, file, "TestAMD64PackedAbsSignRuntimeSemantics")
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
		t.Fatal("original ABS/sign runtime needs its own actual-allocation preflight before execution")
	}
	topLevel := false
	for _, statement := range owner.Body.List {
		if expression, ok := statement.(*ast.ExprStmt); ok && expression.X == calls[0] {
			topLevel = true
		}
	}
	if !topLevel {
		t.Fatal("ABS/sign CPU proof cannot be conditional, deferred or borrowed from another owner")
	}
	var actual bytes.Buffer
	if err := format.Node(&actual, set, calls[0]); err != nil {
		t.Fatal(err)
	}
	const want = `x86OriginalFloatingRuntimeRequireCPU(t, "packed-abs-sign", clang, triple, runPrefix)`
	if actual.String() != want {
		t.Fatal("ABS/sign preflight changed the actual compiler, profile, target or execution route", actual.String())
	}
}

func TestX86PackedAbsSignOriginalRuntimeCompleteOpcodeProfile(t *testing.T) {
	_, file, _ := x86OriginalFloatingPolicyFile(t, "x86_original_floating_runtime_preflight_test.go")
	driver := x86OriginalFloatingPolicyFunction(t, file, "x86OriginalFloatingRuntimeRequireCPU")
	profiles := 0
	ast.Inspect(driver.Body, func(node ast.Node) bool {
		clause, ok := node.(*ast.CaseClause)
		if !ok || len(clause.List) != 1 {
			return true
		}
		literal, ok := clause.List[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			return true
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil || name != "packed-abs-sign" {
			return true
		}
		profiles++
		var body bytes.Buffer
		for _, statement := range clause.Body {
			if err := format.Node(&body, token.NewFileSet(), statement); err != nil {
				t.Fatal(err)
			}
		}
		if strings.Join(strings.Fields(body.String()), "") != "required=4" {
			t.Fatal("ABS/sign preflight borrowed another owner's capability profile", body.String())
		}
		return true
	})
	if profiles != 1 {
		t.Fatal("independent original ABS/sign execution profile missing or duplicated", profiles)
	}
	state, opcodes := x86OriginalFloatingPolicyDriver(t)
	const opening = "__attribute__((target(\"ssse3,avx2,avx512f,avx512vl\")))\nstatic int original_packed_abs_sign(void) {"
	start := strings.Index(opcodes, opening)
	if start < 0 || strings.Count(opcodes, "static int original_packed_abs_sign(void)") != 1 {
		t.Fatal("complete ABS/sign probe requires its own minimum-ISA target function")
	}
	rest := opcodes[start+len(opening):]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("complete ABS/sign original-opcode probe disappeared")
	}
	probe := rest[:end]
	for _, opcode := range []string{"psignw ", "vpsignd ", "vpabsd ", "vpabsq ", "kmovw ", "vmovdqu64 ", "%{%%k1%}", "%{z%}"} {
		if !strings.Contains(probe, opcode) {
			t.Fatal("ABS/sign probe lost legacy alignment, Y/Z, opmask or result observation", opcode)
		}
	}
	for _, forbidden := range []string{"avx512bw", "avx512dq", "fma", "kmovq "} {
		if strings.Contains(probe, forbidden) {
			t.Fatal("ABS/sign probe introduced an independently unnecessary native ISA", forbidden)
		}
	}
	mainStart := strings.LastIndex(opcodes, "int main(void)")
	if mainStart < 0 {
		t.Fatal("actual ABS/sign allocation preflight main is missing")
	}
	main := opcodes[mainStart:]
	guard := strings.Index(main, "if (!original_floating_required_state(")
	legacyGuard := strings.Index(main, "if (profile==4 && !original_packed_abs_sign_required_legacy(ssse3,avx2)) return 78;")
	call := strings.Index(main, "if (profile==4 && !original_packed_abs_sign()) return 82;")
	if guard < 0 || legacyGuard <= guard || call <= legacyGuard {
		t.Fatal("ABS/sign original opcodes must follow actual base and legacy CPUID/XCR0 checks")
	}
	for _, fact := range []string{"ssse3=(c>>9)&1", "avx2=(b>>5)&1", "SSSE3=%u", "AVX2=%u"} {
		if !strings.Contains(main, fact) {
			t.Fatal("ABS/sign actual-allocation receipt lost a genuine native prerequisite", fact)
		}
	}
	if !strings.Contains(state, "static int original_packed_abs_sign_required_legacy(") {
		t.Fatal("ABS/sign legacy feature predicate is missing")
	}
	_, clang, found := findLlcAndClang(t)
	if !found {
		t.Fatal("LLVM22 clang required for the independent pure capability boundary")
	}
	// These rows run the actual pure predicates on the current host. They do
	// not execute a native probe or certify the original x86 runtime.
	const checks = `
int main(void) {
    for(unsigned flags=0;flags<128;flags++) for(unsigned bits=0;bits<32;bits++) {
        unsigned sse2=flags&1,avx=(flags>>1)&1,os=(flags>>2)&1,f=(flags>>3)&1;
        unsigned vl=(flags>>4)&1,ssse3=(flags>>5)&1,avx2=(flags>>6)&1;
        const unsigned positions[]={1,2,5,6,7}; uint64_t xcr0=0;
        for(unsigned i=0;i<5;i++) if(bits&(1u<<i)) xcr0|=UINT64_C(1)<<positions[i];
        for(unsigned fma=0;fma<2;fma++) {
            int actual=original_floating_required_state(4,sse2,avx,os,f,vl,fma,xcr0)&&
                       original_packed_abs_sign_required_legacy(ssse3,avx2);
            if(actual!=(sse2&&avx&&os&&f&&vl&&ssse3&&avx2&&bits==31)) return 1;
        }
    }
    return 0;
}
`
	directory := t.TempDir()
	source, executable := filepath.Join(directory, "abs-capability.c"), filepath.Join(directory, "abs-capability")
	if err := os.WriteFile(source, []byte(state+checks), 0600); err != nil {
		t.Fatal(err)
	}
	execution := x86FloatCompareExecution{triple: testTargetTriple(runtime.GOOS, runtime.GOARCH), compiler: []string{clang}}
	execution.compileC(t, source, executable)
	execution.run(t, executable)
	t.Logf("independent pure ABS/sign prerequisite rows: %d; native execution remains separate", 128*32*2)
}
