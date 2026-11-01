//go:build unix

package plan9asm

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"runtime"
	"strings"
	"testing"
)

type fixedLocalConversionRuntimeCase struct {
	name, destination string
	width, offset     int
	dead              bool
}

func fixedLocalConversionRuntimeCases(all bool) []fixedLocalConversionRuntimeCase {
	rows := x86PackedNativeAddressRows()
	rows = append(rows,
		struct{ name, destination string }{"CVTPL2PS", "X1"},
		struct{ name, destination string }{"CVTPL2PD", "X1"},
		struct{ name, destination string }{"VCVTDQ2PS", "Y1"},
		struct{ name, destination string }{"VCVTDQ2PD", "Y1"})
	var cases []fixedLocalConversionRuntimeCase
	for _, row := range rows {
		if !all && strings.HasPrefix(row.name, "V") {
			continue
		}
		width := 16
		if strings.HasPrefix(row.destination, "Y") {
			width = 32
		}
		for _, dead := range []bool{false, true} {
			for _, offset := range []int{120, 128, 128 + width - 8, 128 + width} {
				cases = append(cases, fixedLocalConversionRuntimeCase{
					name: row.name, destination: row.destination,
					width: width, offset: offset, dead: dead,
				})
			}
		}
	}
	return cases
}

func fixedLocalConversionRuntimeProgram(cases []fixedLocalConversionRuntimeCase, triple string) (string, string, string, string) {
	var assembly, declarations, goRows, cRows, cDeclarations strings.Builder
	prefix := ""
	if strings.Contains(triple, "apple") {
		prefix = "_"
	}
	for index, row := range cases {
		name := fmt.Sprintf("Value%d", index)
		operation := row.name + " 64(BP)," + row.destination
		if !row.dead {
			move := "VMOVDQU"
			if !strings.HasPrefix(row.name, "V") {
				move = "MOVOU"
			}
			operation += "\n" + move + " " + row.destination + ",128(BP)"
		}
		body := fixedLocalPackedAssembly(operation)
		body = strings.Replace(body, "$256-16", "$512-16", 1)
		body = strings.Replace(body, "MOVQ 128(BP),AX", fmt.Sprintf("MOVQ %d(BP),AX", row.offset), 1)
		assembly.WriteString(strings.Replace(body, "·Value", "·"+name, 1))
		fmt.Fprintf(&declarations, "func %s(a uint64) uint64\n", name)
		canary := row.dead || row.offset < 128 || row.offset >= 128+row.width
		fmt.Fprintf(&goRows, "{%s, %v},\n", name, canary)
		canaryValue := 0
		if canary {
			canaryValue = 1
		}
		fmt.Fprintf(&cRows, "{value%d, %d},\n", index, canaryValue)
		fmt.Fprintf(&cDeclarations, "extern uint64_t value%d(uint64_t) __asm__(\"%sexample.invalid/framefixture.%s\");\n", index, prefix, name)
	}
	// The caller controls and snapshots MXCSR outside the observed frame.
	// These helpers belong only to the independently compiled Go executable.
	original := `package main
import "fmt"
func readCSR() uint32
func writeCSR(csr uint32)
` + declarations.String() + `
func main() {
    rows := []struct { call func(uint64) uint64; canary bool }{
` + goRows.String() + `
    }
    values := []uint64{0,1,^uint64(0),0x8000000080000000,0x3fc000003fc00000,0x3ff8000000000000,0x7fc123457fc12345,0x7ff8123456789abc}
    for n,row := range rows {
        for v,value := range values {
            for mode:=0; mode<32; mode++ {
                csr := uint32(0x1f80) | uint32(mode&3)<<13 | uint32((mode>>2)&1)<<6 | uint32((mode>>3)&1)<<15
                if mode&16 != 0 { csr |= 63 }
                writeCSR(csr)
                got := row.call(value)
                status := readCSR()
                writeCSR(0x1f80)
                if row.canary && got != value { panic("original private-frame canary changed") }
                fmt.Printf("%d %d %d %016x %08x\n", n,v,mode,got,status)
            }
        }
    }
}
`
	driver := `#include <stdint.h>
#include <stdio.h>
#include <xmmintrin.h>
` + cDeclarations.String() + `
int main(void) {
    const struct { uint64_t (*call)(uint64_t); int canary; } rows[] = {
` + cRows.String() + `
    };
    const uint64_t values[] = {0,1,UINT64_MAX,UINT64_C(0x8000000080000000),UINT64_C(0x3fc000003fc00000),UINT64_C(0x3ff8000000000000),UINT64_C(0x7fc123457fc12345),UINT64_C(0x7ff8123456789abc)};
    for (unsigned n=0; n<sizeof(rows)/sizeof(rows[0]); n++) {
        for (unsigned v=0; v<8; v++) {
            for (unsigned mode=0; mode<32; mode++) {
                unsigned csr = 0x1f80 | ((mode&3)<<13) | (((mode>>2)&1)<<6) | (((mode>>3)&1)<<15);
                if (mode&16) csr |= 63;
                _mm_setcsr(csr);
                uint64_t got = rows[n].call(values[v]);
                unsigned status = _mm_getcsr();
                _mm_setcsr(0x1f80);
                if (rows[n].canary && got != values[v]) return 2;
                printf("%u %u %u %016llx %08x\n",n,v,mode,(unsigned long long)got,status);
            }
        }
    }
    return 0;
}
`
	return assembly.String(), declarations.String(), original, driver
}

func fixedLocalConversionRuntime(t *testing.T, execution x86FloatCompareExecution, all bool) {
	t.Helper()
	cases := fixedLocalConversionRuntimeCases(all)
	for batch := 0; batch*48 < len(cases); batch++ {
		fixedLocalConversionRuntimeBatch(t, execution, all, batch)
	}
}

func fixedLocalConversionRuntimeBatchRange(total, batch int) (start, end int, ok bool) {
	if total <= 0 || batch < 0 || batch > (total-1)/48 {
		return 0, 0, false
	}
	start, end = batch*48, total
	if total-start > 48 {
		end = start + 48
	}
	return start, end, true
}

func fixedLocalConversionRuntimeBatch(t *testing.T, execution x86FloatCompareExecution, all bool, batch int) {
	t.Helper()
	cases := fixedLocalConversionRuntimeCases(all)
	start, end, ok := fixedLocalConversionRuntimeBatchRange(len(cases), batch)
	if !ok {
		t.Fatal("invalid complete conversion runtime batch", batch, len(cases))
	}
	// Reuse only this batch's disposable compiler artifacts. Each API still
	// captures, binds, consumes and closes its own complete source observation.
	t.Setenv("GOCACHE", t.TempDir())
	t.Run(fmt.Sprintf("batch%d", batch), func(t *testing.T) {
		assembly, declarations, original, driver := fixedLocalConversionRuntimeProgram(cases[start:end], execution.triple)
		helpers := "TEXT ·readCSR(SB),4,$0-4\nSTMXCSR ret+0(FP)\nRET\nTEXT ·writeCSR(SB),4,$0-4\nLDMXCSR csr+0(FP)\nRET\n"
		want := string(x86ScalarFloatIntegerOriginalOutput(t, execution, assembly+helpers, original))
		if strings.Count(want, "\n") != (end-start)*8*32 {
			t.Fatal("original Go numerical/status denominator changed")
		}
		pkg, request, _, options := x86CMOVFixedLocalFixture(t,
			assembly, declarations, runtime.GOOS+"/amd64", execution.triple)
		fixedLocalConversionPrepareToolCache(t, request)
		fixedLocalFreshAPIs(t, pkg, request, options, []string{"Translate", "Module", "GoModule"}, func(t *testing.T, ir string, err error) {
			if err != nil {
				t.Fatal(err)
			}
			for _, optimize := range []bool{false, true} {
				input, level := ir, "-O0"
				if optimize {
					input, level = x86MulDivRoundOptimize(t, ir), "-O2"
				}
				got := string(execution.compileAndRunLLVM(t, "private-conversion", input, driver, level))
				if got != want {
					t.Fatal("original Go and LLVM private-frame value/MXCSR/canary results differ")
				}
			}
		})
	})
}

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionSSE(t *testing.T) {
	fixedLocalConversionRuntime(t, x86FloatCompareRuntimeTools(t, x86FloatCompareSSE), false)
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		t.Log("Rosetta SSE diagnostic, not native AVX512 execution")
	}
}

func TestGoAMD64FixedLocalConversionRuntimeOwnership(t *testing.T) {
	for _, input := range [][2]int{{0, 0}, {48, -1}, {48, 1}, {336, 7}} {
		if _, _, ok := fixedLocalConversionRuntimeBatchRange(input[0], input[1]); ok {
			t.Fatal("invalid conversion runtime batch accepted", input)
		}
	}
	for _, row := range []struct {
		all   bool
		count int
	}{{false, 48}, {true, 336}} {
		cases := fixedLocalConversionRuntimeCases(row.all)
		if len(cases) != row.count {
			t.Fatalf("runtime cases all=%v: %d, want %d", row.all, len(cases), row.count)
		}
		seen := make([]int, len(cases))
		for batch := 0; batch*48 < len(cases); batch++ {
			start, end, ok := fixedLocalConversionRuntimeBatchRange(len(cases), batch)
			if !ok || end-start != 48 {
				t.Fatal("incomplete conversion runtime batch", batch, start, end)
			}
			for index := start; index < end; index++ {
				seen[index]++
			}
		}
		for index, count := range seen {
			if count != 1 {
				t.Fatal("missing or duplicated original runtime case", index, count)
			}
		}
		names := make(map[string]int)
		for _, entry := range cases {
			names[entry.name]++
		}
		if len(names)*8 != row.count {
			t.Fatal("runtime inventory lost distinct family members", names)
		}
		for name, count := range names {
			if count != 8 {
				t.Fatalf("%s lost a live/dead or canary axis: %d", name, count)
			}
		}
		assembly, _, _, _ := fixedLocalConversionRuntimeProgram(cases, "x86_64-unknown-linux-gnu")
		requireX86GoAssemblerResult(t, "amd64", assembly, true)
	}
	const filename = "amd64_fixed_local_conversion_runtime_linux_amd64_test.go"
	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm"}, {"linux", "arm64"},
		{"js", "wasm"}, {"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		context := build.Default
		context.GOOS, context.GOARCH = target.os, target.arch
		selected, err := context.MatchFile(".", filename)
		if err != nil || selected != (target.os == "linux" && target.arch == "amd64") {
			t.Fatal("required native execution owner selection", target, selected, err)
		}
	}
	syntax, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	owners := 0
	for _, declaration := range syntax.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		owners++
		name := fmt.Sprintf("TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalConversionNativeBatch%02d", owners-1)
		if function.Name.Name != name || function.Body == nil || len(function.Body.List) != 1 {
			t.Fatal("native owner missing or conditional")
		}
		statement, ok := function.Body.List[0].(*ast.ExprStmt)
		if !ok {
			t.Fatal("native runtime must execute directly")
		}
		call, ok := statement.X.(*ast.CallExpr)
		if !ok || len(call.Args) != 4 || !fixedLocalConversionIdent(call.Fun, "fixedLocalConversionRuntimeBatch") ||
			!fixedLocalConversionIdent(call.Args[0], "t") || !fixedLocalConversionIdent(call.Args[2], "true") {
			t.Fatal("native runtime lost its complete-family axis")
		}
		batch, ok := call.Args[3].(*ast.BasicLit)
		if !ok || batch.Kind != token.INT || batch.Value != fmt.Sprint(owners-1) {
			t.Fatal("native runtime lost an original batch")
		}
		tools, ok := call.Args[1].(*ast.CallExpr)
		if !ok || len(tools.Args) != 1 || !fixedLocalConversionIdent(tools.Fun, "x86PackedDoubleDwordNativeTools") ||
			!fixedLocalConversionIdent(tools.Args[0], "t") {
			t.Fatal("native runtime bypassed actual CPU/OS/opcode checks")
		}
	}
	if owners != 7 {
		t.Fatal("missing or ambiguous native owner", owners)
	}
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") {
		t.Fatal("required native runtime root not selected by CI", err)
	}
}

func fixedLocalConversionIdent(expression ast.Expr, name string) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name == name
}
