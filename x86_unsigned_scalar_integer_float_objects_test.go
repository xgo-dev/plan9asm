package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

func x86UnsignedScalarIntegerFloatOriginal(t *testing.T) (string, string) {
	t.Helper()
	const path = "amd64_lower_scalar_integer_float_test.go"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"source": "a6867dc62b3626812081e7aeff427689528d6e12feef4f3e190f95f078d754c8",
		"mainC":  "b62cf67cbb3b65a2890d63cdce289a7b6c7e4dae587b5ffc2417cbb0d461ea74",
	}
	values, count := make(map[string]string), 0
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Name.Name != "TestAMD64ScalarIntegerFloatRuntimeSemantics" {
			continue
		}
		count++
		ast.Inspect(function.Body, func(node ast.Node) bool {
			assignment, ok := node.(*ast.AssignStmt)
			if !ok || assignment.Tok != token.DEFINE || len(assignment.Lhs) != 1 || len(assignment.Rhs) != 1 {
				return true
			}
			name, ok := assignment.Lhs[0].(*ast.Ident)
			if !ok || want[name.Name] == "" {
				return true
			}
			literal, ok := assignment.Rhs[0].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || values[name.Name] != "" {
				t.Fatal("original unsigned conversion payload lost its unique complete literal", name.Name)
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || fmt.Sprintf("%x", sha256.Sum256([]byte(value))) != want[name.Name] {
				t.Fatal("original initialized ASM, independent C inputs or observations changed", name.Name, err)
			}
			values[name.Name] = value
			return false
		})
	}
	if count != 1 || len(values) != 2 {
		t.Fatal("complete original scalar integer conversion source/reference disappeared", count)
	}
	return values["source"], values["mainC"]
}

func TestX86UnsignedScalarIntegerFloatOriginalInitializedThreeAPIObjects(t *testing.T) {
	source, _ := x86UnsignedScalarIntegerFloatOriginal(t)
	declaration := "func scalarintegerfloat(out *[128]byte,signed32 *int32,signed64 *int64,unsigned32 *uint32,unsigned64 *uint64,passthrough32 *[4]float32,passthrough64 *[2]float64)"
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("original scalar conversion objects require LLVM22 llc")
	}
	for _, triple := range []string{"x86_64-unknown-linux-gnu", "x86_64-apple-darwin", "x86_64-pc-windows-msvc"} {
		t.Run(triple, func(t *testing.T) {
			x86LEAActualTargetGoObject(t, "amd64", triple, "#include \"textflag.h\"\n"+source)
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source, declaration, "amd64", triple, api)
					if err != nil || ir == "" {
						t.Fatal("original complete initialized scalar integer conversion rejected", err)
					}
					for _, text := range []string{ir, x86DwordProductIROptimize(t, ir)} {
						x86ScalarPrecisionRequireNativeEffects(t, text,
							map[string][]string{"scalarintegerfloat": {"VCVTUSI2SDL", "VCVTUSI2SDQ", "VCVTUSI2SSL", "VCVTUSI2SSQ"}})
						compileLLVMToObject(t, llc, triple, "original-unsigned-scalar.ll", "original-unsigned-scalar.o", text)
					}
				})
			}
		})
	}
}

// The complete physical 64-byte observation exposes both scalar passthrough
// and nonzero wider aliases. These are object fixtures, not AVX512 execution.
// Place the FP integer first: in mode32 its physical ABI0 offset is +4, so a
// nominal W1 producer cannot silently borrow an N8 compressed displacement.
func x86UnsignedScalarIntegerFloatProgram(index int, row x86UnsignedScalarIntegerFloatRow, arch string) (string, string, string) {
	word, move := int(goWordSize(arch)), "MOVQ"
	if arch == "386" {
		move = "MOVL"
	}
	name := fmt.Sprint("UnsignedScalar", index)
	preparation := ""
	if row.source == "GP" {
		preparation = fmt.Sprintf("MOV%s value+0(FP),CX\n", map[int]string{4: "L", 8: "Q"}[row.input])
	}
	source := fmt.Sprintf("TEXT ·%s(SB),4,$0-%d\n%s out+8(FP),DI\n%s p+%d(FP),BX\n"+
		"%s upper+%d(FP),SI\n%s old+%d(FP),DX\nVMOVDQU64 (SI),Z%d\nVMOVDQU64 (DX),Z%d\n%s"+
		"STC\n%s\nVMOVDQU64 Z%d,(DI)\nSETCS 64(DI)\nSTMXCSR 68(DI)\nRET\n",
		name, 8+4*word, move, move, 8+word, move, 8+2*word, move, 8+3*word,
		row.upper, row.destination, preparation, row.instruction(), row.destination)
	declaration := fmt.Sprintf("func %s(value uint64,out *[80]byte,p *byte,upper,old *[64]byte)\n", name)
	return source, declaration, name
}

func TestX86UnsignedScalarIntegerFloatCompleteInitializedFiveTargetObjects(t *testing.T) {
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("unsigned scalar complete objects require LLVM22 llc")
	}
	for _, target := range x86RawReturnTargets {
		t.Run(target.triple, func(t *testing.T) {
			rows := x86UnsignedScalarIntegerFloatRows(target.arch)
			want := 32
			if target.arch == "386" {
				want = 28
			}
			if len(rows) != want {
				t.Fatal("independent complete unsigned shape denominator changed", len(rows), want)
			}
			var source, declarations strings.Builder
			functions := make(map[string][]string)
			for index, row := range rows {
				body, declaration, name := x86UnsignedScalarIntegerFloatProgram(index, row, target.arch)
				source.WriteString(body)
				declarations.WriteString(declaration)
				op := row.op
				if target.arch == "386" {
					op = strings.TrimSuffix(op, "Q")
					if !strings.HasSuffix(op, "L") {
						op += "L"
					}
				}
				functions[name] = []string{op}
			}
			x86LEAActualTargetGoObject(t, target.arch, target.triple, source.String())
			for _, api := range []string{"text", "module", "Go"} {
				t.Run(api, func(t *testing.T) {
					ir, err := x86ScalarFPBitViewAPI(t, source.String(), declarations.String(), target.arch, target.triple, api)
					if err != nil || ir == "" {
						t.Fatal("complete initialized unsigned scalar matrix remains unclosed", err)
					}
					for _, pipeline := range []struct{ name, level, ir string }{
						{"backend_O0", "-O0", ir}, {"backend_O2", "-O2", ir},
						{"IR_O2/backend_O2", "-O2", x86DwordProductIROptimize(t, ir)},
					} {
						t.Run(pipeline.name, func(t *testing.T) {
							x86ScalarPrecisionRequireNativeEffects(t, pipeline.ir, functions)
							x86PackedStringCompileObject(t, llc, target.triple, pipeline.ir, pipeline.level)
						})
					}
				})
			}
		})
	}
}
