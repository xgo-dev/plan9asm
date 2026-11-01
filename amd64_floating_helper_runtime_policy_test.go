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

// Bind the existing complete assembly builders and independent C references.
// A transport repair must not replace them with a smaller passing program.
var x86FloatingHelperOriginalRuntimeOwners = []struct {
	root, file, sourceSHA, cSHA string
}{
	{
		root: "TestAMD64GetExpRuntimeSemantics", file: "amd64_lower_getexp_test.go",
		sourceSHA: "e984e60362c11b28189a43d2e24efc2a25d9ef7df5d7ba750632dffc2ada582c",
		cSHA:      "755b471dca11961ef94e8103f354d27b1b737d265886465f6cca9ce18a953f88",
	},
	{
		root: "TestAMD64GetMantRuntimeSemantics", file: "amd64_lower_getmant_test.go",
		sourceSHA: "631e669e6d8ff1c65192ad74a54f7d5ba3bc847e3b0c64dac64d94f44c1dcbbe",
		cSHA:      "c9bf0ab8f11e0317569d87c4ec72a9815afddcdf599c6b05195f4ecd9f94a19e",
	},
	{
		root: "TestAMD64ScaleFRuntimeSemantics", file: "amd64_lower_scalef_test.go",
		sourceSHA: "9e0547ef11ff18488d9f093641beff6f2f88405e6c6aa8884d7b79bde75307ab",
		cSHA:      "3cec89474463e1884cc2979aea89520dd011589ab73d3c6051bfebc61bcc31c9",
	},
	{
		root: "TestAMD64FloatingRangeRuntimeSemantics", file: "amd64_lower_range_test.go",
		sourceSHA: "5ec0b3b10d651607d57d18991cb9dd1d91aeea18c6bbbaaa540c0c2970370cbb",
		cSHA:      "f8b2c3f77cb8f4c6902308df47a1a832c3d03a981471ffe44a837c93b457b359",
	},
	{
		root: "TestAMD64FloatingRangeDoubleAndScalarRuntimeSemantics", file: "amd64_lower_range_test.go",
		sourceSHA: "a5fac93bf84e828725448f9d6fdef423baf0ac0f1e1bdc7ce30537bbeb4f4377",
		cSHA:      "5dfe99148f760b1df90c2633526437cf02e932f2f98068d6fdb15eb6cee67409",
	},
	{
		root: "TestAMD64FixupImmediateRuntimeSemantics", file: "amd64_lower_fixupimm_test.go",
		sourceSHA: "6ba976350729649f866150d52bc624bc5e5628524295d544c3d5df2bbe79b3fd",
		cSHA:      "147083a3eb84d95f929c67ac71d7ef42932b2bbdc4c8d5b2d3eee81ed7ac5a27",
	},
	{
		root: "TestAMD64ScaledRoundRuntimeSemantics", file: "amd64_lower_scaled_round_test.go",
		sourceSHA: "c53a42b278d22ca13a3144f75dd58be991b8971ab70754f4bcffbbe952f2c413",
		cSHA:      "090f1b1990362807062dfe8709bd4094cfad1fcb2b6b9470ea0c56e516429db9",
	},
	{
		root: "TestAMD64FPClassRuntimeSemantics", file: "amd64_lower_fpclass_test.go",
		sourceSHA: "754b23dc03e28506f8036180859683c6a07f49355752f846d8f5afcb56e4f078",
		cSHA:      "92e86c32eddff2266c607b5ca64b9616e86c46be09e1a9ca2948d1e51306bff8",
	},
}

func TestX86FloatingHelperRuntimeNativeOwnerAndPipelinePolicy(t *testing.T) {
	if len(x86FloatingHelperOriginalRuntimeOwners) != 8 {
		t.Fatal("complete original runtime owner inventory changed")
	}
	for _, owner := range x86FloatingHelperOriginalRuntimeOwners {
		t.Run(owner.root, func(t *testing.T) {
			data, err := os.ReadFile(owner.file)
			if err != nil {
				t.Fatal(err)
			}
			positions := token.NewFileSet()
			file, err := parser.ParseFile(positions, owner.file, data, 0)
			if err != nil {
				t.Fatal(err)
			}
			var function *ast.FuncDecl
			for _, declaration := range file.Decls {
				if candidate, ok := declaration.(*ast.FuncDecl); ok && candidate.Name.Name == owner.root {
					if function != nil {
						t.Fatal("duplicate original runtime owner")
					}
					function = candidate
				}
			}
			if function == nil || function.Body == nil {
				t.Fatal("missing original runtime owner")
			}
			start, end := token.NoPos, token.NoPos
			cSource := ""
			calls := make(map[string]int)
			for _, statement := range function.Body.List {
				ast.Inspect(statement, func(node ast.Node) bool {
					if identifier, ok := node.(*ast.Ident); ok && identifier.Name == "source" && start == token.NoPos {
						start = statement.Pos()
					}
					if call, ok := node.(*ast.CallExpr); ok {
						if identifier, ok := call.Fun.(*ast.Ident); ok {
							calls[identifier.Name]++
							if identifier.Name == "requireX86GoAssemblerResult" && end == token.NoPos {
								end = statement.Pos()
							}
						}
					}
					if specification, ok := node.(*ast.ValueSpec); ok && len(specification.Names) == 1 &&
						specification.Names[0].Name == "mainC" && len(specification.Values) == 1 {
						if literal, ok := specification.Values[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
							cSource, err = strconv.Unquote(literal.Value)
						}
					}
					return true
				})
			}
			if start == token.NoPos || end <= start || cSource == "" || err != nil {
				t.Fatal("original complete source/reference boundaries lost", err)
			}
			assemblyBuilder := strings.TrimSpace(string(data[positions.Position(start).Offset:positions.Position(end).Offset]))
			if actual := fmt.Sprintf("%x", sha256.Sum256([]byte(assemblyBuilder))); actual != owner.sourceSHA {
				t.Fatal("original complete assembly source builder changed", actual, owner.sourceSHA)
			}
			if actual := fmt.Sprintf("%x", sha256.Sum256([]byte(cSource))); actual != owner.cSHA {
				t.Fatal("independent original C values/reference changed", actual, owner.cSHA)
			}
			if calls["x86FloatingHelperRuntimeTools"] != 1 || calls["x86FloatingHelperRunNativePipelines"] != 1 ||
				calls["rosettaAvailable"] != 0 || calls["compileAndRunRuntimeTestForTarget"] != 0 {
				t.Fatal("original runtime must use its required native EVEX/DQ owner and all three execution pipelines", calls)
			}
		})
	}
}

func TestX86FloatingHelperRuntimeNativeDriverPolicy(t *testing.T) {
	data, err := os.ReadFile("amd64_floating_helper_runtime_test.go")
	if err != nil {
		t.Fatal(err)
	}
	positions := token.NewFileSet()
	file, err := parser.ParseFile(positions, "amd64_floating_helper_runtime_test.go", data, 0)
	if err != nil {
		t.Fatal(err)
	}
	functions := make(map[string]*ast.FuncDecl)
	for _, declaration := range file.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok {
			functions[function.Name.Name] = function
		}
	}
	tools := functions["x86FloatingHelperRuntimeTools"]
	pipelines := functions["x86FloatingHelperRunNativePipelines"]
	if tools == nil || pipelines == nil {
		t.Fatal("required native tools or complete pipeline driver missing")
	}
	calls := func(function *ast.FuncDecl) map[string]int {
		result := make(map[string]int)
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				switch target := call.Fun.(type) {
				case *ast.Ident:
					result[target.Name]++
				case *ast.SelectorExpr:
					result[target.Sel.Name]++
				}
			}
			return true
		})
		return result
	}
	toolsCalls, pipelineCalls := calls(tools), calls(pipelines)
	if toolsCalls["x86FloatCompareRuntimeTools"] != 1 || toolsCalls["compileC"] != 1 || toolsCalls["run"] != 1 ||
		toolsCalls["Skip"] != 1 || pipelineCalls["compileAndRunLLVM"] != 1 ||
		pipelineCalls["x86DwordProductIROptimize"] != 1 || pipelineCalls["Run"] != 1 || pipelineCalls["Skip"] != 0 {
		t.Fatal("native preflight or actual compiler/run obligations changed", toolsCalls, pipelineCalls)
	}
	if len(tools.Body.List) < 3 {
		t.Fatal("native host and EVEX checks missing")
	}
	host, ok := tools.Body.List[1].(*ast.IfStmt)
	if !ok {
		t.Fatal("native host exclusion is not an explicit platform boundary")
	}
	condition := string(data[positions.Position(host.Cond.Pos()).Offset:positions.Position(host.Cond.End()).Offset])
	if condition != `runtime.GOOS != "linux" || runtime.GOARCH != "amd64"` {
		t.Fatal("native platform exclusion became a CPU/tool skip", condition)
	}
	var actual []string
	ast.Inspect(pipelines.Body, func(node ast.Node) bool {
		loop, ok := node.(*ast.RangeStmt)
		if !ok {
			return true
		}
		rows, ok := loop.X.(*ast.CompositeLit)
		if !ok {
			t.Fatal("native execution pipelines lost their complete explicit inventory")
		}
		for _, element := range rows.Elts {
			row, ok := element.(*ast.CompositeLit)
			if !ok {
				t.Fatal("native pipeline row is not a complete fixture")
			}
			values := make(map[string]string)
			for _, field := range row.Elts {
				pair, ok := field.(*ast.KeyValueExpr)
				if !ok {
					t.Fatal("native pipeline lacks explicit axes")
				}
				key, ok := pair.Key.(*ast.Ident)
				if !ok {
					t.Fatal("native pipeline key is not bound")
				}
				values[key.Name] = string(data[positions.Position(pair.Value.Pos()).Offset:positions.Position(pair.Value.End()).Offset])
			}
			actual = append(actual, values["name"]+"/"+values["backend"]+"/"+values["optimizeIR"])
		}
		return true
	})
	want := []string{`"backend_O0"/"-O0"/`, `"backend_O2"/"-O2"/`, `"IR_O2/backend_O2"/"-O2"/true`}
	if strings.Join(actual, "\n") != strings.Join(want, "\n") {
		t.Fatal("native execution narrowed or changed backend/IR optimization axes", actual)
	}
	for _, required := range []string{
		`x86FloatCompareRuntimeTools(t, x86FloatCompareEVEX)`,
		`if (!f || !dq || !vl || !osxsave || (xcr0&0xe6)!=0xe6) return 1;`,
		`if (!original_dq()) return 2;`,
		`vfpclassps $2,%%zmm0,%%k1;`,
		`vfpclassps $2,%%xmm0,%%k1;`,
		`vfpclasssd $2,%%xmm0,%%k1;`,
	} {
		if !strings.Contains(string(data), required) {
			t.Fatal("native CPU, original opcode or OS state obligation missing", required)
		}
	}
}
