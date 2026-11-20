package plan9asm

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The explicit inventory records pending native execution, never a passing
// substitute for it. Grammar, original-source and object tests remain default.
func TestCIAVX512NativeQualificationInventory(t *testing.T) {
	data, err := os.ReadFile("testdata/native/avx512-roots.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Fields(string(data))
	if len(want) != 65 || !sort.StringsAreSorted(want) {
		t.Fatal("native qualification must retain all 65 canonical owners")
	}
	for i, name := range want {
		if !strings.HasPrefix(name, "Test") || i > 0 && name == want[i-1] {
			t.Fatal("invalid or duplicate native qualification owner", name)
		}
	}

	for _, target := range []struct{ os, arch string }{
		{"linux", "amd64"}, {"linux", "386"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"}, {"windows", "amd64"},
	} {
		t.Run(target.os+"-"+target.arch, func(t *testing.T) {
			ordinary := ciNativeAVX512Roots(t, target.os, target.arch, false)
			qualified := ciNativeAVX512Roots(t, target.os, target.arch, true)
			var added []string
			for name := range ordinary {
				if !qualified[name] {
					t.Fatal("qualification tag removed an ordinary test", name)
				}
			}
			for name := range qualified {
				if !ordinary[name] {
					added = append(added, name)
				}
			}
			sort.Strings(added)
			if target.os != "linux" || target.arch != "amd64" {
				if len(added) != 0 {
					t.Fatal("native AMD64 qualification escaped its actual host", added)
				}
				return
			}
			if !reflect.DeepEqual(added, want) {
				t.Fatal("native qualification inventory differs from pending owners", added)
			}
			for _, name := range []string{
				"TestAMD64ConformanceNativeGo",
				"TestAMD64ConformanceLLVMRuntime",
				"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalPackedSSE",
				"TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalVEX",
				"TestCrossLinuxRuntimeMatrixX86PackedConversionLegacyIEEEStatusFlags",
				"TestCrossLinuxRuntimeMatrixX86PackedConversionLegacyDeadFaults",
				"TestCrossLinuxRuntimeMatrixX86COMIDeadMemoryExtent",
				"TestCrossLinuxRuntimeMatrixX86COMINativeVectorFlags",
				"TestCrossLinuxRuntimeMatrixX86COMINativeVectorMXCSR",
				"TestCrossLinuxRuntimeMatrixX86ScalarFloatIntegerNativeLegacyUnmaskedTraps",
				"TestCrossLinuxRuntimeMatrixX86FloatingCompareFPScalarByteSpansVEX",
				"TestCrossLinuxRuntimeMatrixX86FloatingCompareIndependentIEEEAndMXCSRVEX",
				"TestCrossLinuxRuntimeMatrixX86FloatingCompareDeadResultEffectsVEX",
				"TestAMD64ConformanceOriginalWideSourceCompiles",
				"TestGoAMD64FixedLocalPackedWideRuntimeOracleCompileOnly",
				"TestGoAMD64FixedLocalPackedWideRuntimeOracleModuleCompileOnly",
				"TestGoAMD64FixedLocalPackedWideRuntimeOracleGoModuleCompileOnly",
				"TestX86PackedConversionNativeRuntimeFixtureObjects",
				"TestX86PackedConversionSignedNativeRuntimeFixtureObjects",
				"TestX86PackedConversionFiveTargetsThreeAPIObjects",
				"TestX86PackedMoveAlignedOriginalGoOracleCompileOnly",
				"TestX86PackedMoveGrammarAxesAndFiveLLVM22Targets",
				"TestX86PackedMoveAlignedResultFiveTargetsThreeAPIs",
				"TestX86ScalarSqrtNativeFixtureObjects",
				"TestX86Reciprocal14NativeOriginalGoProgramCompiles",
				"TestX86Reciprocal14NativeSourceThreeAPIsActualProfileObjects",
			} {
				if !ordinary[name] {
					t.Error("ordinary low-ISA/source/object owner was lost", name)
				}
			}
		})
	}
}

func ciNativeAVX512Roots(t *testing.T, goos, goarch string, qualified bool) map[string]bool {
	t.Helper()
	ctx := ciNativeAVX512BuildContext(goos, goarch, qualified)
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	roots := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		matched, err := ctx.MatchFile(".", name)
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv != nil || !strings.HasPrefix(function.Name.Name, "Test") {
				continue
			}
			if roots[function.Name.Name] {
				t.Fatal("duplicate test root", function.Name.Name)
			}
			roots[function.Name.Name] = true
		}
	}
	return roots
}

// Select explicit test build inputs independently of the executing host or
// ambient tags. This observes file ownership, never native execution.
func ciNativeAVX512BuildContext(goos, goarch string, qualified bool) build.Context {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH = goos, goarch
	ctx.BuildTags = nil
	if qualified {
		ctx.BuildTags = []string{"plan9asm_native_avx512"}
	}
	return ctx
}

// Fixture policies still inspect the complete original body and source/C
// hashes. The new tagged root must call it directly after refusing auto mode.
func ciNativeAVX512RequireWrapper(t *testing.T, root, helper string) {
	t.Helper()
	const path = "amd64_native_avx512_qualification_linux_amd64_test.go"
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range file.Decls {
		fn, ok := declaration.(*ast.FuncDecl)
		if !ok || fn.Name.Name != root {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) != 2 {
			t.Fatal("native qualification must retain its policy and complete fixture", root)
		}
		for i, name := range []string{"x86RequireNativeAVX512Qualification", helper} {
			statement, ok := fn.Body.List[i].(*ast.ExprStmt)
			if !ok {
				t.Fatal("native qualification call became conditional", root)
			}
			call, ok := statement.X.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				t.Fatal("native qualification call lost its original test owner", root)
			}
			callee, ok := call.Fun.(*ast.Ident)
			argument, ordinary := call.Args[0].(*ast.Ident)
			if !ok || !ordinary || callee.Name != name || argument.Name != "t" {
				t.Fatal("native qualification replaced its complete fixture", root, name)
			}
		}
		return
	}
	t.Fatal("missing explicit native qualification wrapper", root)
}
