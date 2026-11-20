package plan9asm

import (
	"errors"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func ordinaryGlobalLineMapPackage(t *testing.T, source, arch string, imported bool) (GoPackage, GoPackage, string) {
	t.Helper()
	owner := importedGlobalPackage(t, "example.com/linemapped", arch,
		[]string{source, "package state\nfunc view() uint32\n"}, map[string]*types.Package{"unsafe": types.Unsafe})
	if imported {
		return importedGlobalConsumer(t, owner, "Flags", arch), owner, importedGlobalOperand(owner.Path, "Flags", 0)
	}
	return owner, owner, "·Flags(SB)"
}

func ordinaryGlobalLineMapObjects(t *testing.T, source string) {
	t.Helper()
	llc := findLLVM22Tool("llc")
	if llc == "" {
		t.Fatal("LLVM22 llc required")
	}
	for _, arch := range []string{"386", "amd64"} {
		triple := "x86_64-unknown-linux-gnu"
		if arch == "386" {
			triple = "i386-unknown-linux-gnu"
		}
		for _, ownerKind := range []string{"same-package", "direct-import"} {
			for _, api := range []string{"public", "owned-context"} {
				t.Run(arch+"/"+ownerKind+"/"+api, func(t *testing.T) {
					pkg, owner, operand := ordinaryGlobalLineMapPackage(t, source, arch, ownerKind == "direct-import")
					assembly := ordinaryGlobalReadAssembly("", "CMPB "+operand+",$0\n")
					ir, err := importedGlobalReadRequest(t, pkg, assembly, arch, triple, api, true, nil)
					if err != nil || ir == "" {
						t.Fatal("diagnostic line mapping changed actual Go storage ownership", err)
					}
					importedGlobalRequireMutable(t, ir, owner.Path+".Flags")
					if strings.Contains(ir, "@foreign.Flags") || strings.Contains(ir, "@\"foreign.Flags\"") {
						t.Fatal("diagnostic filename became the native storage namespace")
					}
					compileLLVMToObject(t, llc, triple, "line-map.ll", "line-map.o", ir)
				})
			}
		}
	}
}

func TestGoModuleOrdinaryGlobalSourceLineMaps(t *testing.T) {
	// cmd/compile's Line Directives specify diagnostic coordinates only.
	// Both forms retain their actual complete syntax and typed package owner.
	for name, directive := range map[string]string{"slash": "//line imaginary/foreign.go:71:9\n", "block": "/*line imaginary/foreign.go:71:9*/"} {
		t.Run(name, func(t *testing.T) {
			ordinaryGlobalLineMapObjects(t, "package state\n"+directive+"var Flags bool\n")
		})
	}
}

func TestGoModuleOrdinaryGlobalActualCoverSource(t *testing.T) {
	dir := t.TempDir()
	input, output := filepath.Join(dir, "original.go"), filepath.Join(dir, "instrumented.go")
	source := "package state\nvar Flags bool\nfunc Flip(value bool) bool { Flags = value; return Flags }\n"
	if err := os.WriteFile(input, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"),
		"tool", "cover", "-mode=count", "-var=LineMapCoverage", "-o", output, input)
	command.Dir = dir
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if diagnostics, err := runtimeOracleCombinedOutput(ctx, command); err != nil {
		t.Fatalf("actual selected Go coverage instrumentation failed: %v\n%s", err, diagnostics)
	}
	generated, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(generated), "//line ") || !strings.Contains(string(generated), "LineMapCoverage.Count") {
		t.Fatal("actual cover output lacks its source mapping or executed-statement counters")
	}
	owner := importedGlobalPackage(t, "example.com/linemapped", "amd64", []string{string(generated)}, nil)
	if owner.Types.Scope().Lookup("LineMapCoverage") == nil {
		t.Fatal("the generated coverage declaration was removed before type checking")
	}
	ordinaryGlobalLineMapObjects(t, string(generated))
}

func TestGoModuleOrdinaryGlobalLineMapRetainsOwnerBoundaries(t *testing.T) {
	const directive = "//line imaginary/foreign.go:71:9\n"
	for _, mutation := range []string{"linkname", "typed-import", "layout", "filename-as-symbol", "resolver", "invalid-line"} {
		t.Run(mutation, func(t *testing.T) {
			source := "package state\n" + directive + "var Flags bool\n"
			if mutation == "linkname" {
				source = "package state\nimport _ \"unsafe\"\n" + directive + "//go:linkname Flags foreign.Flags\nvar Flags bool\n"
			}
			pkg, owner, operand := ordinaryGlobalLineMapPackage(t, source, "amd64", true)
			switch mutation {
			case "typed-import":
				_, other, _ := ordinaryGlobalLineMapPackage(t, source, "amd64", true)
				pkg.Imports[owner.Path] = other.Types
			case "layout":
				_, other, _ := ordinaryGlobalLineMapPackage(t, strings.Replace(source, "bool", "uint64", 1), "amd64", true)
				pkg.ImportSyntax[owner.Path] = other.Syntax
			case "filename-as-symbol":
				operand = "foreign·Flags(SB)"
			case "invalid-line":
				comment := owner.Syntax[0].Comments[0].List[0]
				comment.Text = "//line imaginary/foreign.go:0"
				formatted, err := goReadOnlySyntax(owner)
				if err != nil {
					t.Fatal(err)
				}
				_, parseErr := parser.ParseFile(token.NewFileSet(), "snapshot.go", formatted[0], parser.ParseComments)
				t.Logf("post-parse slash comment: formatted=%q parse error=%v", formatted[0], parseErr)
				// An AST comment has no retained physical line coordinates here:
				// a formatted //line may no longer start a line. The block form
				// remains a directive at any position; prove the actual snapshot
				// is invalid before asking the binder to reject it.
				comment.Text = "/*line imaginary/foreign.go:0*/"
				formatted, err = goReadOnlySyntax(owner)
				if err != nil {
					t.Fatal(err)
				}
				_, parseErr = parser.ParseFile(token.NewFileSet(), "snapshot.go", formatted[0], parser.ParseComments)
				if parseErr == nil || !strings.Contains(parseErr.Error(), "invalid line number: 0") {
					t.Fatalf("negative snapshot lacks an active invalid directive: %q: %v", formatted[0], parseErr)
				}
			}
			assembly := ordinaryGlobalReadAssembly("", "CMPB "+operand+",$0\n")
			ir, err := importedGlobalReadRequest(t, pkg, assembly, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true,
				func(options *GoModuleOptions) {
					if mutation == "resolver" {
						resolve := options.ResolveSym
						options.ResolveSym = func(symbol string) string {
							if resolve(symbol) == owner.Path+".Flags" {
								return "foreign.Flags"
							}
							return resolve(symbol)
						}
					}
				})
			if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("line mapping lent alias, import, layout or symbol authority", err)
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalLineMapInvalidOriginalSource(t *testing.T) {
	for name, directive := range map[string]string{"slash": "//line imaginary/foreign.go:0\n", "block": "/*line imaginary/foreign.go:0*/"} {
		t.Run(name, func(t *testing.T) {
			// Original invalid directives fail before a typed package exists;
			// this is distinct from a subsequently mutated AST comment.
			source := "package state\n" + directive + "var Flags bool\n"
			_, err := parser.ParseFile(token.NewFileSet(), "original.go", source, parser.ParseComments)
			if err == nil || !strings.Contains(err.Error(), "invalid line number: 0") {
				t.Fatal("original source parser accepted an invalid line directive", err)
			}
		})
	}
}

func TestGoModuleOrdinaryGlobalLineMapMutationRevokesBinding(t *testing.T) {
	for form, directive := range map[string]string{"slash": "//line imaginary/foreign.go:71:9\n", "block": "/*line imaginary/foreign.go:71:9*/"} {
		for _, imported := range []bool{false, true} {
			name := "same-package"
			if imported {
				name = "direct-import"
			}
			t.Run(form+"/"+name, func(t *testing.T) {
				pkg, owner, operand := ordinaryGlobalLineMapPackage(t, "package state\n"+directive+"var Flags bool\n", "amd64", imported)
				file, err := Parse(ArchAMD64, string(ordinaryGlobalReadAssembly("", "CMPB "+operand+",$0\n")))
				if err != nil {
					t.Fatal(err)
				}
				binding, err := bindGoReadOnlyStorage(pkg, file, types.SizesFor("gc", "amd64"), "amd64", testResolveSym(pkg.Path))
				if err != nil || binding == nil {
					t.Fatal("actual source-mapped declaration did not bind", err)
				}
				changed := false
				for _, group := range owner.Syntax[0].Comments {
					for _, comment := range group.List {
						if strings.Contains(comment.Text, "imaginary/foreign.go") {
							comment.Text = strings.Replace(comment.Text, "foreign.go", "changed.go", 1)
							changed = true
						}
					}
				}
				if !changed {
					t.Fatal("source mapping was dropped from the original syntax snapshot")
				}
				if err := binding.verify(); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed source-mapping comment retained its old binding", err)
				}
			})
		}
	}
}
