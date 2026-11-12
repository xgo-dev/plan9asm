package plan9asm

import (
	"errors"
	"go/ast"
	"go/types"
	"strings"
	"testing"
)

func importedGlobalRequireContext(t *testing.T, ir string, err error) {
	t.Helper()
	if ir != "" || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatalf("imported declaration expanded its numerical-read role: output=%t err=%v", ir != "", err)
	}
}

func TestGoModuleImportedGlobalReadNeedsActualDeclarations(t *testing.T) {
	for _, mutation := range []string{
		"missing-syntax", "wrong-syntax-key", "nil-file", "missing-import", "foreign-import-pointer",
		"incomplete-import", "wrong-package", "missing-variable", "different-type", "missing-type-file",
		"external-alias", "duplicate-self-linkname", "other-aliases-native", "malformed-linkname", "self-linkname-without-unsafe",
	} {
		t.Run(mutation, func(t *testing.T) {
			owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{
				"package state\nvar Flags Bit\n", "package state\ntype Bit bool\n",
			}, nil)
			pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
			switch mutation {
			case "missing-syntax":
				pkg.ImportSyntax = nil
			case "wrong-syntax-key":
				pkg.ImportSyntax = map[string][]*ast.File{"example.com/foreign": owner.Syntax}
			case "nil-file":
				pkg.ImportSyntax[owner.Path] = []*ast.File{nil}
			case "missing-import":
				delete(pkg.Imports, owner.Path)
			case "foreign-import-pointer":
				// Equal paths and layouts are not the caller's actual import identity.
				other := importedGlobalPackage(t, owner.Path, "amd64", []string{
					"package state\nvar Flags Bit\ntype Bit bool\n",
				}, nil)
				pkg.Imports[owner.Path] = other.Types
			case "incomplete-import":
				pkg.Imports[owner.Path] = types.NewPackage(owner.Path, "state")
			case "wrong-package", "missing-variable", "different-type", "external-alias",
				"duplicate-self-linkname", "other-aliases-native", "malformed-linkname", "self-linkname-without-unsafe":
				source := map[string]string{
					"wrong-package":                "package foreign\ntype Bit bool\nvar Flags Bit\n",
					"missing-variable":             "package state\ntype Bit bool\n",
					"different-type":               "package state\ntype Bit uint64\nvar Flags Bit\n",
					"external-alias":               "package state\nimport _ \"unsafe\"\ntype Bit bool\n//go:linkname Flags foreign.Flags\nvar Flags Bit\n",
					"duplicate-self-linkname":      "package state\nimport _ \"unsafe\"\ntype Bit bool\n//go:linkname Flags\n//go:linkname Flags\nvar Flags Bit\n",
					"other-aliases-native":         "package state\nimport _ \"unsafe\"\ntype Bit bool\nvar Flags Bit\n//go:linkname Shadow example.com/state.Flags\nvar Shadow Bit\n",
					"malformed-linkname":           "package state\nimport _ \"unsafe\"\ntype Bit bool\n//go:linkname Flags example.com/state.Flags extra\nvar Flags Bit\n",
					"self-linkname-without-unsafe": "package state\ntype Bit bool\n//go:linkname Flags\nvar Flags Bit\n",
				}[mutation]
				other := importedGlobalPackage(t, owner.Path, "amd64", []string{source}, map[string]*types.Package{"unsafe": types.Unsafe})
				pkg.ImportSyntax[owner.Path] = other.Syntax
			case "missing-type-file":
				pkg.ImportSyntax[owner.Path] = owner.Syntax[:1]
			}
			source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 0)+",$0\n")
			ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			importedGlobalRequireContext(t, ir, err)
		})
	}
}

func TestGoModuleImportedGlobalReadDoesNotLendOtherStorage(t *testing.T) {
	for _, row := range []struct{ name, declaration, prefix, comparison string }{
		{"wider-than-bool", "var Flags bool", "", "CMPW %s,$0\n"},
		{"past-bool", "var Flags bool", "", "CMPB %s+1(SB),$0\n"},
		{"negative-offset", "var Flags bool", "", "CMPB %s-1(SB),$0\n"},
		{"unknown-symbol", "var Flags bool", "", "CMPB example.com∕state·Missing(SB),$0\n"},
		{"pointer-storage", "var Flags *byte", "", "CMPB %s,$0\n"},
		{"string-header", "var Flags string", "", "CMPB %s,$0\n"},
		{"slice-header", "var Flags []byte", "", "CMPB %s,$0\n"},
		{"blank-field", "var Flags struct { _ byte; Ready bool }", "", "CMPB %s,$0\n"},
		{"padding", "var Flags struct { Ready bool; Word uint64 }", "", "CMPB %s+1(SB),$0\n"},
		{"cross-padding", "var Flags struct { Ready bool; Word uint64 }", "", "CMPW %s,$0\n"},
		{"mov-not-compare", "var Flags bool", "MOVB %s,CL\n", "CMPB %s,$0\n"},
		{"test-not-cmp", "var Flags bool", "TESTB $1,%s\n", "CMPB %s,$0\n"},
		{"write-not-read", "var Flags bool", "MOVB $1,%s\n", "CMPB %s,$0\n"},
		{"rmw-not-read", "var Flags bool", "INCB %s\n", "CMPB %s,$0\n"},
		{"address-not-pointer", "var Flags bool", "LEAQ %s,DX\nMOVB (DX),CL\n", "CMPB %s,$0\n"},
	} {
		t.Run(row.name, func(t *testing.T) {
			owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{
				"package state\n" + row.declaration + "\n",
			}, nil)
			pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
			operand := importedGlobalOperand(owner.Path, "Flags", 0)
			expand := func(pattern string) string {
				if strings.Contains(pattern, "%s+") || strings.Contains(pattern, "%s-") {
					return strings.ReplaceAll(pattern, "%s", strings.TrimSuffix(operand, "+0(SB)"))
				}
				return strings.ReplaceAll(pattern, "%s", operand)
			}
			source := ordinaryGlobalReadAssembly(expand(row.prefix), expand(row.comparison))
			ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			importedGlobalRequireContext(t, ir, err)
		})
	}
}

func TestGoModuleImportedGlobalReadCannotLendToRawAPI(t *testing.T) {
	owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{"package state\nvar Flags bool\n"}, nil)
	pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
	source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 0)+",$0\n")
	for _, api := range []string{"text", "module"} {
		t.Run(api, func(t *testing.T) {
			ir, err := x86ScalarFPBitViewPackageAPI(t, string(source), pkg, "amd64", "x86_64-unknown-linux-gnu", api)
			importedGlobalRequireContext(t, ir, err)
		})
	}
}

func TestGoModuleImportedGlobalReadRechecksAfterCallbacks(t *testing.T) {
	for _, mutation := range []string{"control", "syntax", "imports", "typed-dependencies", "import-syntax-map", "resolver", "original-assembly"} {
		t.Run(mutation, func(t *testing.T) {
			owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{"package state\nvar Flags bool\n"}, nil)
			pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
			other := importedGlobalPackage(t, owner.Path, "amd64", []string{"package state\nvar Flags bool\n"}, nil)
			source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 0)+",$0\n")
			called := false
			ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true, func(options *GoModuleOptions) {
				resolve := options.ResolveSym
				options.ResolveSym = func(symbol string) string {
					native := resolve(symbol)
					if mutation == "resolver" && called && native == owner.Path+".Flags" {
						return "foreign.Flags"
					}
					return native
				}
				options.KeepFunc = func(_, _ string) bool {
					called = true
					switch mutation {
					case "syntax":
						ast.Inspect(owner.Syntax[0], func(node ast.Node) bool {
							if ident, ok := node.(*ast.Ident); ok && ident.Name == "bool" {
								ident.Name = "uint8"
							}
							return true
						})
					case "imports":
						pkg.Imports[owner.Path] = other.Types
					case "typed-dependencies":
						owner.Types.SetImports([]*types.Package{types.Unsafe})
					case "import-syntax-map":
						delete(pkg.ImportSyntax, owner.Path)
					case "original-assembly":
						source[len(source)-1] = ' '
					}
					return true // A callback may not hide the requested function.
				}
			})
			if !called {
				t.Fatal("the source callback did not execute")
			}
			if mutation == "control" {
				if err != nil || ir == "" {
					t.Fatal("unmodified imported declaration callback was rejected", err)
				}
				importedGlobalRequireMutable(t, ir, owner.Path+".Flags")
			} else {
				importedGlobalRequireContext(t, ir, err)
			}
		})
	}
}
