package plan9asm

import (
	"errors"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

const numericalAliasGoModel = `package local
import _ "unsafe"
//go:linkname alias example.invalid/remote.Entry
func alias(value uint32) uint32
`

func numericalAliasLanguageModel(t *testing.T, text, packagePath string) ([]*ast.File, *types.Package) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "decl.go", text, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	files := []*ast.File{file}
	pkg, err := (&types.Config{Importer: importer.Default()}).Check(packagePath, fset, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	return files, pkg
}

func TestNumericalSDKSelfLinknameKeepsOrdinaryABI0Role(t *testing.T) {
	for _, directive := range []string{"//go:linkname alias", "//go:linkname alias example.invalid/local.alias", "//go:linknamestd alias"} {
		for _, arch := range []string{"386", "amd64"} {
			t.Run(arch+"/"+directive, func(t *testing.T) {
				text := "package local\nimport _ \"unsafe\"\n" + directive + "\nfunc alias(value uint32) uint32\n"
				files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
				names, err := numericalGoDeclarationLinknames(files, pkg)
				if err != nil {
					t.Fatal(err)
				}
				file, err := Parse(ArchAMD64, "TEXT ·alias(SB),4,$0-8\nRET\n")
				if err != nil {
					t.Fatal(err)
				}
				if len(numericalCompilerAliasDemand(file, pkg.Path(), names)) != 0 {
					t.Fatal("ordinary self-linkname acquired a new compiler-wrapper requirement")
				}
				entries, _, err := numericalTypedSourceDeclarations(file, pkg.Path(), arch, numericalSBSDKSource, names, nil)
				if err != nil || len(entries) != 1 || entries[pkg.Path()+".alias"].local != "alias" {
					t.Fatal("ordinary ABI0 declaration lost its existing source role", entries, err)
				}
				model := numericalCompilerAliasModel(false)
				model.ABI = 0
				if err := numericalCompilerAliasAssociation(model); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("ordinary role was confused with the new foreign ABI1 wrapper witness", err)
				}
			})
		}
	}
}

func TestNumericalSDKVariableAliasCannotDeclareTEXT(t *testing.T) {
	text := strings.Replace(numericalAliasGoModel, "func alias(value uint32) uint32", "var alias uint32", 1)
	files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
	names, err := numericalGoDeclarationLinknames(files, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := names.declaration("example.invalid/remote.Entry", pkg.Path(), 1,
		map[string]numericalCompilerAliasWitness{"example.invalid/remote.Entry": {ABI: 1}}); ok {
		t.Fatal("a variable directive acquired a TEXT declaration")
	}
}

func TestNumericalSDKCompilerAliasCompleteInventoryBounds(t *testing.T) {
	for _, which := range []string{"generated", "selected"} {
		model := numericalCompilerAliasModel(false)
		over := make([]gostaticstorage.TextRecord, gostaticstorage.ObjectSymbolInventoryLimit+1)
		if which == "generated" {
			model.Generated = over
		} else {
			model.Selected = over
		}
		if err := numericalCompilerAliasAssociation(model); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("oversized complete object inventory was retained", which, err)
		}
	}
}

func TestNumericalSDKLinknameCandidatesNeedCompilerAssociation(t *testing.T) {
	for _, directive := range []string{"go:linkname", "go:linknamestd"} {
		t.Run(directive, func(t *testing.T) {
			text := strings.Replace(numericalAliasGoModel, "go:linkname", directive, 1)
			files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
			names, err := numericalGoDeclarationLinknames(files, pkg)
			if err != nil {
				t.Fatal(err)
			}
			file, err := Parse(ArchAMD64, "TEXT example.invalid∕remote·Entry<ABIInternal>(SB),4,$0-12\nRET\n")
			if err != nil {
				t.Fatal(err)
			}
			for _, aliases := range []map[string]numericalCompilerAliasWitness{
				nil,
				{"example.invalid/remote.Other": {ABI: 1}},
				{"example.invalid/remote.Entry": {ABI: 0}},
				{"example.invalid/remote.Entry": {ABI: 1, Standard: directive != "go:linknamestd"}},
			} {
				if _, _, err := numericalTypedSourceDeclarations(file, pkg.Path(), "amd64", numericalSBSDKSource, names, aliases); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("candidate directive borrowed an absent/different compiler association", aliases, err)
				}
			}
			// This is only the private model's name-comparison output, not a
			// factory witness. No ready source or public binding is created.
			aliases := map[string]numericalCompilerAliasWitness{"example.invalid/remote.Entry": {ABI: 1, Standard: directive == "go:linknamestd"}}
			entries, _, err := numericalTypedSourceDeclarations(file, pkg.Path(), "amd64", numericalSBSDKSource, names, aliases)
			if err != nil || len(entries) != 1 || entries["example.invalid/remote.Entry"].local != "alias" {
				t.Fatal("matching model association lost its distinct local/native names", entries, err)
			}
		})
	}
}

func TestNumericalSDKLinknameCandidateCompleteOriginalScope(t *testing.T) {
	for name, change := range map[string]func(string) string{
		"unsafe-absent":   func(s string) string { return strings.Replace(s, "import _ \"unsafe\"\n", "", 1) },
		"unknown-local":   func(s string) string { return strings.Replace(s, "linkname alias ", "linkname missing ", 1) },
		"duplicate-local": func(s string) string { return s + "//go:linkname alias example.invalid/remote.Other\n" },
		"extra-field":     func(s string) string { return strings.Replace(s, "remote.Entry", "remote.Entry extra", 1) },
		"instantiation":   func(s string) string { return strings.Replace(s, "remote.Entry", "remote.Entry[int]", 1) },
	} {
		t.Run(name, func(t *testing.T) {
			files, pkg := numericalAliasLanguageModel(t, change(numericalAliasGoModel), "example.invalid/local")
			if _, err := numericalGoDeclarationLinknames(files, pkg); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("malformed candidate acquired a declaration role", err)
			}
		})
	}
	t.Run("duplicate-remote", func(t *testing.T) {
		text := numericalAliasGoModel + "//go:linkname other example.invalid/remote.Entry\nfunc other(value uint32) uint32\n"
		files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
		names, err := numericalGoDeclarationLinknames(files, pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, valid := names.declaration("example.invalid/remote.Entry", pkg.Path(), 1,
			map[string]numericalCompilerAliasWitness{"example.invalid/remote.Entry": {ABI: 1}}); valid {
			t.Fatal("two local declarations selected one native winner")
		}
	})
	t.Run("shadowed-ordinary", func(t *testing.T) {
		text := strings.Replace(numericalAliasGoModel, "example.invalid/remote.Entry", "example.invalid/local.Ordinary", 1) + "func Ordinary(value uint32) uint32\n"
		files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
		names, err := numericalGoDeclarationLinknames(files, pkg)
		if err != nil {
			t.Fatal(err)
		}
		if _, valid := names.declaration("example.invalid/local.Ordinary", pkg.Path(), 1,
			map[string]numericalCompilerAliasWitness{"example.invalid/local.Ordinary": {ABI: 1}}); valid {
			t.Fatal("an alias shadowed an independent ordinary declaration")
		}
	})
	t.Run("file-level-not-doc-attachment", func(t *testing.T) {
		text := strings.Replace(numericalAliasGoModel, "func alias", "var unrelated uint32\n\nfunc alias", 1)
		files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
		names, err := numericalGoDeclarationLinknames(files, pkg)
		if err != nil || names.nativeToLocal["example.invalid/remote.Entry"] != "alias" {
			t.Fatal("compiler file-level candidate became a doc attachment", err)
		}
	})
	t.Run("one-argument-native-prefix", func(t *testing.T) {
		text := strings.Replace(numericalAliasGoModel, "alias example.invalid/remote.Entry", "alias", 1)
		files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/a.b")
		names, err := numericalGoDeclarationLinknames(files, pkg)
		if err != nil || names.localToNative["alias"] != "example.invalid/a%2eb.alias" {
			t.Fatal("one-argument candidate guessed a logical rather than native package prefix", names, err)
		}
	})
	t.Run("unused-alias-does-not-rename-ordinary", func(t *testing.T) {
		text := numericalAliasGoModel + "func Ordinary(value uint32) uint32\n"
		files, pkg := numericalAliasLanguageModel(t, text, "example.invalid/local")
		names, err := numericalGoDeclarationLinknames(files, pkg)
		if err != nil {
			t.Fatal(err)
		}
		if local, valid := names.declaration("example.invalid/local.Ordinary", pkg.Path(), 1, nil); !valid || local != "Ordinary" {
			t.Fatal("unrelated ordinary declaration inherited an unused alias", local, valid)
		}
	})
}
