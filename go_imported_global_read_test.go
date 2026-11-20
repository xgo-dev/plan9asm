package plan9asm

import (
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/xgo-dev/llvm"
)

func importedGlobalPackage(t *testing.T, path, arch string, sources []string, imports map[string]*types.Package) GoPackage {
	t.Helper()
	set := token.NewFileSet()
	files := make([]*ast.File, len(sources))
	for index, source := range sources {
		file, err := parser.ParseFile(set, fmt.Sprintf("input%d.go", index), source, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		files[index] = file
	}
	config := types.Config{Importer: goReadOnlyImporter(imports), Sizes: types.SizesFor("gc", arch)}
	typed, err := config.Check(path, set, files, nil)
	if err != nil {
		t.Fatal(err)
	}
	actualImports := make(map[string]*types.Package)
	for _, dependency := range typed.Imports() {
		actualImports[dependency.Path()] = dependency
	}
	return GoPackage{Path: path, Types: typed, Syntax: files, Imports: actualImports}
}

func importedGlobalConsumer(t *testing.T, owner GoPackage, name, arch string) GoPackage {
	t.Helper()
	consumer := importedGlobalPackage(t, "example.com/globalconsumer", arch, []string{
		"package globalconsumer\nimport dep " + fmt.Sprintf("%q", owner.Path) +
			"\nvar _ = dep." + name + "\nvar Flags bool\nfunc view() uint32\n",
	}, map[string]*types.Package{owner.Path: owner.Types})
	consumer.ImportSyntax = map[string][]*ast.File{owner.Path: owner.Syntax}
	return consumer
}

func importedGlobalOperand(path, name string, offset int64) string {
	// Stock Go's assembler spells package-path punctuation as identifier
	// characters; a literal dot would terminate the symbol token.
	path = strings.NewReplacer("/", "∕", ".", "·").Replace(path)
	return fmt.Sprintf("%s·%s+%d(SB)", path, name, offset)
}

func importedGlobalReadRequest(t *testing.T, pkg GoPackage, source []byte, arch, triple, api string, preprocessed bool,
	configure func(*GoModuleOptions),
) (string, error) {
	t.Helper()
	options := GoModuleOptions{GOOS: "linux", GOARCH: arch, TargetTriple: triple,
		Sizes: types.SizesFor("gc", arch), FrameSizes: types.SizesFor("gc", arch),
		SourcePreprocessed: preprocessed, ResolveSym: testResolveSym(pkg.Path)}
	if configure != nil {
		configure(&options)
	}
	var result *GoModuleTranslation
	var err error
	if api == "public" {
		result, err = TranslateGoModule(pkg, source, options)
	} else {
		if api != "owned-context" {
			t.Fatal("unknown imported global test API", api)
		}
		ctx := llvm.NewContext()
		defer ctx.Dispose()
		result, err = translateGoModuleInContext(ctx, pkg, source, options)
		if result != nil {
			defer result.Module.Dispose()
			if err == nil {
				if verify := llvm.VerifyModule(result.Module, llvm.ReturnStatusAction); verify != nil {
					t.Fatal("invalid imported-global LLVM module", verify)
				}
			}
			return result.Module.String(), err
		}
		return "", err
	}
	if result == nil {
		return "", err
	}
	defer result.Module.Dispose()
	if err == nil {
		if verify := llvm.VerifyModule(result.Module, llvm.ReturnStatusAction); verify != nil {
			t.Fatal("invalid imported-global LLVM module", verify)
		}
	}
	return result.Module.String(), err
}

func importedGlobalRequireMutable(t *testing.T, ir, native string) {
	t.Helper()
	if !strings.Contains(ir, "load volatile i8") || !strings.Contains(ir, "br i1") {
		t.Fatal("imported comparison lost its exact mutable read or observable predicate", ir)
	}
	for _, line := range strings.Split(ir, "\n") {
		if strings.HasPrefix(line, "@\""+native+"\" = ") || strings.HasPrefix(line, "@"+native+" = ") {
			if !strings.Contains(line, " = external global ") {
				t.Fatal("Go-owned numerical storage became DATA, a definition or a constant", line)
			}
			return
		}
	}
	t.Fatal("missing actual imported native declaration", native, ir)
}

// ImportDir selects files directly using go/build, not a subprocess or go list.
// Recheck every selected CPU Go file, including real self-linkname directives;
// do not manufacture a struct from the assembly's observed offsets.
func importedGlobalSelectedCPU(t *testing.T) GoPackage {
	t.Helper()
	context := build.Default
	context.GOROOT, context.GOOS, context.GOARCH = runtime.GOROOT(), "linux", "amd64"
	context.CgoEnabled = false
	context.ToolTags = nil
	for _, tag := range build.Default.ToolTags {
		if !strings.HasPrefix(tag, build.Default.GOARCH+".") && !strings.HasPrefix(tag, "amd64.") {
			context.ToolTags = append(context.ToolTags, tag) // Preserve selected Go experiments and other non-ISA tags.
		}
	}
	context.ToolTags = append(context.ToolTags, "amd64.v1")
	directory := filepath.Join(context.GOROOT, "src", "internal", "cpu")
	selected, err := context.ImportDir(directory, 0)
	if err != nil || len(selected.GoFiles) == 0 {
		t.Fatal("missing actual selected SDK CPU source", err)
	}
	var sources []string
	for _, name := range selected.GoFiles {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		sources = append(sources, string(data))
	}
	return importedGlobalPackage(t, "internal/cpu", "amd64", sources, map[string]*types.Package{"unsafe": types.Unsafe})
}

func TestGoModuleImportedGlobalReadSelectedCPU(t *testing.T) {
	owner := importedGlobalSelectedCPU(t)
	variable, ok := owner.Types.Scope().Lookup("X86").(*types.Var)
	if !ok {
		t.Fatal("selected CPU source lacks its actual X86 variable")
	}
	structure, ok := variable.Type().Underlying().(*types.Struct)
	if !ok {
		t.Fatal("selected CPU X86 is not its actual struct")
	}
	fields := make([]*types.Var, structure.NumFields())
	for index := range fields {
		fields[index] = structure.Field(index)
	}
	offsets := types.SizesFor("gc", "amd64").Offsetsof(fields)
	for _, candidate := range []struct{ file, field string }{
		{"count_amd64.s", "HasPOPCNT"}, {"index_amd64.s", "HasSSE42"},
		{"indexbyte_amd64.s", "HasAVX2"}, {"equal_amd64.s", "HasAVX2"},
	} {
		offset := int64(-1)
		for index, field := range fields {
			if field.Name() == candidate.field && types.Identical(field.Type(), types.Typ[types.Bool]) {
				offset = offsets[index]
			}
		}
		if offset < 0 {
			t.Fatal("missing actual selected numerical CPU field", candidate.field)
		}
		for _, api := range []string{"public", "owned-context"} {
			for _, preprocessed := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/preprocessed=%t", candidate.file, api, preprocessed), func(t *testing.T) {
					pkg := importedGlobalConsumer(t, owner, "X86", "amd64")
					source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "X86", offset)+",$1\n")
					ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", api, preprocessed, nil)
					if err != nil || ir == "" {
						t.Fatal("actual loaded CPU declarations did not establish the bounded numeric read", err)
					}
					importedGlobalRequireMutable(t, ir, "internal/cpu.X86")
				})
			}
		}
	}
	t.Log("four CPU comparison sites with actual selected SDK types/syntax; independent ABI0 regression, not successful whole-bytealg/ABIInternal execution")
}

func TestGoModuleImportedGlobalReadOrdinaryPackages(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		for _, self := range []bool{false, true} {
			declarations := "package state\nvar Flags bool\n"
			if self {
				declarations = "package state\nimport _ \"unsafe\"\n//go:linkname Flags\nvar Flags bool\n"
			}
			owner := importedGlobalPackage(t, "example.com/state", arch, []string{declarations}, map[string]*types.Package{"unsafe": types.Unsafe})
			for _, api := range []string{"public", "owned-context"} {
				t.Run(fmt.Sprintf("%s/self=%t/%s", arch, self, api), func(t *testing.T) {
					pkg := importedGlobalConsumer(t, owner, "Flags", arch)
					source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 0)+",$0\n")
					triple := "x86_64-unknown-linux-gnu"
					if arch == "386" {
						triple = "i386-unknown-linux-gnu"
					}
					ir, err := importedGlobalReadRequest(t, pkg, source, arch, triple, api, true, nil)
					if err != nil || ir == "" {
						t.Fatal("ordinary imported numerical declaration was treated as a CPU whitelist", err)
					}
					importedGlobalRequireMutable(t, ir, owner.Path+".Flags")
				})
			}
		}
	}
}

func TestGoModuleImportedGlobalReadDistinctNamespaces(t *testing.T) {
	owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{
		"package state\nvar Flags struct { _ [3]byte; Ready bool }\n",
	}, nil)
	for _, main := range []bool{false, true} {
		t.Run(fmt.Sprint("linked-main=", main), func(t *testing.T) {
			pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
			if main {
				pkg.Path = "main" // Legitimate linked namespace distinct from Types.Path().
			}
			source := ordinaryGlobalReadAssembly("CMPB ·Flags(SB),$0\n", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 3)+",$0\n")
			ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true, nil)
			if err != nil || ir == "" {
				t.Fatal("local/imported variables with equal names were conflated", err)
			}
			importedGlobalRequireMutable(t, ir, owner.Path+".Flags")
			importedGlobalRequireMutable(t, ir, pkg.Path+".Flags")
			if strings.Count(ir, "load volatile i8") != 2 {
				t.Fatal("the two actual numerical reads did not remain distinct", ir)
			}
		})
	}
}

func TestGoModuleImportedGlobalReadTypedDependencies(t *testing.T) {
	dependency := importedGlobalPackage(t, "example.com/numeric", "amd64", []string{
		"package numeric\ntype Byte uint8\n",
	}, nil)
	owner := importedGlobalPackage(t, "example.com/state", "amd64", []string{
		"package state\nimport \"example.com/numeric\"\nvar Flags numeric.Byte\n",
	}, map[string]*types.Package{dependency.Path: dependency.Types})
	pkg := importedGlobalConsumer(t, owner, "Flags", "amd64")
	if len(pkg.Imports) != 1 || pkg.Imports[dependency.Path] != nil {
		t.Fatal("fixture accidentally flattened imported-package dependencies into the caller")
	}
	source := ordinaryGlobalReadAssembly("", "CMPB "+importedGlobalOperand(owner.Path, "Flags", 0)+",$0\n")
	ir, err := importedGlobalReadRequest(t, pkg, source, "amd64", "x86_64-unknown-linux-gnu", "owned-context", true, nil)
	if err != nil || ir == "" {
		t.Fatal("import syntax did not use its own actual complete typed dependencies", err)
	}
	importedGlobalRequireMutable(t, ir, owner.Path+".Flags")
}
