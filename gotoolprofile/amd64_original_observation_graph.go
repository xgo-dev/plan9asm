package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/modfile"
)

type amd64OriginalListModule struct {
	Path, Version, Dir, GoMod, GoVersion string
	Main                                 bool
	Replace                              *amd64OriginalListModule
}

type amd64OriginalListPackage struct {
	instrumentationTypeListPackage
	Standard bool
	Module   *amd64OriginalListModule
}

func captureAMD64OriginalGraph(ctx context.Context, request AMD64OriginalObservationRequest, actual map[string]string, profile *Observation, files *amd64OriginalObservationFiles, downloaded *amd64DownloadedSources, export bool, run Runner) (map[string]amd64OriginalListPackage, error) {
	args := []string{"list", "-deps", "-compiled", "-json", "-mod=readonly"}
	if export {
		args = append(args, "-export")
	}
	stdout, stderr, err := downloaded.runList(ctx, request, run, append(args, request.PackagePath)...)
	if err != nil || len(stderr) != 0 || len(stdout) == 0 || len(stdout) > commandOutputLimit {
		return nil, fmt.Errorf("actual original Go graph failed: %v; %s", err, stderr)
	}
	packages := make(map[string]amd64OriginalListPackage)
	decoder := json.NewDecoder(bytes.NewReader(stdout))
	for {
		var pkg amd64OriginalListPackage
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if len(packages) >= 4096 || pkg.ImportPath == "" || !token.IsIdentifier(pkg.Name) || pkg.Name == "_" {
			return nil, fmt.Errorf("invalid or over-bound original package graph")
		}
		if _, duplicate := packages[pkg.ImportPath]; duplicate {
			return nil, fmt.Errorf("duplicate original package graph member")
		}
		if pkg.Incomplete || len(pkg.Error)+len(pkg.DepsErrors) != 0 || pkg.ForTest != "" ||
			len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.EmbedFiles)+len(pkg.EmbedPatterns) != 0 {
			return nil, fmt.Errorf("%w: original observation has unknown/native/generated/test/embed roles", plan9asm.ErrProbeNeedsContext)
		}
		packages[pkg.ImportPath] = pkg
	}
	selected, present := packages[request.PackagePath]
	legacy := downloaded != nil && downloaded.primary.legacy()
	if !present || selected.Standard || selected.Module == nil || selected.Module.Replace != nil ||
		!legacy && (!selected.Module.Main || selected.Module.Version != "") {
		return nil, fmt.Errorf("%w: original observation needs an owned main, not external/foreign/SDK source identity", plan9asm.ErrProbeNeedsContext)
	}
	module := selected.Module
	root, err := sourcepath.Resolve(module.Dir)
	if err != nil {
		return nil, err
	}
	for _, forbidden := range []string{actual["GOROOT"], originalObservationEnvironment(request.Environment, "GOMODCACHE")} {
		physical, err := sourcepath.Resolve(forbidden)
		if err != nil {
			return nil, err
		}
		if relative, err := filepath.Rel(physical, root); err == nil && filepath.IsLocal(relative) {
			if downloaded != nil && forbidden != actual["GOROOT"] && downloaded.primary.matchesPrimary(module) {
				continue
			}
			return nil, fmt.Errorf("%w: cached external or SDK source cannot acquire an owned-main role", plan9asm.ErrProbeNeedsContext)
		}
	}
	if downloaded != nil && !downloaded.primary.matchesPrimary(module) {
		return nil, fmt.Errorf("actual primary source differs from the exact original download handoff")
	}
	goMod, err := sourcepath.Resolve(module.GoMod)
	wantedGoMod := filepath.Join(root, "go.mod")
	if legacy {
		wantedGoMod = downloaded.primary.goMod
	}
	if err != nil || goMod != wantedGoMod {
		return nil, fmt.Errorf("actual main module lost its original go.mod")
	}
	if err := files.retain(goMod); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(goMod)
	if err != nil {
		return nil, err
	}
	parsed, err := modfile.Parse(goMod, data, nil)
	if err != nil || parsed.Module == nil || parsed.Module.Mod.Path != module.Path {
		return nil, fmt.Errorf("actual main module declaration differs from Go selection")
	}
	declaredVersion := ""
	if parsed.Go != nil {
		declaredVersion = parsed.Go.Version
	}
	if gooriginalsrc.SelectedGoVersion(declaredVersion, !legacy) != module.GoVersion {
		return nil, fmt.Errorf("%w: actual module language is not closed by its original go.mod", plan9asm.ErrProbeNeedsContext)
	}
	if err := files.directory(root, false); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(root, "go.sum")); !os.IsNotExist(err) {
		if err := files.retain(filepath.Join(root, "go.sum")); err != nil {
			return nil, err
		}
	}
	for path, pkg := range packages {
		base, relative := filepath.Join(actual["GOROOT"], "src"), path
		if pkg.Module != nil {
			if pkg.Standard {
				return nil, fmt.Errorf("SDK package acquired a module source role")
			}
			base = root
			if downloaded != nil {
				source, err := downloaded.module(pkg.Module)
				if err != nil {
					return nil, err
				}
				base = source.root
			} else if !reflect.DeepEqual(pkg.Module, module) {
				return nil, fmt.Errorf("%w: foreign/replaced module source needs authenticated handoff", plan9asm.ErrProbeNeedsContext)
			}
			relative = strings.TrimPrefix(path, pkg.Module.Path+"/")
			if path == pkg.Module.Path {
				relative = "."
			} else if relative == path {
				return nil, fmt.Errorf("main package path does not match its actual module directory")
			}
		} else if !pkg.Standard {
			return nil, fmt.Errorf("%w: dependency has no actual stock-stdlib/module role", plan9asm.ErrProbeNeedsContext)
		}
		if !filepath.IsLocal(filepath.FromSlash(relative)) {
			return nil, fmt.Errorf("original package path escapes its actual source root")
		}
		dir, err := sourcepath.Resolve(pkg.Dir)
		wanted, wantedErr := sourcepath.Resolve(filepath.Join(base, filepath.FromSlash(relative)))
		if err != nil || wantedErr != nil || dir != wanted {
			return nil, fmt.Errorf("original package physical directory does not match actual source identity")
		}
		goFiles := instrumentationTypeNames(pkg.GoFiles, dir, base)
		compiled := instrumentationTypeNames(pkg.CompiledGoFiles, dir, base)
		if path == "unsafe" && pkg.Module == nil && pkg.Name == "unsafe" {
			compiled = goFiles // cmd/go does not compile the builtin package.
		}
		if goFiles == nil || len(goFiles) == 0 || !reflect.DeepEqual(goFiles, compiled) || len(goFiles) > 32768 {
			return nil, fmt.Errorf("%w: original graph lacks complete ordinary compiler files", plan9asm.ErrProbeNeedsContext)
		}
		if err := retainAMD64OriginalPackageDirectory(pkg, dir, files); err != nil {
			return nil, err
		}
		if err := replayAMD64OriginalSelection(pkg, dir, profile); err != nil {
			return nil, err
		}
		if pkg.Standard {
			if err := captureAMD64OriginalSDKDependency(pkg, actual["GOROOT"], profile, files); err != nil {
				return nil, err
			}
		} else {
			// Use the verified physical directory for relative CPP paths. The
			// packages map retains Go's original spelling for later replay.
			pkg.Dir = dir
			if err := captureAMD64OriginalCPP(pkg, base, actual["GOROOT"], profile, files); err != nil {
				return nil, err
			}
		}
		if export && path != "unsafe" {
			cache, cacheErr := sourcepath.Resolve(actual["GOCACHE"])
			resolved, resolveErr := sourcepath.Resolve(pkg.Export)
			rel, relErr := filepath.Rel(cache, resolved)
			if cacheErr != nil || resolveErr != nil || relErr != nil || !filepath.IsLocal(rel) {
				return nil, fmt.Errorf("original actual export is missing or outside its bound cache")
			}
			if err := files.retain(pkg.Export); err != nil {
				return nil, err
			}
		}
		for _, imported := range pkg.Imports {
			if _, present := packages[imported]; !present {
				return nil, fmt.Errorf("original graph omitted an actual import/export")
			}
		}
		for _, imported := range pkg.ImportMap {
			if _, present := packages[imported]; !present {
				return nil, fmt.Errorf("original graph has an unbound ImportMap target")
			}
		}
	}
	selectedDir, err := sourcepath.Resolve(selected.Dir)
	requestedDir, requestErr := sourcepath.Resolve(request.Directory)
	if err != nil || requestErr != nil || selectedDir != requestedDir || len(selected.SFiles) == 0 {
		return nil, fmt.Errorf("original selected assembly package differs from the requested directory")
	}
	return packages, nil
}

func equalAMD64OriginalSelections(a, b map[string]amd64OriginalListPackage) bool {
	withoutExports := make(map[string]amd64OriginalListPackage, len(b))
	for path, pkg := range b {
		pkg.Export = ""
		withoutExports[path] = pkg
	}
	return reflect.DeepEqual(a, withoutExports)
}

func checkAMD64OriginalDeclarations(packages map[string]amd64OriginalListPackage, path string) (map[string]string, error) {
	pkg := packages[path]
	set := token.NewFileSet()
	var syntax []*ast.File
	for _, name := range pkg.CompiledGoFiles {
		if !filepath.IsAbs(name) {
			name = filepath.Join(pkg.Dir, name)
		}
		file, err := parser.ParseFile(set, name, nil, parser.ParseComments)
		if err != nil {
			return nil, err
		}
		syntax = append(syntax, file)
	}
	actualImporter := importer.ForCompiler(set, "gc", func(path string) (io.ReadCloser, error) {
		if target, mapped := pkg.ImportMap[path]; mapped {
			path = target
		}
		dependency, present := packages[path]
		if !present || dependency.Export == "" {
			return nil, fmt.Errorf("missing actual selected compiler export: %s", path)
		}
		return os.Open(dependency.Export)
	})
	version := "go" + pkg.Module.GoVersion // Independently matched to original go.mod.
	if pkg.Module.GoVersion == "" {
		version = "go1.16" // Actual dependency default, not the query main's language.
	}
	typed, err := (&types.Config{Importer: actualImporter, Sizes: types.SizesFor("gc", "amd64"), GoVersion: version}).Check(path, set, syntax, nil)
	if err != nil {
		return nil, fmt.Errorf("original full compiler-source typecheck failed: %w", err)
	}
	declarations := make(map[string]string)
	for _, file := range syntax {
		for _, declaration := range file.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil && function.Body == nil {
				object := typed.Scope().Lookup(function.Name.Name)
				if object == nil {
					return nil, fmt.Errorf("original assembly declaration lacks its actual checked type")
				}
				declarations[function.Name.Name] = types.TypeString(object.Type(), func(p *types.Package) string { return p.Path() })
			}
		}
	}
	return declarations, nil
}

func originalObservationEnvironment(env []string, key string) string {
	for _, item := range env {
		if strings.HasPrefix(item, key+"=") {
			return strings.TrimPrefix(item, key+"=")
		}
	}
	return ""
}

func replayAMD64OriginalSelection(pkg amd64OriginalListPackage, directory string, profile *Observation) error {
	selection, err := ordinaryPackageSelectionContext(&ConsumerInput{Observed: profile}, nil)
	if err != nil {
		return err
	}
	selection.OpenFile = nil // MatchFile consumes the guarded actual source.
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	var goFiles, asmFiles []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" && filepath.Ext(name) != ".s" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		selected, err := selection.MatchFile(directory, name)
		if err != nil {
			return err
		}
		if !selected {
			continue
		}
		if filepath.Ext(name) == ".s" {
			asmFiles = append(asmFiles, name)
			continue
		}
		source, err := parser.ParseFile(token.NewFileSet(), filepath.Join(directory, name), nil, parser.ImportsOnly)
		if err != nil || source.Name.Name != pkg.Name {
			return fmt.Errorf("original package clause/import source differs from actual Go")
		}
		for _, imported := range source.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil || path == "C" {
				return fmt.Errorf("%w: original source has an unclosed CGO import role", plan9asm.ErrProbeNeedsContext)
			}
		}
		goFiles = append(goFiles, name)
	}
	if !equalDiscoveryStrings(goFiles, pkg.GoFiles) || !equalDiscoveryStrings(asmFiles, pkg.SFiles) {
		return fmt.Errorf("actual original Go/ASM selection differs from independent full-directory replay")
	}
	return nil
}
