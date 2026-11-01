// Package sdkfrontend shares the SDK numerical source handoff between Go
// package frontends. The package view deliberately has no x/tools dependency:
// the translator and its source observers continue to support Go 1.20.
package sdkfrontend

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/types"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// Package is a comparison view of an actual load, never source authority.
// Frontends retain the original load and supply a fresh view to each guard.
type Package struct {
	ID, Name, Path, Dir                  string
	GoFiles, CompiledGoFiles, OtherFiles []string
	Module, Test, IllTyped               bool
	Errors                               []string
	Types                                *types.Package
	Sizes                                types.Sizes
	Imports                              map[string]*Package
}

type Selection struct {
	identity string
	target   string
	types    *types.Package
	sizes    []int64
	imports  map[string]*types.Package
	env      []string
	mode     *string
	ready    bool
	graph    map[string]string
	inputs   map[string]string
	problem  error
}

func contextError(message string) error {
	return fmt.Errorf("%w: SDK numerical %s", plan9asm.ErrProbeNeedsContext, message)
}

func Identity(pkg *Package) string {
	if pkg == nil {
		return ""
	}
	canonical := func(files []string) []string {
		result := append([]string(nil), files...)
		sort.Strings(result)
		return result
	}
	imports := make(map[string]string, len(pkg.Imports))
	for path, dependency := range pkg.Imports {
		if dependency == nil {
			return ""
		}
		imports[path] = dependency.Path
	}
	encoded, err := json.Marshal(struct {
		ID, Name, Path, Dir                  string
		GoFiles, CompiledGoFiles, OtherFiles []string
		Module, Test                         bool
		Imports                              map[string]string
	}{pkg.ID, pkg.Name, pkg.Path, pkg.Dir, canonical(pkg.GoFiles), canonical(pkg.CompiledGoFiles),
		canonical(pkg.OtherFiles), pkg.Module, pkg.Test, imports})
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%x", sha256.Sum256(encoded))
}

func Sizes(sizes types.Sizes) []int64 {
	if sizes == nil {
		return nil
	}
	var values []int64
	for _, kind := range []types.BasicKind{
		types.UnsafePointer, types.Int8, types.Uint8, types.Int16, types.Uint16,
		types.Int32, types.Uint32, types.Int64, types.Uint64, types.Int, types.Uint,
		types.Float32, types.Float64,
	} {
		values = append(values, sizes.Sizeof(types.Typ[kind]))
	}
	return values
}

// CaptureSelection belongs at the actual packages.Load boundary. A selection
// retains the producer's types/environment; it cannot reconstruct a capability.
func CaptureSelection(pkg *Package, target string, environment []string, mode *string) *Selection {
	imports := make(map[string]*types.Package, len(pkg.Imports))
	for path, dependency := range pkg.Imports {
		if dependency != nil {
			imports[path] = dependency.Types
		}
	}
	ready := !pkg.Test && len(pkg.CompiledGoFiles) != 0 && reflect.DeepEqual(pkg.GoFiles, pkg.CompiledGoFiles)
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GOFLAGS=") && strings.Contains(entry, "-overlay") ||
			strings.HasPrefix(entry, "GOPACKAGESDRIVER=") && entry != "GOPACKAGESDRIVER=off" {
			ready = false
		}
	}
	selection := &Selection{identity: Identity(pkg), target: target, types: pkg.Types, sizes: Sizes(pkg.Sizes),
		imports: imports, env: append([]string(nil), environment...), mode: mode, ready: ready}
	if !pkg.Module && ready {
		var err error
		selection.graph, err = Graph(pkg)
		if err == nil {
			selection.inputs, err = GraphHashes(pkg)
		}
		selection.ready = err == nil
		selection.problem = err
	}
	return selection
}

func (selected *Selection) Environment() []string { return append([]string(nil), selected.env...) }

func Check(pkg *Package, selected *Selection, target string) error {
	if selected != nil && selected.problem != nil {
		return fmt.Errorf("SDK numerical original load inputs: %w", selected.problem)
	}
	if pkg == nil || selected == nil || !selected.ready || selected.types != pkg.Types ||
		selected.target != target || pkg.Types == nil || pkg.Sizes == nil || pkg.IllTyped || len(pkg.Errors) != 0 ||
		selected.identity == "" || selected.identity != Identity(pkg) ||
		!reflect.DeepEqual(selected.sizes, Sizes(pkg.Sizes)) || len(selected.imports) != len(pkg.Imports) {
		return contextError("actual-load identity changed")
	}
	for path, dependency := range pkg.Imports {
		if dependency == nil || dependency.Types == nil || dependency.Types != selected.imports[path] {
			return contextError("actual-load dependency types changed")
		}
	}
	if selected.graph != nil {
		graph, err := Graph(pkg)
		if err != nil || !reflect.DeepEqual(graph, selected.graph) {
			return contextError("original complete source/import graph changed")
		}
		inputs, err := GraphHashes(pkg)
		if err != nil || !reflect.DeepEqual(inputs, selected.inputs) {
			return contextError("original complete selected source bytes changed")
		}
	}
	return nil
}

func GraphHashes(pkg *Package) (map[string]string, error) {
	result := make(map[string]string)
	seen := make(map[*Package]bool)
	var visit func(*Package) error
	visit = func(current *Package) error {
		if current == nil || len(seen) >= 256 {
			return contextError("source hash graph is incomplete or unbounded")
		}
		if seen[current] {
			return nil
		}
		seen[current] = true
		if current.Path == "unsafe" && current.Types == types.Unsafe && len(current.Imports) == 0 &&
			len(current.GoFiles)+len(current.CompiledGoFiles)+len(current.OtherFiles) == 0 {
			return nil // The compiler builtin has no selected source/export files.
		}
		inputs, err := SourceHashes(current)
		if err != nil {
			return fmt.Errorf("package %s (Go=%d compiled=%d other=%d): %w", current.Path,
				len(current.GoFiles), len(current.CompiledGoFiles), len(current.OtherFiles), err)
		}
		for name, digest := range inputs {
			if existing, duplicate := result[name]; duplicate && existing != digest {
				return contextError("source hash graph has conflicting inputs")
			}
			result[name] = digest
		}
		if len(result) > 8192 {
			return contextError("complete source hash inventory is unbounded")
		}
		for _, dependency := range current.Imports {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	return result, visit(pkg)
}

func Graph(pkg *Package) (map[string]string, error) {
	graph := make(map[string]string)
	var visit func(*Package) error
	visit = func(current *Package) error {
		if current == nil || current.IllTyped || len(current.Errors) != 0 || current.Types == nil || current.Module {
			return contextError("import graph is incomplete or not standard")
		}
		identity, err := PhysicalIdentity(current)
		if err != nil {
			return err
		}
		if existing, seen := graph[current.Path]; seen {
			if existing != identity {
				return contextError("import graph has conflicting package identities")
			}
			return nil
		}
		if len(graph) >= 256 || identity == "" {
			return contextError("import graph is unbounded")
		}
		graph[current.Path] = identity
		for _, dependency := range current.Imports {
			if err := visit(dependency); err != nil {
				return err
			}
		}
		return nil
	}
	return graph, visit(pkg)
}

// Resolve a comparison projection only. Original source/type snapshots retain
// their spelling; byte-identical foreign sources cannot borrow SDK identity.
func PhysicalIdentity(pkg *Package) (string, error) {
	physical := *pkg
	var err error
	physical.Dir, err = sourcepath.Resolve(pkg.Dir)
	if err != nil {
		return "", err
	}
	for _, files := range []*[]string{&physical.GoFiles, &physical.CompiledGoFiles, &physical.OtherFiles} {
		resolved := make([]string, len(*files))
		seen := make(map[string]bool, len(resolved))
		for index, name := range *files {
			filename, err := sourcepath.Resolve(name)
			if err != nil || filepath.Dir(filename) != physical.Dir || seen[filename] {
				return "", contextError(fmt.Sprintf("selection has a missing, redirected or duplicate source: %v", err))
			}
			seen[filename], resolved[index] = true, filename
		}
		*files = resolved
	}
	return Identity(&physical), nil
}

func SourceHashes(pkg *Package) (map[string]string, error) {
	files := append(append([]string(nil), pkg.CompiledGoFiles...), pkg.OtherFiles...)
	if pkg.Path == "unsafe" && pkg.Types == types.Unsafe && len(pkg.Imports) == 0 && len(files) == 0 {
		// go/packages retains the builtin's API source but correctly reports
		// no ordinary compiled Go file. Retain that selected source as input.
		files = append([]string(nil), pkg.GoFiles...)
	}
	if len(files) == 0 || len(files) > 512 {
		return nil, contextError("selected source inventory is unbounded")
	}
	result := make(map[string]string, len(files))
	for _, name := range files {
		physical, err := sourcepath.Resolve(name)
		if err != nil {
			return nil, err
		}
		if _, duplicate := result[physical]; duplicate {
			return nil, contextError("source hash inventory has duplicate physical files")
		}
		digest, err := gotoolprofile.FileSHA256(physical)
		if err != nil {
			return nil, err
		}
		result[physical] = digest
	}
	return result, nil
}
