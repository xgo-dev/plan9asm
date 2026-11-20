package plan9asm

import (
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The linker graph's genuine root is runtime, not the candidate's package.
// Unlike a declaration-only graph it may naturally contain the candidate as
// a dependency. Preserve every original row/edge, including that dependency;
// neither synthesize a package selection nor delete imports to fit the older
// declaration-root assumption. This private guard never gains a Frame role.
func (observed *GoX86SDKLiteralAlignment) bindLinkGraph(graph []byte) (map[string]goAMD64FrameSelection, error) {
	if len(graph) > 16<<20 {
		return nil, sdkASMDataContext("complete literal linker graph exceeds its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(graph))
	var root goAMD64FrameSelection
	seen := make(map[string]bool)
	matched := false
	candidateReferenced := false
	for {
		var selected goAMD64FrameSelection
		if err := decoder.Decode(&selected); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if selected.ImportPath == "" || seen[selected.ImportPath] || len(seen) >= 4096 {
			return nil, sdkASMDataContext("literal linker graph has duplicate/empty/excessive original selections")
		}
		seen[selected.ImportPath] = true
		for _, path := range selected.Imports {
			if mapped, exists := selected.ImportMap[path]; exists {
				path = mapped
			}
			if path == observed.guard.selection.ImportPath {
				candidateReferenced = true
			}
		}
		if selected.ImportPath == "runtime" {
			root = selected
		}
		if selected.ImportPath == observed.guard.selection.ImportPath {
			if !reflect.DeepEqual(selected, observed.guard.selection) {
				return nil, sdkASMDataContext("literal linker graph replaced its original SDK candidate")
			}
			matched = true
		}
	}
	if !matched || root.ImportPath != "runtime" || !root.Standard || root.Module != nil || root.nonordinaryRole() ||
		root.ForTest != "" || len(root.Error)+len(root.DepsErrors) != 0 || len(root.GoFiles) == 0 {
		return nil, sdkASMDataContext("literal linker graph lacks its actual ordinary runtime/candidate selections")
	}
	rootDirectory := filepath.Join(observed.guard.env["GOROOT"], "src", "runtime")
	physical, err := sourcepath.Resolve(root.Dir)
	if err != nil || root.Dir != rootDirectory || physical != rootDirectory {
		return nil, sdkASMDataContext("literal linker runtime source origin differs")
	}
	compiled := append([]string(nil), root.CompiledGoFiles...)
	for index, name := range compiled {
		if filepath.IsAbs(name) {
			if filepath.Dir(name) != rootDirectory {
				return nil, sdkASMDataContext("literal linker runtime generated-source mapping is unbound")
			}
			compiled[index] = filepath.Base(name)
		}
	}
	if !reflect.DeepEqual(compiled, root.GoFiles) {
		return nil, sdkASMDataContext("literal linker runtime omitted complete original compiler sources")
	}
	for _, files := range [][]string{root.GoFiles, root.SFiles, root.HFiles} {
		for _, name := range files {
			if filepath.Base(name) != name {
				return nil, sdkASMDataContext("literal linker runtime source is not an exact package-local file")
			}
			if _, err := observed.guard.read(filepath.Join(rootDirectory, name)); err != nil {
				return nil, err
			}
		}
	}
	original := observed.guard.selection
	// Select a genuine top-level row, never a synthetic package. A candidate
	// already imported by runtime cannot be the root of the declaration helper;
	// a public candidate that itself imports runtime must instead be its root.
	selectedRoot := original
	if candidateReferenced {
		selectedRoot = root
	}
	observed.guard.selection = selectedRoot
	defer func() { observed.guard.selection = original }()
	imports, err := observed.guard.bindOriginalDeclarationImports(graph)
	if err != nil {
		return nil, err
	}
	imports[selectedRoot.ImportPath] = selectedRoot
	return imports, nil
}
