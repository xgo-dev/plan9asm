package plan9asm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// SDK imports supply actual compiler types, never caller-memory permissions.
// Exact downloaded modules have their own independent archive handoff;
// nonordinary compiler roles remain separate.
func (source *GoAMD64FrameSource) loadOriginalDeclarationImports(ctx context.Context) (map[string]goAMD64FrameSelection, error) {
	if len(source.selection.Imports) == 0 {
		return nil, nil
	}
	output, err := source.run(ctx, "list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", ".")
	if err != nil {
		return nil, err
	}
	if err := source.captureDownloadedDeclarationOrigins(ctx, output); err != nil {
		return nil, err
	}
	return source.bindOriginalDeclarationImports(output)
}

func (source *GoAMD64FrameSource) bindOriginalDeclarationImports(output []byte) (map[string]goAMD64FrameSelection, error) {
	return source.projectOriginalDeclarationImports(output, func(name string) (int, error) {
		data, err := source.read(name)
		return len(data), err
	})
}

// Recheck the physical graph against retained inputs. The caller must verify
// the complete input hashes in the same live operation before publishing.
func (source *GoAMD64FrameSource) recheckOriginalDeclarationImports(output []byte) (map[string]goAMD64FrameSelection, error) {
	return source.projectOriginalDeclarationImports(output, func(name string) (int, error) {
		if _, retained := source.inputs[name]; !retained {
			return 0, goAMD64FrameContext("declaration dependency is outside the original input inventory: %s", filepath.Base(name))
		}
		info, err := os.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > 64<<20 {
			return 0, goAMD64FrameContext("declaration dependency is not a bounded regular input: %s", filepath.Base(name))
		}
		return int(info.Size()), nil
	})
}

// Both capture and verification resolve the complete physical graph. The
// input observation supplies bounded extents for source and export roles.
func (source *GoAMD64FrameSource) projectOriginalDeclarationImports(output []byte, inputSize func(string) (int, error)) (map[string]goAMD64FrameSelection, error) {
	if len(output) > 16<<20 {
		return nil, goAMD64FrameContext("declaration import graph exceeds its bound")
	}
	root, err := sourcepath.Resolve(source.env["GOROOT"])
	if err != nil {
		return nil, err
	}
	cache, err := sourcepath.Resolve(source.env["GOCACHE"])
	if err != nil {
		return nil, err
	}
	graph := make(map[string]goAMD64FrameSelection)
	decoder := json.NewDecoder(bytes.NewReader(output))
	var originalFound bool
	var inputBytes, inputFiles int
	for {
		var selected goAMD64FrameSelection
		if err := decoder.Decode(&selected); err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		if selected.ImportPath == "" || len(graph) >= 4096 ||
			len(selected.Error)+len(selected.DepsErrors) != 0 || selected.ForTest != "" || selected.nonordinaryRole() {
			return nil, goAMD64FrameContext("incomplete or nonordinary declaration import graph")
		}
		if selected.ImportPath == source.selection.ImportPath {
			selected.Export, err = sourcepath.Resolve(selected.Export)
			if err != nil || originalFound || !reflect.DeepEqual(selected, source.selection) {
				return nil, goAMD64FrameContext("declaration graph lost the actual original package")
			}
			originalFound = true
			continue
		}
		if _, duplicate := graph[selected.ImportPath]; duplicate ||
			!filepath.IsLocal(filepath.FromSlash(selected.ImportPath)) {
			return nil, goAMD64FrameContext("foreign or duplicate declaration dependency needs authenticated handoff")
		}
		dir, err := sourcepath.Resolve(selected.Dir)
		var wanted string
		var wantedErr error
		if selected.Standard && selected.Module == nil {
			wanted, wantedErr = sourcepath.Resolve(filepath.Join(root, "src", filepath.FromSlash(selected.ImportPath)))
		} else {
			wanted, wantedErr = source.downloadedDeclarationDirectory(selected)
		}
		if err != nil || wantedErr != nil || dir != wanted {
			return nil, goAMD64FrameContext("actual declaration dependency escaped its original source origin: %v", wantedErr)
		}
		compiled := append([]string(nil), selected.CompiledGoFiles...)
		for index, file := range compiled {
			if filepath.IsAbs(file) {
				relative, err := filepath.Rel(dir, file)
				if err != nil || filepath.Base(relative) != relative {
					return nil, goAMD64FrameContext("generated dependency compiler sources are unbound")
				}
				compiled[index] = relative
			}
		}
		if selected.ImportPath == "unsafe" {
			compiled = selected.GoFiles // This builtin package has no compiled export.
		}
		if len(selected.GoFiles) == 0 || !reflect.DeepEqual(compiled, selected.GoFiles) {
			return nil, goAMD64FrameContext("declaration dependency omitted ordinary compiler sources")
		}
		for _, files := range [][]string{selected.GoFiles, selected.SFiles, selected.HFiles} {
			for _, file := range files {
				if filepath.Base(file) != file {
					return nil, goAMD64FrameContext("declaration dependency source is not a package-local file")
				}
				size, err := inputSize(filepath.Join(dir, file))
				if err != nil {
					return nil, err
				}
				inputBytes += size
				inputFiles++
				if inputBytes > 64<<20 || inputFiles > 32768 {
					return nil, goAMD64FrameContext("complete declaration dependency inputs exceed their bound")
				}
			}
		}
		if selected.ImportPath != "unsafe" {
			selected.Export, err = sourcepath.Resolve(selected.Export)
			if err != nil || !goAssemblyPathWithinRoot(cache, selected.Export) {
				return nil, goAMD64FrameContext("declaration compiler export is outside its actual cache")
			}
			size, err := inputSize(selected.Export)
			if err != nil || size == 0 {
				return nil, goAMD64FrameContext("declaration compiler export is empty or changed: %v", err)
			}
		}
		graph[selected.ImportPath] = selected
	}
	if !originalFound {
		return nil, goAMD64FrameContext("declaration graph omitted its original package")
	}
	for _, selected := range append([]goAMD64FrameSelection{source.selection}, frameImportGraphValues(graph)...) {
		for _, path := range selected.Imports {
			if _, present := graph[path]; !present {
				return nil, goAMD64FrameContext("declaration graph omitted an actual import")
			}
		}
		for _, target := range selected.ImportMap {
			if _, present := graph[target]; !present {
				return nil, goAMD64FrameContext("declaration graph omitted an actual import mapping")
			}
		}
	}
	return graph, nil
}

func frameImportGraphValues(graph map[string]goAMD64FrameSelection) []goAMD64FrameSelection {
	values := make([]goAMD64FrameSelection, 0, len(graph))
	for _, selected := range graph {
		values = append(values, selected)
	}
	return values
}
