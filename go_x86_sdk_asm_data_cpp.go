package plan9asm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func (source *GoX86SDKASMDataSource) captureAssembly(ctx context.Context, ordinal int, name string) (gostaticstorage.SDKASMDataSource, AssemblyCPPObservation, error) {
	var result gostaticstorage.SDKASMDataSource
	var cpp AssemblyCPPObservation
	if filepath.Base(name) != name {
		return result, cpp, sdkASMDataContext("selected ASM escaped its exact package-local route")
	}
	file := filepath.Join(source.request.Directory, name)
	raw, err := source.guard.read(file)
	if err != nil {
		return result, cpp, err
	}
	cpp, positions, err := observeSDKAssemblyCPP(string(raw), AssemblyPreprocessOptions{FileName: file,
		Defines:     GoAssemblerDefinesWithEnv(source.guard.env["GOOS"], source.guard.env["GOARCH"], source.guard.env),
		ReadInclude: source.readAssemblyInclude})
	if err != nil {
		return result, cpp, err
	}
	source.observation.Positions = append(source.observation.Positions, positions)
	expanded, err := source.artifact(fmt.Sprintf("expanded-%d.s", ordinal), []byte(positions.Mapped))
	if err != nil {
		return result, cpp, err
	}
	originalObject := filepath.Join(source.guard.owned, fmt.Sprintf("original-%d.o", ordinal))
	expandedObject := filepath.Join(source.guard.owned, fmt.Sprintf("expanded-%d.o", ordinal))
	for _, command := range [][2]string{{file, originalObject}, {expanded, expandedObject}} {
		args := append(source.asmArguments(source.guard.owned), "-o", command[1], command[0])
		if _, err := source.run(ctx, args...); err != nil {
			return result, cpp, err
		}
	}
	originalBytes, err := source.guard.read(originalObject)
	if err != nil {
		return result, cpp, err
	}
	expandedBytes, err := source.guard.read(expandedObject)
	if err != nil {
		return result, cpp, err
	}
	return gostaticstorage.SDKASMDataSource{Name: name, Original: raw, Expanded: []byte(cpp.Output),
		OriginalObject: originalBytes, ExpandedObject: expandedBytes}, cpp, nil
}

// cmd/asm keeps its original CWD and fixed include roots for nested headers;
// the including header's directory does not become a new lookup origin.
func (source *GoX86SDKASMDataSource) readAssemblyInclude(_ string, header string) (string, []byte, error) {
	if source.closePending || source.generation != 0 {
		return "", nil, sdkASMDataContext("include input query is outside its unpublished capture lifetime")
	}
	relative := filepath.Base(header) != header
	if relative {
		if !sourcepath.CPPLocalSource(header) {
			return "", nil, sdkASMDataContext("relative/foreign include escaped its canonical SDK source route")
		}
		if err := source.verifySDKDirectory(); err != nil {
			return "", nil, sdkASMDataContext("relative/foreign include needs its exact SDK package: %v", err)
		}
		if err := source.verifyDirectories(); err != nil {
			return "", nil, err
		}
	}
	for _, directory := range []string{source.request.Directory, source.guard.owned,
		filepath.Join(source.guard.env["GOROOT"], "pkg", "include")} {
		candidate := filepath.Join(directory, filepath.FromSlash(header))
		_, err := os.Lstat(candidate)
		if os.IsNotExist(err) {
			source.misses[candidate] = true
			continue
		}
		if err != nil {
			return "", nil, err
		}
		if header == "go_asm.h" && directory != source.guard.owned {
			return "", nil, sdkASMDataContext("generated header is not the observed compiler artifact")
		}
		if relative {
			inventory := source.guard.directoryInventory
			if directory == source.guard.owned || inventory == nil {
				return "", nil, sdkASMDataContext("relative/foreign include has no selected SDK source origin")
			}
			physical, err := sourcepath.CPPRegularSource(directory, header)
			if err != nil || physical != candidate {
				return "", nil, sdkASMDataContext("relative SDK include identity: %v", err)
			}
			for parent := filepath.Dir(candidate); ; parent = filepath.Dir(parent) {
				before := source.directories[parent]
				after, err := os.Lstat(parent)
				if err != nil || before != nil && !os.SameFile(before, after) {
					return "", nil, sdkASMDataContext("relative SDK include parent identity changed")
				}
				// Observe membership without reading unrelated child contents.
				// The existing source graph owns all file/directory/byte budgets.
				if err := inventory.Directory(parent, false); err != nil {
					return "", nil, sdkASMDataContext("relative SDK include directory: %v", err)
				}
				if err := source.retainDirectory(parent); err != nil {
					return "", nil, err
				}
				if parent == directory {
					break
				}
			}
			if err := inventory.Retain(candidate); err != nil {
				return "", nil, sdkASMDataContext("relative SDK header source: %v", err)
			}
		}
		data, err := source.guard.read(candidate)
		return candidate, data, err
	}
	return "", nil, sdkASMDataContext("active header has no exact SDK/compiler source route")
}
