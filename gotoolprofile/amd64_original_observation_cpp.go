package gotoolprofile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm"
)

// This is an observation of the actual active input stack, not a list of
// possible includes and not a generated-header or frame authority. The fixed
// original package search and registered ordinary cmd/asm defines are shared
// with the existing CPP consumer. Unclosed roles remain needs-context.
func captureAMD64OriginalCPP(pkg amd64OriginalListPackage, root, goRoot string, profile *Observation, files *amd64OriginalObservationFiles) error {
	if len(pkg.SFiles) == 0 {
		return nil
	}
	macros, err := CaptureAssemblerMacros(goRoot, profile, pkg.ImportPath)
	if err != nil {
		return err
	}
	if err := ValidateOrdinaryAssemblerMacros(macros, profile, pkg.ImportPath); err != nil {
		return fmt.Errorf("%w: original CPP package role is not closed: %v", plan9asm.ErrProbeNeedsContext, err)
	}
	for file, digest := range macros.ToolSourceSHA256 {
		name, err := CPPRegularSource(goRoot, file)
		if err != nil {
			return err
		}
		if err := files.retain(name); err != nil || files.hashes[name] != digest {
			return fmt.Errorf("original CPP assembler registration changed: %s", file)
		}
	}
	for _, file := range pkg.SFiles {
		assembly, err := filepath.Rel(root, filepath.Join(pkg.Dir, file))
		if err != nil || !CPPLocalSource(filepath.ToSlash(assembly)) {
			return fmt.Errorf("original selected CPP assembly has no closed source origin")
		}
		assembly = filepath.ToSlash(assembly)
		source, err := CPPRegularSource(root, assembly)
		if err != nil {
			return err
		}
		opened, err := os.Open(source)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(opened, AssemblySourceByteLimit+1))
		if err := errors.Join(readErr, opened.Close()); err != nil {
			return fmt.Errorf("read bounded original CPP assembly: %w", err)
		}
		if len(data) > AssemblySourceByteLimit {
			return fmt.Errorf("original CPP assembly is missing or exceeds its byte bound")
		}
		used, bytes := []string{source}, len(data)
		expanded, err := plan9asm.PreprocessAssemblySource(string(data), plan9asm.AssemblyPreprocessOptions{
			FileName: source, Defines: macros.Defines,
			ReadInclude: func(parent, include string) (string, []byte, error) {
				module, tool, err := CPPIncludeCandidates(assembly, include)
				if err != nil || !CPPLocalSource(module) || path.Clean(include) == "go_asm.h" {
					return "", nil, fmt.Errorf("%w: active CPP include is escaping, generated or unknown", plan9asm.ErrProbeNeedsContext)
				}
				name := filepath.Join(root, filepath.FromSlash(module))
				if err := files.directory(filepath.Dir(name), false); err != nil {
					return "", nil, fmt.Errorf("%w: active CPP search directory is not closed: %v", plan9asm.ErrProbeNeedsContext, err)
				}
				if _, err := os.Lstat(name); os.IsNotExist(err) {
					if !CPPLocalSource(tool) {
						return "", nil, fmt.Errorf("%w: active CPP tool search escapes its source origin", plan9asm.ErrProbeNeedsContext)
					}
					name, err = CPPRegularSource(goRoot, tool)
					if err != nil {
						return "", nil, err
					}
					if err := files.directory(filepath.Dir(name), false); err != nil {
						return "", nil, err
					}
				} else if err != nil {
					return "", nil, err
				} else {
					name, err = CPPRegularSource(root, module)
					if err != nil {
						return "", nil, err
					}
				}
				if err := files.retain(name); err != nil {
					return "", nil, err
				}
				data, err := os.ReadFile(name)
				bytes += len(data)
				if err != nil || len(data) > 2<<20 || bytes > 16<<20 || len(used) >= 4096 {
					return "", nil, fmt.Errorf("original active CPP inputs exceed their bound or cannot be read")
				}
				used = append(used, name)
				return name, data, nil
			},
		})
		if err != nil {
			return fmt.Errorf("%w: actual original CPP cannot be closed: %v", plan9asm.ErrProbeNeedsContext, err)
		}
		if len(expanded) > 16<<20 {
			return fmt.Errorf("original expanded CPP exceeds its byte bound")
		}
		proof := amd64OriginalCPPObservation{Expanded: bytesSHA256([]byte(expanded)), Inputs: used}
		if prior, present := files.cpp[source]; present && !reflect.DeepEqual(prior, proof) {
			return fmt.Errorf("actual original active CPP input/expansion changed during export")
		}
		files.cpp[source] = proof
	}
	return nil
}
