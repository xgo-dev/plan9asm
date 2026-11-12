package plan9asm

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

var quotedGoAssemblyIncludeRE = regexp.MustCompile(`^#include[ \t]+"([^"\r\n]+)"[ \t]*(?://.*)?$`)

// GoAssemblySourceReadReport is a plain read inventory, not source/CPP authority.
// SearchMisses records preferred local names whose absence selected a fallback;
// missing generated headers never become successful Inputs.
type GoAssemblySourceReadReport struct {
	Inputs       map[string]string
	SearchMisses []string
}

// ReadGoAssemblySource reads one .s file and recursively expands quoted
// includes from its module/source root or the active Go toolchain. Generated
// headers which do not exist yet (notably go_asm.h) remain directives so the
// type-aware expansion path can provide their values later.
func ReadGoAssemblySource(asmFile, sourceRoot string) ([]byte, error) {
	return readGoAssemblySource(asmFile, sourceRoot, "", nil)
}

// ReadGoAssemblySourceWithReport also reports the physical files and original
// requested names actually read by the same expansion, with their byte hashes.
// Missing generated headers are not invented inputs. This is an inventory, not
// a compiler-backed source/CPP observation or any native-memory permission.
func ReadGoAssemblySourceWithReport(asmFile, sourceRoot string) ([]byte, *GoAssemblySourceReadReport, error) {
	inputs := &GoAssemblySourceReadReport{Inputs: make(map[string]string)}
	source, err := readGoAssemblySource(asmFile, sourceRoot, "", inputs)
	if err != nil {
		return nil, nil, err
	}
	return source, inputs, nil
}

// ReadGoAssemblySourceAtGOROOT expands the same source inventory using the
// explicitly selected Go installation. It does not substitute the host SDK's
// headers when inspecting another compiler version. Missing generated headers
// remain unresolved, just as in ReadGoAssemblySource; this is not a complete
// compiler-backed CPP or translation observation.
func ReadGoAssemblySourceAtGOROOT(asmFile, sourceRoot, goRoot string) ([]byte, error) {
	if goRoot == "" {
		return nil, fmt.Errorf("assembly source inventory requires an explicit GOROOT")
	}
	return readGoAssemblySource(asmFile, sourceRoot, goRoot, nil)
}

func readGoAssemblySource(asmFile, sourceRoot, goRoot string, inputs *GoAssemblySourceReadReport) ([]byte, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly source root: %w", err)
	}
	root, err = sourcepath.Resolve(root)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly source root symlinks: %w", err)
	}
	file, err := filepath.Abs(asmFile)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly path: %w", err)
	}
	requested := file
	file, err = sourcepath.Resolve(file)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly path symlinks: %w", err)
	}
	if !goAssemblyPathWithinRoot(root, file) {
		return nil, fmt.Errorf("assembly source %s escapes source root %s", file, root)
	}
	source, err := expandGoAssemblyIncludes(file, root, goRoot, make(map[string]bool), inputs, 0)
	if err == nil && inputs != nil {
		inputs.Inputs[requested] = inputs.Inputs[file]
	}
	return source, err
}

func expandGoAssemblyIncludes(file, sourceRoot, goRoot string, active map[string]bool, inputs *GoAssemblySourceReadReport, depth int) ([]byte, error) {
	if depth > 32 {
		return nil, fmt.Errorf("assembly include depth exceeds 32 at %s", file)
	}
	if active[file] {
		return nil, fmt.Errorf("assembly include cycle at %s", file)
	}
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if inputs != nil {
		inputs.Inputs[file] = fmt.Sprintf("%x", sha256.Sum256(src))
	}
	active[file] = true
	defer delete(active, file)

	var out strings.Builder
	for _, line := range strings.SplitAfter(string(src), "\n") {
		trimmed := strings.TrimSpace(strings.TrimSuffix(line, "\n"))
		match := quotedGoAssemblyIncludeRE.FindStringSubmatch(trimmed)
		if match == nil || filepath.IsAbs(match[1]) {
			out.WriteString(line)
			continue
		}

		includedPath := filepath.Clean(filepath.Join(filepath.Dir(file), filepath.FromSlash(match[1])))
		requestedPath := includedPath
		localAllowed := goAssemblyPathWithinRoot(sourceRoot, includedPath)
		var included []byte
		var includeErr error
		if localAllowed {
			resolvedPath, err := sourcepath.Resolve(includedPath)
			if err == nil {
				if !goAssemblyPathWithinRoot(sourceRoot, resolvedPath) {
					return nil, fmt.Errorf("assembly include %q escapes source root %s through symlink %s", match[1], sourceRoot, resolvedPath)
				}
				includedPath = resolvedPath
			} else if !os.IsNotExist(err) {
				return nil, fmt.Errorf("resolve assembly include %q from %s: %w", match[1], file, err)
			}
			included, includeErr = expandGoAssemblyIncludes(includedPath, sourceRoot, goRoot, active, inputs, depth+1)
			if includeErr == nil && inputs != nil {
				inputs.Inputs[requestedPath] = inputs.Inputs[includedPath]
			}
		}
		if !localAllowed || os.IsNotExist(includeErr) {
			if localAllowed && os.IsNotExist(includeErr) && inputs != nil {
				inputs.SearchMisses = append(inputs.SearchMisses, requestedPath)
			}
			if goRoot == "" {
				goRoot, err = gotoolchain.Root()
				if err != nil {
					return nil, err
				}
			}
			goRoot, err = sourcepath.Resolve(filepath.Clean(goRoot))
			if err != nil {
				return nil, fmt.Errorf("resolve GOROOT symlinks: %w", err)
			}
			goIncludeRoot := filepath.Join(goRoot, "pkg", "include")
			goIncludedPath := filepath.Clean(filepath.Join(goIncludeRoot, filepath.FromSlash(match[1])))
			requestedPath := goIncludedPath
			if goAssemblyPathWithinRoot(goRoot, goIncludedPath) {
				resolvedPath, err := sourcepath.Resolve(goIncludedPath)
				if err == nil {
					if !goAssemblyPathWithinRoot(goRoot, resolvedPath) {
						return nil, fmt.Errorf("assembly include %q escapes GOROOT %s through symlink %s", match[1], goRoot, resolvedPath)
					}
					goIncludedPath = resolvedPath
				} else if !os.IsNotExist(err) {
					return nil, fmt.Errorf("resolve Go assembly include %q: %w", match[1], err)
				}
				included, includeErr = expandGoAssemblyIncludes(goIncludedPath, goRoot, goRoot, active, inputs, depth+1)
				if includeErr == nil && inputs != nil {
					inputs.Inputs[requestedPath] = inputs.Inputs[goIncludedPath]
				}
			} else if !localAllowed {
				return nil, fmt.Errorf("assembly include %q escapes source root %s and GOROOT %s", match[1], sourceRoot, goRoot)
			}
			if os.IsNotExist(includeErr) {
				if !localAllowed {
					return nil, fmt.Errorf("assembly include %q escapes source root %s", match[1], sourceRoot)
				}
				out.WriteString(line)
				continue
			}
		}
		if includeErr != nil {
			return nil, fmt.Errorf("expand assembly include %q from %s: %w", match[1], file, includeErr)
		}
		out.Write(included)
		if strings.HasSuffix(line, "\n") && len(included) != 0 && included[len(included)-1] != '\n' {
			out.WriteByte('\n')
		}
	}
	return []byte(out.String()), nil
}

func goAssemblyPathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
