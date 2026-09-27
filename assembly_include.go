package plan9asm

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

var quotedGoAssemblyIncludeRE = regexp.MustCompile(`^#include[ \t]+"([^"\r\n]+)"[ \t]*(?://.*)?$`)

// ReadGoAssemblySource reads one .s file and recursively expands quoted
// includes from its module/source root or the active Go toolchain. Generated
// headers which do not exist yet (notably go_asm.h) remain directives so the
// type-aware expansion path can provide their values later.
func ReadGoAssemblySource(asmFile, sourceRoot string) ([]byte, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly source root: %w", err)
	}
	root, err = evalGoAssemblyPath(root)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly source root symlinks: %w", err)
	}
	file, err := filepath.Abs(asmFile)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly path: %w", err)
	}
	file, err = evalGoAssemblyPath(file)
	if err != nil {
		return nil, fmt.Errorf("resolve assembly path symlinks: %w", err)
	}
	if !goAssemblyPathWithinRoot(root, file) {
		return nil, fmt.Errorf("assembly source %s escapes source root %s", file, root)
	}
	return expandGoAssemblyIncludes(file, root, make(map[string]bool), 0)
}

func expandGoAssemblyIncludes(file, sourceRoot string, active map[string]bool, depth int) ([]byte, error) {
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
		localAllowed := goAssemblyPathWithinRoot(sourceRoot, includedPath)
		var included []byte
		var includeErr error
		if localAllowed {
			resolvedPath, err := evalGoAssemblyPath(includedPath)
			if err == nil {
				if !goAssemblyPathWithinRoot(sourceRoot, resolvedPath) {
					return nil, fmt.Errorf("assembly include %q escapes source root %s through symlink %s", match[1], sourceRoot, resolvedPath)
				}
				includedPath = resolvedPath
			} else if !os.IsNotExist(err) {
				return nil, fmt.Errorf("resolve assembly include %q from %s: %w", match[1], file, err)
			}
			included, includeErr = expandGoAssemblyIncludes(includedPath, sourceRoot, active, depth+1)
		}
		if !localAllowed || os.IsNotExist(includeErr) {
			goRoot, err := gotoolchain.Root()
			if err != nil {
				return nil, err
			}
			goRoot, err = evalGoAssemblyPath(filepath.Clean(goRoot))
			if err != nil {
				return nil, fmt.Errorf("resolve GOROOT symlinks: %w", err)
			}
			goIncludeRoot := filepath.Join(goRoot, "pkg", "include")
			goIncludedPath := filepath.Clean(filepath.Join(goIncludeRoot, filepath.FromSlash(match[1])))
			if goAssemblyPathWithinRoot(goRoot, goIncludedPath) {
				resolvedPath, err := evalGoAssemblyPath(goIncludedPath)
				if err == nil {
					if !goAssemblyPathWithinRoot(goRoot, resolvedPath) {
						return nil, fmt.Errorf("assembly include %q escapes GOROOT %s through symlink %s", match[1], goRoot, resolvedPath)
					}
					goIncludedPath = resolvedPath
				} else if !os.IsNotExist(err) {
					return nil, fmt.Errorf("resolve Go assembly include %q: %w", match[1], err)
				}
				included, includeErr = expandGoAssemblyIncludes(goIncludedPath, goRoot, active, depth+1)
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

// evalGoAssemblyPath canonicalizes symlinks before containment checks. The
// Windows hosted toolcache exposes GOROOT through a cross-volume directory
// link which filepath.EvalSymlinks cannot always traverse even though the path
// is readable. In that one trusted tree, retain the absolute path after proving
// it exists; module and arbitrary source roots still require full resolution.
func evalGoAssemblyPath(path string) (string, error) {
	goRoot := runtime.GOROOT()
	if goRoot == "" && runtime.GOOS == "windows" {
		var err error
		goRoot, err = gotoolchain.Root()
		if err != nil {
			return "", err
		}
	}
	return evalGoAssemblyPathForOS(path, runtime.GOOS, goRoot, filepath.EvalSymlinks)
}

func evalGoAssemblyPathForOS(path, goos, goRoot string, eval func(string) (string, error)) (string, error) {
	resolved, err := eval(path)
	if err == nil || goos != "windows" {
		return resolved, err
	}
	absPath, absErr := filepath.Abs(path)
	if absErr != nil {
		return "", err
	}
	absRoot, absErr := filepath.Abs(goRoot)
	if absErr != nil || !goAssemblyPathWithinRoot(filepath.Clean(absRoot), filepath.Clean(absPath)) {
		return "", err
	}
	if _, statErr := os.Stat(absPath); statErr != nil {
		return "", err
	}
	return filepath.Clean(absPath), nil
}

func goAssemblyPathWithinRoot(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
