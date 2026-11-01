package main

import (
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func ordinaryDependencyActualRoot(consumer *featureConsumer, pkg *packages.Package) string {
	if pkg.Module == nil {
		return filepath.Join(consumer.Root, "src")
	}
	if pkg.Module.Replace != nil {
		return pkg.Module.Replace.Dir
	}
	return pkg.Module.Dir
}

// Only the actual driver's module-root spelling may have ancestor aliases.
// Preserve its relative source identity before resolving anything below it:
// blindly canonicalizing a selected file would hide source-internal redirects.
func ordinaryDependencyOriginalPath(observed, root, filename string) (string, error) {
	// go.mod replacement roots may keep '/' on Windows. Normalize separators
	// only; Clean below must still reject dot segments and other changed paths.
	observed = filepath.FromSlash(observed)
	root = filepath.FromSlash(root)
	filename = filepath.FromSlash(filename)
	for _, name := range []string{observed, root, filename} {
		if !filepath.IsAbs(name) || filepath.Clean(name) != name {
			return "", fmt.Errorf("ordinary dependency has an unbound original source path")
		}
	}
	resolved, err := sourcepath.Resolve(observed)
	if err != nil || resolved != root {
		return "", fmt.Errorf("ordinary dependency observed source root changed")
	}
	resolved, err = sourcepath.Resolve(root)
	if err != nil || resolved != root {
		return "", fmt.Errorf("ordinary dependency canonical source root changed")
	}
	relative, err := filepath.Rel(observed, filename)
	local := func(name string) bool {
		return name == "." || gotoolprofile.CPPLocalSource(filepath.ToSlash(name))
	}
	if err != nil || !local(relative) {
		// Some drivers already canonicalize selected filenames. This is not
		// permission to use another arbitrary alias to the same bytes.
		relative, err = filepath.Rel(root, filename)
		if err != nil || !local(relative) {
			return "", fmt.Errorf("ordinary dependency source escapes its actual module root")
		}
	}
	canonical := filepath.Join(root, relative)
	resolved, err = sourcepath.Resolve(canonical)
	if err != nil || resolved != canonical {
		return "", fmt.Errorf("ordinary dependency source is internally redirected")
	}
	resolved, err = sourcepath.Resolve(filename)
	if err != nil || resolved != canonical {
		return "", fmt.Errorf("ordinary dependency original source identity changed")
	}
	return canonical, nil
}

func captureOrdinaryPackageEmbedSelection(proof gotoolprofile.PackageProof, observed, root string, pkg *packages.Package) (*gotoolprofile.TestEmbedSelection, error) {
	copy := *pkg
	copy.EmbedFiles = make([]string, len(pkg.EmbedFiles))
	for index, file := range pkg.EmbedFiles {
		canonical, err := ordinaryDependencyOriginalPath(observed, root, file)
		if err != nil {
			return nil, err
		}
		copy.EmbedFiles[index] = canonical
	}
	// Keep the driver's original GoFiles and pattern spellings paired: glob
	// syntax is not an existing filename and must not pass through EvalSymlinks.
	return captureTestPackageEmbedSelection(proof, root, &copy)
}
