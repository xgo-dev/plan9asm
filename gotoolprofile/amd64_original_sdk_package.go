package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// The actual import graph owns each SDK package separately. Descendant package
// contents are not compiler inputs merely because an ancestor package (crypto,
// for example) is imported. Retain every direct member, including inactive Go,
// assembly and header candidates, and the complete directory membership. Actual
// imported descendants have their own package capture; literal assembly includes
// have the separate bounded SDK include closure and shadow-directory guards.
// Ordinary module source inventories keep their existing complete-tree role.
func retainAMD64OriginalPackageDirectory(pkg amd64OriginalListPackage, directory string, files *amd64OriginalObservationFiles) error {
	if !pkg.Standard {
		return files.directory(directory, true)
	}
	if pkg.Module != nil {
		return fmt.Errorf("SDK package source cannot acquire a module identity")
	}
	if err := files.directory(directory, false); err != nil {
		return err
	}
	// Match Snapshot's shared 65,536-file / 4,096-directory member bound.
	entries, info, err := gooriginalsrc.ReadDirectory(directory, 65536+4096)
	if err != nil {
		return err
	}
	if !os.SameFile(info, files.directories[directory]) {
		return fmt.Errorf("SDK package directory identity changed during capture")
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if err := files.retain(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
	}
	return nil
}
