package gotoolprofile

import (
	"fmt"
	"path/filepath"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// SDK dependencies supply actual compiler exports and their complete guarded
// source graph, just as the independent GoAMD64FrameSource declaration-import
// owner does. They are not ordinary target CPP units: cmd/asm may use special
// ABI experiment macros and compiler-generated headers in these packages.
// No expanded source or frame capability is produced for them here.
func captureAMD64OriginalSDKDependency(pkg amd64OriginalListPackage, goRoot string,
	profile *Observation, files *amd64OriginalObservationFiles,
) error {
	if !pkg.Standard || pkg.Module != nil || !CPPLocalSource(pkg.ImportPath) {
		return fmt.Errorf("original SDK dependency lacks its actual standard package role")
	}
	wanted, err := sourcepath.Resolve(filepath.Join(goRoot, "src", filepath.FromSlash(pkg.ImportPath)))
	directory, dirErr := sourcepath.Resolve(pkg.Dir)
	if err != nil || dirErr != nil || directory != wanted || files.directories[directory] == nil {
		return fmt.Errorf("original SDK dependency lacks its complete bound source directory")
	}
	if len(pkg.SFiles) == 0 {
		return nil
	}
	// Capture, rather than broaden the ordinary validator: the registered
	// actual SDK sources derive any special package macros for this exact
	// observed environment. Unknown compiler registrations still fail.
	macros, err := CaptureAssemblerMacros(goRoot, profile, pkg.ImportPath)
	if err != nil {
		return err
	}
	for file, digest := range macros.ToolSourceSHA256 {
		name, err := CPPRegularSource(goRoot, file)
		if err != nil {
			return err
		}
		if err := files.retain(name); err != nil || files.hashes[name] != digest {
			return fmt.Errorf("original SDK assembler registration changed: %s", file)
		}
	}
	// Package-local source/header inventories were already retained in full.
	// Also bind the actual shared SDK header directory. Generated go_asm.h is
	// an input to the independently executed original export, not a fabricated
	// header/CPP or frame grant to the ordinary module being translated.
	if err := files.directory(filepath.Join(goRoot, "pkg", "include"), true); err != nil {
		return err
	}
	return captureAMD64SDKIncludeSources(pkg, goRoot, files)
}
