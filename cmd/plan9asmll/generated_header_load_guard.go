package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// Machine paths stay in this private invocation guard. Portable metadata keeps
// normalized package/module identities and dependency source/export digests.
type generatedHeaderLoadGuard struct {
	Packages map[string]string
	Sources  map[string]string
}

type generatedHeaderLoadSelection struct {
	Name            string
	PackagePath     string
	Module          *packages.Module
	GoFiles         []string
	CompiledGoFiles []string
	OtherFiles      []string
	EmbedFiles      []string
	EmbedPatterns   []string
	Imports         map[string]string
}

func captureGeneratedHeaderLoadGuard(ctx context.Context, pkgs []*packages.Package) (*generatedHeaderLoadGuard, error) {
	return captureTypedSourceLoadGuard(ctx, pkgs, nil)
}

// The sole optional test identity is an explicitly requested same-package
// variant. Generated-header callers continue rejecting every test role.
func captureTypedSourceLoadGuard(ctx context.Context, pkgs []*packages.Package, allowedTests map[string]bool) (*generatedHeaderLoadGuard, error) {
	return captureTypedSourceLoadGuardWithEmbeds(ctx, pkgs, allowedTests, nil)
}

func captureTypedSourceLoadGuardWithEmbeds(ctx context.Context, pkgs []*packages.Package, allowedTests map[string]bool, verifyEmbed func(*packages.Package) error) (*generatedHeaderLoadGuard, error) {
	guard := &generatedHeaderLoadGuard{Packages: make(map[string]string), Sources: make(map[string]string)}
	var captureErr error
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if captureErr != nil {
			return false
		}
		if ctx == nil || ctx.Err() != nil {
			captureErr = fmt.Errorf("generated-header source guard requires a live candidate context")
			return false
		}
		if len(pkg.Errors) != 0 {
			var diagnostics []string
			for _, err := range pkg.Errors {
				diagnostics = append(diagnostics, err.Error())
			}
			captureErr = fmt.Errorf("actual generated-header Go source selection:\n%s", strings.Join(diagnostics, "\n"))
			return false
		}
		if pkg.PkgPath == "unsafe" {
			return false // Go's builtin singleton has no source or export file.
		}
		hasEmbed := len(pkg.EmbedFiles) != 0 || len(pkg.EmbedPatterns) != 0
		if pkg.ID == "" || len(guard.Packages) >= 4096 || hasEmbed && verifyEmbed == nil || isTestVariantPackage(pkg) && !allowedTests[pkg.ID] {
			captureErr = fmt.Errorf("generated-header query has an unbound embed/test role or exceeds its package bound: package_id=%q package_path=%q for_test=%q test_variant=%t allowed_test=%t embed_files=%d embed_patterns=%d used_packages=%d package_bound=4096",
				pkg.ID, pkg.PkgPath, pkg.ForTest, isTestVariantPackage(pkg), allowedTests[pkg.ID],
				len(pkg.EmbedFiles), len(pkg.EmbedPatterns), len(guard.Packages))
			return false
		}
		if hasEmbed {
			if err := verifyEmbed(pkg); err != nil {
				captureErr = err
				return false
			}
		}
		canonical := func(files []string) []string {
			result := append([]string(nil), files...)
			sort.Strings(result)
			return result
		}
		selection := generatedHeaderLoadSelection{
			Name: pkg.Name, PackagePath: pkg.PkgPath, Module: pkg.Module,
			GoFiles: canonical(pkg.GoFiles), CompiledGoFiles: canonical(pkg.CompiledGoFiles),
			OtherFiles: canonical(pkg.OtherFiles), Imports: make(map[string]string),
			EmbedFiles: canonical(pkg.EmbedFiles), EmbedPatterns: canonical(pkg.EmbedPatterns),
		}
		for name, dep := range pkg.Imports {
			selection.Imports[name] = dep.PkgPath
		}
		data, err := json.Marshal(selection)
		if err != nil {
			captureErr = err
			return false
		}
		guard.Packages[pkg.ID] = featureBytesSHA256(data)
		for _, file := range append(append([]string(nil), pkg.CompiledGoFiles...), pkg.EmbedFiles...) {
			if ctx.Err() != nil || len(guard.Sources) >= 32768 {
				captureErr = fmt.Errorf("generated-header source guard exceeded its deadline/file bound")
				return false
			}
			info, err := os.Stat(file)
			if err != nil || !info.Mode().IsRegular() || info.Size() > 64<<20 {
				captureErr = fmt.Errorf("generated-header dependency source must be a bounded regular file")
				return false
			}
			digest, err := gotoolprofile.FileSHA256(file)
			if err != nil {
				captureErr = err
				return false
			}
			guard.Sources[file] = digest
		}
		return true
	}, nil)
	return guard, captureErr
}
