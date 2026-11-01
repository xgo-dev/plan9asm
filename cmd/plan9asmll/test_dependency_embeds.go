package main

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

type testDependencyEmbedGuard struct {
	Source gotoolprofile.TestSourcePackage
	Root   string
}

// go/packages exposes absolute patterns; go list exposes package-relative
// spelling. Preserve that spelling, including all:, without resolving globs
// as filesystem paths or changing their grammar.
func captureTestPackageEmbedSelection(proof gotoolprofile.PackageProof, root string, pkg *packages.Package) (*gotoolprofile.TestEmbedSelection, error) {
	var patterns []string
	for _, pattern := range pkg.EmbedPatterns {
		if len(pkg.GoFiles) == 0 || !filepath.IsAbs(pattern) {
			return nil, fmt.Errorf("actual typed package has an unbound absolute embed pattern")
		}
		rel, err := filepath.Rel(filepath.Dir(pkg.GoFiles[0]), pattern)
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, filepath.ToSlash(rel))
	}
	return gotoolprofile.CaptureTestEmbedSelection(proof, root, patterns, pkg.EmbedFiles)
}

// Installed only after the producer closure agrees with independently bound
// actual Module/Go selection. JSON alone never authorizes an embed source role.
func (consumer *featureConsumer) verifyTestEmbedPackage(pkg *packages.Package) error {
	bound, found := consumer.TestEmbedGuards[pkg.ID]
	if !found {
		return fmt.Errorf("test dependency embed role has no independently bound actual source closure")
	}
	actual, err := captureTestPackageEmbedSelection(bound.Source.Package, bound.Root, pkg)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, bound.Source.Embed) {
		return fmt.Errorf("actual test dependency embed source/pattern/file selection changed")
	}
	return nil
}

func (consumer *featureConsumer) captureTestSourceLoadGuard(ctx context.Context, pkgs []*packages.Package, allowedTests map[string]bool) (*generatedHeaderLoadGuard, error) {
	return captureTypedSourceLoadGuardWithEmbeds(ctx, pkgs, allowedTests, consumer.verifyTestEmbedPackage)
}
