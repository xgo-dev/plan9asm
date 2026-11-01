package gotoolprofile

import (
	"fmt"
	"reflect"
)

const OrdinaryDependencyProtocol = "actual_go_ordinary_dependency_sources_v1"

// OrdinaryDependencyProof binds every ordinary import edge and every package's
// positive or empty embed selection. It never provides a test-variant role or
// an assembly/output receipt for dependency packages.
type OrdinaryDependencyProof struct {
	Protocol         string                 `json:"protocol"`
	Candidate        SourceInventory        `json:"candidate_sources"`
	Packages         []SourcePackageProof   `json:"source_packages"`
	ExternalPackages []SourcePackageProof   `json:"external_source_packages"`
	SourceModules    []ModuleSourceSnapshot `json:"dependency_source_roots"`
}

func inventoryInput(input *ConsumerInput, inventory SourceInventory) *ConsumerInput {
	view := *input
	view.Sources, view.Headers = inventory.Sources, inventory.Headers
	view.Directories = make(map[string][]string)
	for dir, entries := range inventory.Directories {
		view.Directories[dir] = []string{}
		for _, entry := range entries {
			view.Directories[dir] = append(view.Directories[dir], entry.Name)
		}
	}
	return &view
}

func ValidateOrdinaryDependencies(input *ConsumerInput, metadata *MetadataProof, tags []string) error {
	if input == nil || input.Observed == nil || metadata == nil {
		return fmt.Errorf("ordinary dependency validation lacks source/profile metadata")
	}
	proof := metadata.Dependencies
	if proof == nil || proof.Protocol != OrdinaryDependencyProtocol || len(proof.Packages) == 0 {
		return fmt.Errorf("ordinary metadata lacks its complete dependency source role")
	}
	if err := ValidateSourceInventory(proof.Candidate); err != nil {
		return err
	}
	view := inventoryInput(input, proof.Candidate)
	for file, digest := range proof.Candidate.Sources {
		if previous, found := input.Sources[file]; found && previous != digest {
			return fmt.Errorf("ordinary dependency candidate bytes conflict with original inputs")
		}
	}
	for dir, entries := range view.Directories {
		if previous, found := input.Directories[dir]; found && !reflect.DeepEqual(previous, entries) {
			return fmt.Errorf("ordinary dependency candidate membership conflicts with original inputs")
		}
	}
	modules, err := sourceModuleSnapshots(input, proof.SourceModules)
	if err != nil {
		return err
	}
	roots := make(map[string]bool)
	byPath := make(map[string]SourcePackageProof)
	for _, source := range append(append([]SourcePackageProof(nil), proof.Packages...), proof.ExternalPackages...) {
		byPath[source.Package.PackagePath] = source
	}
	for _, pkg := range metadata.Packages {
		source, found := byPath[pkg.PackagePath]
		actual := pkg
		actual.Macros = nil
		if !found || source.SourceRootID != "" || !reflect.DeepEqual(source.Package, actual) {
			return fmt.Errorf("ordinary header root differs from its complete source closure")
		}
		roots[pkg.PackagePath] = true
	}
	if err := validatePackageSourceClosure(view, proof.Packages, proof.ExternalPackages, modules, roots, tags, false); err != nil {
		return fmt.Errorf("ordinary dependency closure: %w", err)
	}
	for _, header := range metadata.Headers {
		source := byPath[header.PackagePath]
		if !reflect.DeepEqual(source.ImportMap, header.ImportMap) {
			return fmt.Errorf("ordinary compiler import map differs from its complete source closure")
		}
		for _, imported := range header.Imports {
			dep := byPath[imported.PackagePath]
			pkg := dep.Package
			goSHA := make(map[string]string)
			for _, file := range pkg.CompiledGoFiles {
				goSHA[file] = pkg.SourceSHA256[file]
			}
			if imported.ModulePath != pkg.ModulePath || imported.Version != pkg.ModuleVersion ||
				imported.SourceModule != pkg.SourceModule || imported.SourceVersion != pkg.SourceVersion || imported.SourceRole != pkg.SourceRole ||
				!reflect.DeepEqual(imported.GoSHA256, goSHA) || dep.SourceRootID != "" && imported.ExportSHA256 != dep.ExportSHA256 {
				return fmt.Errorf("ordinary header export differs from bound dependency source/role")
			}
		}
	}
	return nil
}
