package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/mod/module"
	"golang.org/x/tools/go/packages"
)

// An ordinary owner is private to one live load. It is never installed in the
// test guards and portable records alone cannot manufacture this authority.
type ordinaryDependencyOwner struct {
	Compiled bool
	Proof    *gotoolprofile.OrdinaryDependencyProof
	Packages map[string]ordinaryDependencyPackage
	Modules  map[string]*ordinaryDependencyModule
	Roots    map[string]string
}

type ordinaryDependencyPackage struct {
	Source             gotoolprofile.SourcePackageProof
	Root, ObservedRoot string
}

type ordinaryDependencyModule struct {
	Source                     gotoolprofile.ModuleSourceSnapshot
	Root, ZIP, DownloadedGoMod string
	Metadata                   map[string]string
}

func (consumer *featureConsumer) captureOrdinaryDependencies(pkgs []*packages.Package) error {
	consumer.OrdinaryDependencies = nil
	owner := &ordinaryDependencyOwner{
		Proof:    &gotoolprofile.OrdinaryDependencyProof{Protocol: gotoolprofile.OrdinaryDependencyProtocol},
		Packages: make(map[string]ordinaryDependencyPackage), Modules: make(map[string]*ordinaryDependencyModule),
		Roots: make(map[string]string),
	}
	var captureErr error
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if captureErr != nil {
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
		if consumer.Context == nil || consumer.Context.Err() != nil || len(owner.Packages) >= 4096 ||
			pkg.ID != pkg.PkgPath || isTestVariantPackage(pkg) {
			captureErr = fmt.Errorf("ordinary dependency source requires a live complete ordinary package selection")
			return false
		}
		source, root, err := consumer.captureOrdinaryDependencyPackage(owner, pkg)
		if err != nil {
			captureErr = err
			return false
		}
		owner.Packages[pkg.PkgPath] = ordinaryDependencyPackage{Source: source, Root: root, ObservedRoot: ordinaryDependencyActualRoot(consumer, pkg)}
		return true
	}, nil)
	if captureErr != nil {
		return captureErr
	}
	for _, bound := range owner.Packages {
		if bound.Source.SourceRootID == "" {
			owner.Proof.Packages = append(owner.Proof.Packages, bound.Source)
		} else {
			owner.Proof.ExternalPackages = append(owner.Proof.ExternalPackages, bound.Source)
		}
	}
	for _, module := range owner.Modules {
		owner.Proof.SourceModules = append(owner.Proof.SourceModules, module.Source)
	}
	gotoolprofile.SortTestModuleSources(owner.Proof.SourceModules)
	for _, sources := range [][]gotoolprofile.SourcePackageProof{owner.Proof.Packages, owner.Proof.ExternalPackages} {
		sort.Slice(sources, func(i, j int) bool { return sources[i].Package.PackagePath < sources[j].Package.PackagePath })
	}
	if err := consumer.verifyOrdinaryOwner(owner); err != nil {
		return err
	}
	consumer.OrdinaryDependencies = owner
	return nil
}

func (consumer *featureConsumer) captureOrdinaryDependencyPackage(owner *ordinaryDependencyOwner, actual *packages.Package) (gotoolprofile.SourcePackageProof, string, error) {
	result := gotoolprofile.SourcePackageProof{VariantID: actual.ID, ImportMap: make(map[string]string)}
	proof := gotoolprofile.PackageProof{PackagePath: actual.PkgPath, SourceSHA256: make(map[string]string)}
	root, id, metadata := consumer.Dir, "", ""
	if actual.Module == nil {
		root = filepath.Join(consumer.Root, "src")
		proof.SourceRole, id = "stdlib", "stdlib@"+consumer.Observed.GoVersion
	} else {
		m := actual.Module
		root, metadata = m.Dir, m.GoMod
		proof.ModulePath, proof.ModuleVersion = m.Path, m.Version
		proof.SourceModule, proof.SourceVersion, proof.SourceRole = m.Path, m.Version, "module"
		if m.Main {
			proof.SourceRole = "main"
		}
		if r := m.Replace; r != nil {
			root, metadata = r.Dir, r.GoMod
			if r.Version == "" {
				proof.SourceRole = "owned_local_replace"
			} else {
				proof.SourceModule, proof.SourceVersion, proof.SourceRole = r.Path, r.Version, "version_replace"
			}
		}
		if m.Path == consumer.Input.Module {
			if origin := consumer.Input.ProxyGoMod; origin != nil {
				proof.GoModOrigin, proof.GoModSHA256, proof.GoModSum = origin.Protocol, origin.SHA256, origin.GoModSum
			}
			if err := gotoolprofile.ValidatePackageModule(consumer.Input, proof); err != nil {
				return result, "", err
			}
		} else {
			if m.Main || module.Check(m.Path, m.Version) != nil || module.Check(proof.SourceModule, proof.SourceVersion) != nil || proof.SourceRole == "owned_local_replace" {
				return result, "", fmt.Errorf("ordinary dependency lacks an exact versioned Module/Replace source")
			}
			id = proof.SourceModule + "@" + proof.SourceVersion
		}
	}
	observedRoot := root
	var err error
	root, err = sourcepath.Resolve(root)
	if err != nil || !filepath.IsAbs(root) || id == "" && root != consumer.Dir {
		return result, "", fmt.Errorf("ordinary dependency has a different actual source root")
	}
	if previous, present := owner.Roots[observedRoot]; present && previous != root {
		return result, "", fmt.Errorf("ordinary dependency observed source root changed")
	}
	owner.Roots[observedRoot] = root
	var inventory *gotoolprofile.SourceInventory
	if id == "" {
		inventory = &owner.Proof.Candidate
	} else {
		bound := owner.Modules[id]
		if bound == nil {
			bound, err = consumer.captureOrdinaryModule(proof, root, metadata)
			if err != nil {
				return result, "", err
			}
			owner.Modules[id] = bound
		} else if root != bound.Root {
			return result, "", fmt.Errorf("ordinary dependency source identity changed roots")
		}
		view := bound.Source.Inventory()
		inventory = &view
		defer func() {
			bound.Source.Sources, bound.Source.Headers, bound.Source.Directories = view.Sources, view.Headers, view.Directories
		}()
		if metadata != "" {
			canonical, err := sourcepath.Resolve(metadata)
			if err != nil {
				return result, "", err
			}
			bound.Metadata[metadata] = canonical
		}
		if bound.Source.SourceModule != "" {
			proof.GoModOrigin, proof.GoModSHA256, proof.GoModSum = bound.Source.GoModOrigin, bound.Source.GoModSHA256, bound.Source.GoModSum
		}
	}
	if len(actual.GoFiles) == 0 {
		return result, "", fmt.Errorf("ordinary dependency lacks original Go sources")
	}
	directory, err := ordinaryDependencyOriginalPath(observedRoot, root, filepath.Dir(actual.GoFiles[0]))
	if err != nil {
		return result, "", err
	}
	if err := gotoolprofile.CaptureSourceDirectory(consumer.Context, inventory, root, directory, len(actual.EmbedPatterns) != 0); err != nil {
		return result, "", err
	}
	capture := func(files []string, assembly bool) ([]string, error) {
		var names []string
		for _, filename := range files {
			if assembly && filepath.Ext(filename) != ".s" {
				continue
			}
			filename, err := ordinaryDependencyOriginalPath(observedRoot, root, filename)
			if err != nil {
				return nil, err
			}
			name, err := filepath.Rel(root, filename)
			name = filepath.ToSlash(name)
			if err != nil {
				return nil, err
			}
			if _, err := gotoolprofile.CPPRegularSource(root, name); err != nil {
				return nil, err
			}
			digest, err := gotoolprofile.FileSHA256(filename)
			if err != nil || inventory.Sources[name] != digest {
				return nil, fmt.Errorf("ordinary dependency selected unbound original bytes")
			}
			proof.SourceSHA256[name] = digest
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	if proof.GoFiles, err = capture(actual.GoFiles, false); err != nil {
		return result, "", err
	}
	if proof.CompiledGoFiles, err = capture(actual.CompiledGoFiles, false); err != nil {
		return result, "", err
	}
	if proof.SFiles, err = capture(actual.OtherFiles, true); err != nil {
		return result, "", err
	}
	if actual.PkgPath == "unsafe" {
		if actual.Name != "unsafe" || actual.Module != nil || actual.ExportFile != "" || len(actual.Imports) != 0 ||
			!reflect.DeepEqual(proof.GoFiles, []string{"unsafe/unsafe.go"}) || len(proof.CompiledGoFiles) != 0 || len(proof.SFiles) != 0 {
			return result, "", fmt.Errorf("ordinary unsafe singleton has a different source role")
		}
		result.Builtin = "go_typechecker_unsafe_v1"
	} else if !reflect.DeepEqual(proof.GoFiles, proof.CompiledGoFiles) {
		return result, "", fmt.Errorf("ordinary dependency cannot acquire a generated/cgo/overlay source role")
	}
	for spelling, dep := range actual.Imports {
		result.ImportMap[spelling] = dep.PkgPath
	}
	result.Package, result.SourceRootID = proof, id
	result.Embed, err = captureOrdinaryPackageEmbedSelection(proof, observedRoot, root, actual)
	return result, root, err
}

func (consumer *featureConsumer) captureOrdinaryModule(pkg gotoolprofile.PackageProof, root, metadata string) (*ordinaryDependencyModule, error) {
	bound := &ordinaryDependencyModule{Root: root, Metadata: make(map[string]string), Source: gotoolprofile.ModuleSourceSnapshot{
		Protocol: gotoolprofile.TestDependencyModuleProtocol, SourceModule: pkg.SourceModule, SourceVersion: pkg.SourceVersion,
	}}
	if pkg.SourceRole == "stdlib" {
		bound.Source.GoVersion = consumer.Observed.GoVersion
		return bound, nil
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	data, _, err := gotoolprofile.RunBounded(consumer.Context, consumer.WorkDir, consumer.Env, binary, "mod", "download", "-json", bound.Source.ID())
	if err != nil {
		return nil, err
	}
	var download struct{ Path, Version, Dir, Zip, GoMod, Sum, GoModSum, Error string }
	if err := json.Unmarshal(data, &download); err != nil || download.Error != "" || download.Path != pkg.SourceModule || download.Version != pkg.SourceVersion {
		return nil, fmt.Errorf("ordinary dependency download has a different exact module identity")
	}
	directory, err := sourcepath.Resolve(download.Dir)
	if err != nil || directory != root {
		return nil, fmt.Errorf("ordinary dependency download has a different actual source root")
	}
	bound.ZIP, bound.DownloadedGoMod = download.Zip, download.GoMod
	bound.Source.ModuleSum, bound.Source.GoModSum = download.Sum, download.GoModSum
	bound.Source.ZipSHA256, err = gotoolprofile.FileSHA256(download.Zip)
	if err != nil {
		return nil, err
	}
	bound.Source.GoModSHA256, err = gotoolprofile.FileSHA256(download.GoMod)
	if err != nil {
		return nil, err
	}
	if _, err := os.Lstat(filepath.Join(root, "go.mod")); os.IsNotExist(err) {
		var prior *gotoolprofile.ProxyGoModProof
		if expected := consumer.Input.GeneratedHeaders; expected != nil && expected.Dependencies != nil {
			for _, source := range expected.Dependencies.SourceModules {
				if source.ID() == bound.Source.ID() {
					prior = source.ProxyGoMod
				}
			}
		}
		origin, canonical, err := gotoolprofile.CaptureDownloadedProxyGoMod(consumer.Context, binary, consumer.WorkDir, consumer.Env,
			pkg.SourceModule, pkg.SourceVersion, download.Sum, download.GoModSum, download.GoMod, prior)
		if err != nil {
			return nil, fmt.Errorf("ordinary dependency proxy metadata authentication: %w", err)
		}
		bound.Source.GoModOrigin, bound.Source.ProxyGoMod = gotoolprofile.ProxyGoModProtocol, origin
		bound.DownloadedGoMod = canonical
		return bound, nil
	} else if err != nil {
		return nil, err
	}
	bound.Source.GoModOrigin = gotoolprofile.TestModuleOriginalGoModOrigin
	return bound, nil
}

func (consumer *featureConsumer) verifyOrdinaryOwner(owner *ordinaryDependencyOwner) error {
	if owner == nil {
		return nil
	}
	if owner.Proof == nil || owner.Proof.Protocol != gotoolprofile.OrdinaryDependencyProtocol || len(owner.Packages) == 0 {
		return fmt.Errorf("ordinary dependency source owner is incomplete")
	}
	if len(owner.Roots) == 0 {
		return fmt.Errorf("ordinary dependency source owner lacks its actual root identity")
	}
	for observed, canonical := range owner.Roots {
		if _, err := ordinaryDependencyOriginalPath(observed, canonical, observed); err != nil {
			return err
		}
	}
	if err := gotoolprofile.VerifySourceInventory(consumer.Context, owner.Proof.Candidate, consumer.Dir); err != nil {
		return err
	}
	for _, bound := range owner.Modules {
		if bound == nil {
			return fmt.Errorf("ordinary dependency source owner has no bound module")
		}
		if err := gotoolprofile.VerifyTestModuleSource(consumer.Context, bound.Source, bound.Root, bound.ZIP); err != nil {
			return err
		}
		for filename, canonical := range bound.Metadata {
			actual, err := sourcepath.Resolve(filename)
			if err != nil || actual != canonical {
				return fmt.Errorf("ordinary dependency metadata path changed")
			}
			if err := gotoolprofile.VerifyTestModuleGoModMetadata(bound.Source, bound.Root, filename, bound.DownloadedGoMod); err != nil {
				return err
			}
		}
	}
	return nil
}

func (consumer *featureConsumer) verifyOrdinaryEmbedPackage(pkg *packages.Package) error {
	owner := consumer.OrdinaryDependencies
	if owner == nil || pkg == nil {
		return fmt.Errorf("ordinary dependency lacks a live independently bound source owner")
	}
	bound, present := owner.Packages[pkg.PkgPath]
	if !present || pkg.ID != pkg.PkgPath || isTestVariantPackage(pkg) {
		return fmt.Errorf("ordinary dependency embed package changed its role")
	}
	if ordinaryDependencyActualRoot(consumer, pkg) != bound.ObservedRoot {
		return fmt.Errorf("ordinary dependency actual module source root changed")
	}
	actual, err := captureOrdinaryPackageEmbedSelection(bound.Source.Package, bound.ObservedRoot, bound.Root, pkg)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual, bound.Source.Embed) {
		return fmt.Errorf("ordinary dependency embed selection changed")
	}
	return nil
}

func (consumer *featureConsumer) finishOrdinaryDependencies(pkgs []*packages.Package) error {
	owner := consumer.OrdinaryDependencies
	if owner == nil || len(pkgs) == 0 {
		return fmt.Errorf("ordinary dependency compiler load lacks a live source owner")
	}
	var captureErr error
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if captureErr != nil {
			return false
		}
		bound, found := owner.Packages[pkg.PkgPath]
		if !found {
			captureErr = fmt.Errorf("ordinary source closure changed during compiler loading")
			return false
		}
		if bound.Source.Builtin == "" {
			digest, err := gotoolprofile.FileSHA256(pkg.ExportFile)
			if err != nil {
				captureErr = err
				return false
			}
			if err := consumer.retainGeneratedGuard(map[string]string{pkg.ExportFile: digest}); err != nil {
				captureErr = err
				return false
			}
			if bound.Source.SourceRootID != "" {
				bound.Source.ExportSHA256 = digest
			}
			owner.Packages[pkg.PkgPath] = bound
		}
		return true
	}, nil)
	if captureErr != nil {
		return captureErr
	}
	for index, source := range owner.Proof.ExternalPackages {
		owner.Proof.ExternalPackages[index] = owner.Packages[source.Package.PackagePath].Source
	}
	if err := consumer.verifyOrdinaryOwner(owner); err != nil {
		return err
	}
	owner.Compiled = true
	return nil
}

func (consumer *featureConsumer) ordinaryDependencyProof() (*gotoolprofile.OrdinaryDependencyProof, error) {
	if consumer == nil || consumer.Proof == nil || consumer.Input == nil || consumer.OrdinaryDependencies == nil ||
		!consumer.OrdinaryDependencies.Compiled || consumer.OrdinaryDependencies.Proof == nil {
		return nil, fmt.Errorf("ordinary compiler metadata lacks its completed live dependency source owner")
	}
	if err := consumer.verifyOrdinaryOwner(consumer.OrdinaryDependencies); err != nil {
		return nil, err
	}
	return consumer.OrdinaryDependencies.Proof, nil
}
