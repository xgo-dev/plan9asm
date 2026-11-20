package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This fixture exercises the compact shape plus the real public SumDB proof.
// Its local source inventory is not the authenticated AEZ archive. Production
// still has to compare the whole actual ZIP and selected bytes independently.
func legacyTestModuleShape(t *testing.T) TestModuleSource {
	t.Helper()
	source, _, _ := testDependencyModuleFixture(t)
	proof := fixtureProxyGoMod(t)
	delete(source.Sources, "go.mod")
	for index, entry := range source.Directories["."] {
		if entry.Name == "go.mod" {
			source.Directories["."] = append(source.Directories["."][:index], source.Directories["."][index+1:]...)
			break
		}
	}
	source.SourceModule, source.SourceVersion = proof.Module, proof.Version
	source.ModuleSum, source.GoModSum, source.GoModSHA256 = proof.ModuleSum, proof.GoModSum, proof.SHA256
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	fields["go_mod_origin"], fields["proxy_go_mod"] = ProxyGoModProtocol, proof
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &source); err != nil {
		t.Fatal(err)
	}
	return source
}

func TestTestDependencyLegacyAuthenticatedMetadataShape(t *testing.T) {
	source := legacyTestModuleShape(t)
	if err := ValidateTestModuleSource(cloneTestModuleSource(t, source)); err != nil {
		t.Fatal("authenticated metadata outside an original ZIP must retain its own origin:", err)
	}
}

func TestTestDependencyGoModOriginCannotBeDeleted(t *testing.T) {
	source, _, _ := testDependencyModuleFixture(t)
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	delete(fields, "go_mod_origin")
	delete(fields, "proxy_go_mod")
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	var replay TestModuleSource
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTestModuleSource(replay); err == nil {
		t.Fatal("paired deletion of metadata-origin fields downgraded a current source-root proof")
	}
}

func TestTestDependencyLegacyMetadataMutations(t *testing.T) {
	source := legacyTestModuleShape(t)
	for name, mutate := range map[string]func(*TestModuleSource){
		"old root protocol": func(p *TestModuleSource) { p.Protocol = "actual_go_test_dependency_module_sources_v1" },
		"unknown origin":    func(p *TestModuleSource) { p.GoModOrigin = "local_metadata" },
		"missing origin and signature": func(p *TestModuleSource) {
			p.GoModOrigin, p.ProxyGoMod = "", nil
		},
		"missing signature":     func(p *TestModuleSource) { p.ProxyGoMod = nil },
		"changed module":        func(p *TestModuleSource) { p.SourceModule += "/other" },
		"changed version":       func(p *TestModuleSource) { p.SourceVersion = "v1.0.0" },
		"changed ZIP h1":        func(p *TestModuleSource) { p.ModuleSum = p.GoModSum },
		"changed metadata h1":   func(p *TestModuleSource) { p.GoModSum = p.ModuleSum },
		"changed metadata hash": func(p *TestModuleSource) { p.GoModSHA256 = strings.Repeat("0", 64) },
		"forged ZIP member":     func(p *TestModuleSource) { p.Sources["go.mod"] = p.GoModSHA256 },
		"forged ZIP directory entry": func(p *TestModuleSource) {
			p.Directories["."] = append(p.Directories["."], TestSourceEntry{Name: "go.mod", Kind: "file", SHA256: p.GoModSHA256})
		},
		"proxy marked original ZIP": func(p *TestModuleSource) { p.GoModOrigin = TestModuleOriginalGoModOrigin },
		"changed signed metadata":   func(p *TestModuleSource) { p.ProxyGoMod.Contents += "//changed\n" },
		"unsigned tree":             func(p *TestModuleSource) { p.ProxyGoMod.SignedTree = "" },
		"missing inclusion":         func(p *TestModuleSource) { p.ProxyGoMod.Inclusion = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTestModuleSource(t, source)
			mutate(&changed)
			if err := ValidateTestModuleSource(changed); err == nil {
				t.Fatal("changed or deleted legacy identity acquired source-root authority")
			}
		})
	}
	_, root, archive := testDependencyModuleFixture(t)
	// A valid public metadata record cannot authenticate a different local
	// archive. Recompute only its physical hash to reach the actual h1 guard.
	source.ZipSHA256, _ = FileSHA256(archive)
	if err := verifyTestModuleZIP(context.Background(), source, archive); err == nil {
		t.Fatal("a self-consistent source/ZIP snapshot replaced the signed original module h1")
	}
	if err := VerifyTestModuleSource(context.Background(), source, root, archive); err == nil {
		t.Fatal("proxy metadata bypassed complete actual source directory and ZIP verification")
	}
}

func TestTestDependencyLegacyActualMetadataPathAndBytes(t *testing.T) {
	source := legacyTestModuleShape(t)
	root, metadata := t.TempDir(), filepath.Join(t.TempDir(), "authenticated.mod")
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	write := func(filename string) {
		t.Helper()
		if err := os.WriteFile(filename, []byte(source.ProxyGoMod.Contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(metadata)
	if err := VerifyTestModuleGoModMetadata(source, root, metadata, metadata); err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(t.TempDir(), "equal.mod")
	write(copy)
	if err := VerifyTestModuleGoModMetadata(source, root, copy, metadata); err == nil {
		t.Fatal("equal bytes at a different actual Module.GoMod path retained proxy origin")
	}
	inside := filepath.Join(root, "proxy.mod")
	write(inside)
	if err := VerifyTestModuleGoModMetadata(source, root, inside, inside); err == nil {
		t.Fatal("proxy metadata inside the original archive acquired an external role")
	}
	redirect := filepath.Join(t.TempDir(), "redirect.mod")
	if err := os.Symlink(metadata, redirect); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTestModuleGoModMetadata(source, root, redirect, metadata); err == nil {
		t.Fatal("redirected metadata retained its actual regular source role")
	}
	if err := os.WriteFile(metadata, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTestModuleGoModMetadata(source, root, metadata, metadata); err == nil {
		t.Fatal("metadata bytes changed after authentication without failing")
	}
}

func TestTestDependencyLegacyPackageRoleRequiresMatchingOrigin(t *testing.T) {
	root := legacyTestModuleShape(t)
	input := &ConsumerInput{Module: "example.invalid/main", Version: "v1.0.0"}
	source := TestSourcePackage{
		Package: PackageProof{
			PackagePath: root.SourceModule, ModulePath: root.SourceModule, ModuleVersion: root.SourceVersion,
			SourceModule: root.SourceModule, SourceVersion: root.SourceVersion, SourceRole: "module",
			GoModOrigin: root.GoModOrigin, GoModSHA256: root.GoModSHA256, GoModSum: root.GoModSum,
		},
		SourceRootID: root.ID(), ExportSHA256: strings.Repeat("a", 64),
	}
	roots := map[string]TestModuleSource{root.ID(): root}
	if _, err := testDependencyPackageInput(input, source, roots); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TestSourcePackage){
		"deleted package origin":   func(p *TestSourcePackage) { p.Package.GoModOrigin = "" },
		"deleted package hash":     func(p *TestSourcePackage) { p.Package.GoModSHA256 = "" },
		"deleted package h1":       func(p *TestSourcePackage) { p.Package.GoModSum = "" },
		"fake original metadata":   func(p *TestSourcePackage) { p.Package.GoModOrigin = TestModuleOriginalGoModOrigin },
		"different source version": func(p *TestSourcePackage) { p.Package.SourceVersion = "v1.0.0" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := source
			mutate(&changed)
			if _, err := testDependencyPackageInput(input, changed, roots); err == nil {
				t.Fatal("package metadata did not match its exact authenticated source root")
			}
		})
	}
}

func TestTestDependencyLegacyMetadataRequiresRealArchive(t *testing.T) {
	source := legacyTestModuleShape(t)
	if source.Sources["go.mod"] != "" {
		t.Fatal("proxy metadata was inserted into the original file inventory")
	}
	for _, entry := range source.Directories["."] {
		if entry.Name == "go.mod" {
			t.Fatal("proxy metadata was inserted into the original directory inventory")
		}
	}
	if strings.Contains(source.ID(), "example.invalid") {
		t.Fatal("fixture lost the actual signed public module identity")
	}
}
