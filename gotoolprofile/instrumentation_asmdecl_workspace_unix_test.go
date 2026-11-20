//go:build unix

package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

// This reuses the signed metadata witness, not a signed external source ZIP.
// The controlled source only tests separation of its physical source root
// from the independent proxy metadata origin.
func TestInstrumentationAsmdeclLegacyMetadataPhysicalRoot(t *testing.T) {
	for _, inside := range []bool{false, true} {
		name := "outside control"
		if inside {
			name = "inside aliased root"
		}
		t.Run(name, func(t *testing.T) {
			input, actual, metadata := instrumentationTypeLegacyMetadataFixture(t)
			physical := input.Original.SourceRoot
			alias := filepath.Join(t.TempDir(), "original-source")
			if err := os.Symlink(physical, alias); err != nil {
				t.Fatal(err)
			}
			input.Original.SourceRoot = alias
			if inside {
				metadata = filepath.Join(physical, "proxy.mod")
				if err := os.WriteFile(metadata, []byte(input.Original.ProxyGoMod.Contents), 0600); err != nil {
					t.Fatal(err)
				}
				input.Original.ProxyGoModPath = metadata
			}
			proof := input.Original.ProxyGoMod
			selected := &PackageProof{
				PackagePath: actual.ImportPath, ModulePath: proof.Module, ModuleVersion: proof.Version,
				SourceModule: proof.Module, SourceVersion: proof.Version, SourceRole: "module",
				GoModOrigin: proof.Protocol, GoModSHA256: proof.SHA256, GoModSum: proof.GoModSum,
				GoFiles: actual.GoFiles, CompiledGoFiles: actual.CompiledGoFiles,
				SourceSHA256: input.Original.Sources,
			}
			pkg := &instrumentationAsmdeclPackage{
				Dir: physical, ImportPath: actual.ImportPath,
				GoFiles: actual.GoFiles, CompiledGoFiles: actual.CompiledGoFiles,
				Module: &instrumentationAsmdeclModule{
					Path: proof.Module, Version: proof.Version, Dir: physical, GoMod: metadata,
				},
			}
			plan := &InstrumentationOriginalPackagePlan{PackagePath: actual.ImportPath, PackageDirectory: "."}
			guards := &instrumentationTypeGraph{hashes: make(map[string]string), paths: make(map[string]string)}
			err := bindInstrumentationAsmdeclSource(input.Original, plan, selected, pkg, &instrumentationAsmdeclConfig{}, guards)
			if inside {
				if err == nil {
					t.Fatal("logical root alias disguised metadata inside the original source root")
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInstrumentationAsmdeclWorkspaceAliasAndConfigRedirection(t *testing.T) {
	for _, scenario := range []string{"control", "alias retarget", "config symlink"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			first, second := filepath.Join(root, "first"), filepath.Join(root, "second")
			for _, name := range []string{first, second} {
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			physical := filepath.Join(first, "owned")
			if err := os.Mkdir(physical, 0700); err != nil {
				t.Fatal(err)
			}
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(first, alias); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(alias, "owned")
			identity, err := os.Lstat(name)
			if err != nil {
				t.Fatal(err)
			}
			physical, err = filepath.EvalSymlinks(name)
			if err != nil {
				t.Fatal(err)
			}
			owned := &instrumentationAsmdeclWorkspace{name: name, physical: physical, identity: identity}
			filename := filepath.Join(name, "ordinary.cfg")
			if err := os.WriteFile(filename, []byte("unchanged config"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := owned.verifyConfig(); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "alias retarget":
				if err := os.Rename(physical, filepath.Join(second, "owned")); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(second, alias); err != nil {
					t.Fatal(err)
				}
				actual, err := os.Lstat(name)
				if err != nil || !os.SameFile(identity, actual) {
					t.Fatal("retarget fixture failed to retain the original directory inode")
				}
			case "config symlink":
				original := filepath.Join(root, "original.cfg")
				if err := os.Rename(filename, original); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(original, filename); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "control" {
				if err := owned.verifyConfig(); err != nil {
					t.Fatal(err)
				}
			} else if err := owned.verifyConfig(); err == nil {
				t.Fatal("same inode/bytes authorized a retargeted alias or config leaf")
			}
			if scenario == "alias retarget" {
				if err := owned.close(os.RemoveAll); err == nil {
					t.Fatal("retargeted alias was deleted")
				}
			} else if err := owned.close(os.RemoveAll); err != nil {
				t.Fatal(err)
			}
		})
	}
}
