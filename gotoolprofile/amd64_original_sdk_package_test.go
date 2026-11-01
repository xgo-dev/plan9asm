package gotoolprofile

import (
	"os"
	"path/filepath"
	"testing"
)

func originalSDKPackageMemberFixture(t *testing.T) (amd64OriginalListPackage, string, *amd64OriginalObservationFiles) {
	t.Helper()
	return sdkIncludeSourceFixture(t, "// original assembly\n", map[string]string{
		"src/fixture/sdk/value.go":          "package sdk\n",
		"src/fixture/sdk/inactive.go":       "//go:build inactive\n\npackage sdk\n",
		"src/fixture/sdk/value_test.go":     "package sdk\n",
		"src/fixture/sdk/value.h":           "#define VALUE 7\n",
		"src/fixture/sdk/descendant/dep.go": "package descendant\n",
	})
}

func TestAMD64OriginalSDKPackageMembersAreComplete(t *testing.T) {
	pkg, _, files := originalSDKPackageMemberFixture(t)
	for _, name := range []string{"value.go", "inactive.go", "value_test.go", "value_amd64.s", "value.h"} {
		if files.hashes[filepath.Join(pkg.Dir, name)] == "" {
			t.Fatalf("direct source/selection member is unguarded: %s", name)
		}
	}
	nested := filepath.Join(pkg.Dir, "descendant", "dep.go")
	if files.hashes[nested] != "" {
		t.Fatal("unimported descendant acquired a package-input role")
	}
	if err := os.WriteFile(nested, []byte("package descendant\n// unrelated edit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.verify(); err != nil {
		t.Fatal("an unconsumed descendant is not a parent-package source input", err)
	}
	// When the actual graph selects a descendant, its own package role closes
	// every direct member independently. A parent observation cannot replace it.
	selected := amd64OriginalListPackage{Standard: true}
	selected.ImportPath, selected.Dir = pkg.ImportPath+"/descendant", filepath.Dir(nested)
	if err := retainAMD64OriginalPackageDirectory(selected, selected.Dir, files); err != nil {
		t.Fatal(err)
	}
	if files.hashes[nested] == "" {
		t.Fatal("separately selected descendant lost its actual source")
	}
	if err := os.WriteFile(nested, []byte("package descendant\n// selected edit\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := files.verify(); err == nil {
		t.Fatal("changed selected descendant escaped source verification")
	}
}

func TestAMD64OriginalSDKPackageMemberMutationGuards(t *testing.T) {
	for _, name := range []string{"value.go", "inactive.go", "value_test.go", "value_amd64.s", "value.h", "added.go", "added.h"} {
		t.Run(name, func(t *testing.T) {
			pkg, _, files := originalSDKPackageMemberFixture(t)
			if err := os.WriteFile(filepath.Join(pkg.Dir, name), []byte("// changed member\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := files.verify(); err == nil {
				t.Fatal("changed/new package source member escaped verification")
			}
		})
	}
	t.Run("new directory", func(t *testing.T) {
		pkg, _, files := originalSDKPackageMemberFixture(t)
		if err := os.Mkdir(filepath.Join(pkg.Dir, "new"), 0700); err != nil {
			t.Fatal(err)
		}
		if err := files.verify(); err == nil {
			t.Fatal("new source directory escaped complete member verification")
		}
	})
	t.Run("directory identity", func(t *testing.T) {
		pkg, root, files := originalSDKPackageMemberFixture(t)
		if err := os.Rename(pkg.Dir, pkg.Dir+".old"); err != nil {
			t.Fatal(err)
		}
		writeSDKIncludeFixture(t, root, "src/fixture/sdk/value.go", "package sdk\n")
		if err := files.verify(); err == nil {
			t.Fatal("replaced original SDK directory escaped identity verification")
		}
	})
}

func TestAMD64OriginalSDKPackageAncestorAlias(t *testing.T) {
	pkg, root, _ := originalSDKPackageMemberFixture(t)
	_, otherRoot, _ := originalSDKPackageMemberFixture(t)
	alias := filepath.Join(t.TempDir(), "sdk-root")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	pkg.Dir = filepath.Join(alias, "src", "fixture", "sdk")
	files := newAMD64OriginalObservationFiles()
	if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, files); err != nil {
		t.Fatal("stable SDK ancestor alias failed source observation", err)
	}
	if err := files.verify(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(alias, alias+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(otherRoot, alias); err != nil {
		t.Fatal(err)
	}
	if err := files.verify(); err == nil {
		t.Fatal("changed ancestor alias escaped original SDK identity checks")
	}
}

func TestAMD64OriginalSDKPackageDoesNotRelaxOtherRoles(t *testing.T) {
	t.Run("ordinary module tree", func(t *testing.T) {
		pkg, _, _ := originalSDKPackageMemberFixture(t)
		pkg.Standard = false
		files := newAMD64OriginalObservationFiles()
		if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, files); err != nil {
			t.Fatal(err)
		}
		if files.hashes[filepath.Join(pkg.Dir, "descendant", "dep.go")] == "" {
			t.Fatal("ordinary module lost its existing complete source-tree guard")
		}
	})
	t.Run("foreign module SDK", func(t *testing.T) {
		pkg, _, _ := originalSDKPackageMemberFixture(t)
		pkg.Module = &amd64OriginalListModule{Path: "example.invalid/foreign"}
		if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, newAMD64OriginalObservationFiles()); err == nil {
			t.Fatal("module source impersonated the SDK package role")
		}
	})
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file symlink", true: "directory symlink"}[directory], func(t *testing.T) {
			pkg, _, _ := originalSDKPackageMemberFixture(t)
			target := filepath.Join(pkg.Dir, "value.go")
			if directory {
				target = filepath.Join(pkg.Dir, "descendant")
			}
			if err := os.Symlink(target, filepath.Join(pkg.Dir, "alias")); err != nil {
				t.Fatal(err)
			}
			if err := retainAMD64OriginalPackageDirectory(pkg, pkg.Dir, newAMD64OriginalObservationFiles()); err == nil {
				t.Fatal("source-internal symlink acquired a regular member role")
			}
		})
	}
}
