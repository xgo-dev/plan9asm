package main

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestTypedSourceLoadGuardRejectsUnboundRolesWithPackageIdentity(t *testing.T) {
	const path = "example.invalid/query/dep"
	const variant = path + " [example.invalid/query.test]"
	for _, tc := range []struct {
		name         string
		pkg          *packages.Package
		allowedTests map[string]bool
		want         []string
	}{
		{
			name: "missing identity",
			pkg:  &packages.Package{PkgPath: path},
			want: []string{
				`package_id=""`, `package_path="` + path + `"`, `for_test=""`,
				"test_variant=false", "allowed_test=false", "embed_files=0", "embed_patterns=0",
				"used_packages=0", "package_bound=4096",
			},
		},
		{
			name: "embedded files",
			pkg:  &packages.Package{ID: path, PkgPath: path, EmbedFiles: []string{"private/file.bin"}},
			want: []string{
				`package_id="` + path + `"`, `package_path="` + path + `"`,
				"test_variant=false", "embed_files=1", "embed_patterns=0", "used_packages=0",
			},
		},
		{
			name: "embedded patterns",
			pkg:  &packages.Package{ID: path, PkgPath: path, EmbedPatterns: []string{"assets/*", "other/*"}},
			want: []string{
				`package_id="` + path + `"`, `package_path="` + path + `"`,
				"embed_files=0", "embed_patterns=2", "used_packages=0",
			},
		},
		{
			name: "unregistered test variant",
			pkg:  &packages.Package{ID: variant, PkgPath: path, ForTest: "example.invalid/query"},
			want: []string{
				`package_id="` + variant + `"`, `package_path="` + path + `"`,
				`for_test="example.invalid/query"`, "test_variant=true", "allowed_test=false",
				"embed_files=0", "embed_patterns=0", "used_packages=0",
			},
		},
		{
			name:         "registered test does not permit embed",
			pkg:          &packages.Package{ID: variant, PkgPath: path, EmbedFiles: []string{"private/file.bin"}},
			allowedTests: map[string]bool{variant: true},
			want:         []string{"test_variant=true", "allowed_test=true", "embed_files=1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := captureTypedSourceLoadGuard(context.Background(), []*packages.Package{tc.pkg}, tc.allowedTests)
			if err == nil {
				t.Fatal("unbound source role was accepted")
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("diagnostic %q lacks %q", err, want)
				}
			}
			if strings.Contains(err.Error(), "private/file.bin") || strings.Contains(err.Error(), "assets/*") {
				t.Fatal("diagnostic leaked resource paths instead of compact role counts")
			}
		})
	}
}

func TestTypedSourceLoadGuardPackageBoundDiagnostic(t *testing.T) {
	pkgs := make([]*packages.Package, 4097)
	for i := range pkgs {
		path := fmt.Sprintf("example.invalid/query/dep%04d", i)
		pkgs[i] = &packages.Package{ID: path, PkgPath: path}
	}
	guard, err := captureTypedSourceLoadGuard(context.Background(), pkgs, nil)
	if err == nil || len(guard.Packages) != 4096 {
		t.Fatalf("package bound changed: captured=%d, err=%v", len(guard.Packages), err)
	}
	for _, want := range []string{
		`package_id="example.invalid/query/dep4096"`, `package_path="example.invalid/query/dep4096"`,
		"used_packages=4096", "package_bound=4096", "test_variant=false", "embed_files=0", "embed_patterns=0",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("bound diagnostic %q lacks %q", err, want)
		}
	}
}

func TestTypedSourceLoadGuardOrdinaryAndExplicitTestRolesRemainAccepted(t *testing.T) {
	const path = "example.invalid/query/dep"
	const variant = path + " [example.invalid/query.test]"
	for _, tc := range []struct {
		name         string
		pkg          *packages.Package
		allowedTests map[string]bool
	}{
		{name: "ordinary", pkg: &packages.Package{ID: path, PkgPath: path}},
		{name: "explicit same-package test", pkg: &packages.Package{ID: variant, PkgPath: path}, allowedTests: map[string]bool{variant: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			guard, err := captureTypedSourceLoadGuard(context.Background(), []*packages.Package{tc.pkg}, tc.allowedTests)
			if err != nil || len(guard.Packages) != 1 {
				t.Fatalf("previously permitted role rejected: %v", err)
			}
		})
	}
}
