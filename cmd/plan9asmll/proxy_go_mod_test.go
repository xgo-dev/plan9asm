package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestFeatureConsumerAllowsAuthenticatedMetadataOutsideOriginalZIP(t *testing.T) {
	data, err := os.ReadFile("../../gotoolprofile/testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof gotoolprofile.ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateProxyGoMod(&proof); err != nil {
		t.Fatal(err)
	}
	root, metadata := t.TempDir(), filepath.Join(t.TempDir(), "proxy.mod")
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	source := []byte("package fixture\n")
	if err := os.WriteFile(filepath.Join(root, "source.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &featureConsumer{Context: context.Background(), Dir: root,
		Input: &featureInput{Module: proof.Module, SourceModule: proof.Module, Version: proof.Version,
			Sources: map[string]string{"source.go": featureBytesSHA256(source)}, Directories: map[string][]string{".": {"source.go"}},
			ProxyGoMod: &proof, ProxyGoModPath: metadata,
		},
	}
	if err := consumer.verifySources(); err != nil {
		t.Fatalf("signed external metadata is not a ZIP go.mod requirement: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); !os.IsNotExist(err) {
		t.Fatal("legacy metadata was injected into the original source tree")
	}
	if err := os.WriteFile(metadata, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifySources(); err == nil {
		t.Fatal("changed proxy metadata retained its source authentication")
	}
}

func TestFeatureConsumerCapturesTheActualProxyMetadataOrigin(t *testing.T) {
	input, dir := featureConsumerFixture(t)
	data, err := os.ReadFile("../../gotoolprofile/testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof gotoolprofile.ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	// The ordinary source files are owned fixtures, not executed library code.
	// Removing this exact t.TempDir member models an original ZIP without it.
	if err := os.Remove(filepath.Join(dir, "go.mod")); err != nil {
		t.Fatal(err)
	}
	delete(input.Sources, "go.mod")
	input.Directories["."] = []string{"fallback.go", "probe_amd64.s", "selected.go"}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "proxy.mod")
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	input.Module, input.SourceModule, input.Version = proof.Module, proof.Module, proof.Version
	input.SourceRoot, input.ProxyGoMod, input.ProxyGoModPath = dir, &proof, metadata
	consumer := &featureConsumer{
		Context: context.Background(), Dir: dir,
		Input: input, Observed: input.Observed, Proof: new(featureSelectionProof),
	}
	pkg := &packages.Package{
		PkgPath: proof.Module,
		Module:  &packages.Module{Path: proof.Module, Version: proof.Version, Dir: dir, GoMod: metadata},
		GoFiles: []string{filepath.Join(dir, "selected.go")}, CompiledGoFiles: []string{filepath.Join(dir, "selected.go")},
		OtherFiles: []string{filepath.Join(dir, "probe_amd64.s")},
	}
	// CaptureAssemblerMacros is bound to the actual Go source root observation.
	root, _, err := testFeatureRunner(context.Background(), "", os.Environ(), "go", "env", "GOROOT")
	if err != nil {
		t.Fatal(err)
	}
	consumer.Root = strings.TrimSpace(string(root))
	if err := consumer.capturePackages([]*packages.Package{pkg}); err != nil {
		t.Fatal(err)
	}
	actual := consumer.Proof.Packages[0]
	if actual.GoModOrigin != proof.Protocol || actual.GoModSHA256 != proof.SHA256 || actual.GoModSum != proof.GoModSum {
		t.Fatalf("actual metadata origin was omitted: %#v", actual)
	}
	other := filepath.Join(t.TempDir(), "other.mod")
	if err := os.WriteFile(other, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	pkg.Module.GoMod = other
	if err := consumer.capturePackages([]*packages.Package{pkg}); err == nil {
		t.Fatal("equal bytes at another actual metadata source were accepted")
	}
}
