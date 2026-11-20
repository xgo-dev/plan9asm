package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestTestModuleConsumerCachedLegacyMetadataCannotDisappear(t *testing.T) {
	data, err := os.ReadFile("../../gotoolprofile/testdata/aez_proxy_go_mod.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof gotoolprofile.ProxyGoModProof
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "proxy.mod")
	if err := os.WriteFile(metadata, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	source := gotoolprofile.TestModuleSource{
		Protocol: gotoolprofile.TestDependencyModuleProtocol, SourceModule: proof.Module, SourceVersion: proof.Version,
		ModuleSum: proof.ModuleSum, GoModSum: proof.GoModSum, GoModSHA256: proof.SHA256,
		GoModOrigin: proof.Protocol, ProxyGoMod: &proof, ZipSHA256: strings.Repeat("b", 64),
		Sources: map[string]string{"fixture.go": digest}, Headers: map[string]string{"fixture.go": "package fixture\n"},
		Directories: map[string][]gotoolprofile.TestSourceEntry{
			".": {{Name: "fixture.go", Kind: "file", SHA256: digest}},
		},
	}
	// This models only an already-bound private guard's repeat transition,
	// not authenticating the fixture as that public module's original ZIP.
	consumer := &featureConsumer{TestModuleGuards: map[string]testDependencyModuleGuard{
		source.ID(): {Source: source, Root: root, GoMod: metadata},
	}}
	if err := consumer.bindTestModuleSource(source, root, metadata); err != nil {
		t.Fatal(err)
	}
	if err := consumer.bindTestModuleSource(source, root, ""); err == nil {
		t.Fatal("cached source binding authorized an actual Module.GoMod that disappeared")
	}
	other := filepath.Join(t.TempDir(), "equal.mod")
	if err := os.WriteFile(other, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.bindTestModuleSource(source, root, other); err == nil {
		t.Fatal("cached legacy binding authorized equal metadata at another actual path")
	}
	if err := os.WriteFile(metadata, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.bindTestModuleSource(source, root, metadata); err == nil {
		t.Fatal("cached binding authorized changed actual metadata bytes")
	}
}
