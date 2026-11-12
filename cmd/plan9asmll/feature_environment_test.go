package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestFeatureConsumerFixturePreparesSelectedCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "new-cache")
	t.Setenv("GOENV", "off")
	t.Setenv("GOCACHE", cache)
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatalf("cache fixture already exists: %v", err)
	}
	before := os.Environ()
	input, _ := featureConsumerFixture(t)
	if input.Observed == nil {
		t.Fatal("fixture omitted its actual Go observation")
	}
	if info, err := os.Stat(cache); err != nil || !info.IsDir() {
		t.Fatalf("actual selected cache was not prepared: %v", err)
	}
	if !reflect.DeepEqual(before, os.Environ()) {
		t.Fatal("fixture changed the producer's original environment")
	}
}

func TestFeatureConsumerResolvesOrdinaryEnvironmentBeforeSelection(t *testing.T) {
	t.Setenv("GOENV", "off")
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		t.Setenv(key, "")
	}
	input, directory := featureConsumerFixture(t)
	t.Chdir(directory)
	before := os.Environ()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
	if err != nil {
		t.Fatal(err)
	}
	values := make(map[string]string)
	for _, entry := range consumer.Env {
		key, value, _ := strings.Cut(entry, "=")
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate effective environment key %s", key)
		}
		values[key] = value
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		if !filepath.IsAbs(values[key]) {
			t.Errorf("feature selection lacks its actual %s directory: %q", key, values[key])
			continue
		}
		if info, err := os.Stat(values[key]); err != nil || !info.IsDir() {
			t.Errorf("feature selection %s directory does not exist: %v", key, err)
		}
	}
	for key, want := range map[string]string{
		"GOENV": "off", "GOWORK": "off", "GOFLAGS": "",
		"GOAMD64": "v3", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
		"GOOS": "linux", "GOARCH": "amd64",
	} {
		if values[key] != want {
			t.Errorf("feature selection changed %s: got %q, want %q", key, values[key], want)
		}
	}
	if !reflect.DeepEqual(before, os.Environ()) {
		t.Fatal("feature selection mutated the process environment")
	}
	if t.Failed() {
		return
	}
	packages, environment, err := loadPkgsInEnvironment("linux", "amd64", []string{"."}, nil, input.Module, true, false, consumer)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(environment, consumer.Env) {
		t.Fatal("package selection changed the reobserved feature environment")
	}
	if err := consumer.capturePackages(packages); err != nil {
		t.Fatal(err)
	}
	if consumer.ID != input.ID || len(consumer.Proof.Packages) != 1 {
		t.Fatal("resolving execution paths changed the actual feature/source profile")
	}
	if files := consumer.Proof.Packages[0].CompiledGoFiles; len(files) != 1 || files[0] != "selected.go" {
		t.Fatalf("actual v3 source selection changed: %v", files)
	}
}
