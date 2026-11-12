//go:build !windows

package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func ciNodeTransportFixture(t *testing.T, body string) (config, string, string) {
	t.Helper()
	directory := t.TempDir()
	node := filepath.Join(directory, "node")
	if err := os.WriteFile(node, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory)
	for _, key := range []string{"NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA"} {
		t.Setenv(key, "")
	}
	return config{Dir: directory, Timeout: time.Second}, filepath.Join(directory, "before"), node
}

// These are independent command-transport controls, not execution evidence for
// the actual Node interpreter or the ARM64 assembly/C oracle.
func TestCINodeDependencyRecordsVersionAndOrigin(t *testing.T) {
	for _, row := range []struct {
		name, body string
		failure    bool
	}{
		{"valid", "printf 'v24.10.0\\n'\n", false},
		{"wrong-version-output", "printf 'not-a-version\\n'\n", true},
		{"tool-failure", "exit 7\n", true},
	} {
		t.Run(row.name, func(t *testing.T) {
			cfg, stem, node := ciNodeTransportFixture(t, row.body)
			origins := map[string]string{}
			err := captureCINodeDependency(context.Background(), cfg, stem, origins)
			if (err != nil) != row.failure {
				t.Fatalf("observation error=%v; want failure=%t", err, row.failure)
			}
			if err != nil {
				return
			}
			if origins["node"] != node {
				t.Fatal("selected tool origin was not retained")
			}
			got, err := ciFileSHA(origins["node"])
			want := fmt.Sprintf("%x", sha256.Sum256([]byte("#!/bin/sh\n"+row.body)))
			if err != nil || got != want {
				t.Fatal("scope hash does not bind actual executable bytes", got, err)
			}
		})
	}
}

func TestCINodeDependencyRejectsMissingOrDelegatedRuntime(t *testing.T) {
	for _, key := range []string{"PATH", "NODE_OPTIONS", "NODE_PATH", "NODE_ICU_DATA"} {
		t.Run(key, func(t *testing.T) {
			cfg, stem, _ := ciNodeTransportFixture(t, "printf 'v24.10.0\\n'\n")
			value := "unobserved-delegation"
			if key == "PATH" {
				value = ""
			}
			t.Setenv(key, value)
			if err := captureCINodeDependency(context.Background(), cfg, stem, map[string]string{}); err == nil {
				t.Fatal("missing/delegated runtime acquired a successful observation")
			}
		})
	}
}
