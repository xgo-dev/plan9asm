package gostaticstorage

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func snapshotFixtureDirectory(t *testing.T) string {
	t.Helper()
	directory, err := sourcepath.Resolve(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestStaticStorageCapturePreservesSourceInventoryDiagnostic(t *testing.T) {
	directory := snapshotFixtureDirectory(t)
	for index := 0; index < 257; index++ {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("source-%03d.go", index)), []byte("package fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	request := Request{GoBinary: filepath.Join(directory, "go"), Directory: directory,
		PackagePath: "example.invalid/fixture", Target: "linux/amd64", Variables: []Reference{{"example.invalid/fixture", "V"}}}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		request.Environment = append(request.Environment, key+"="+directory)
	}
	observation, err := Capture(context.Background(), request)
	if observation != nil {
		observation.Close()
	}
	if !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "source inventory bound exceeded") {
		t.Fatal("underlying source inventory failure was discarded", err)
	}
}

func TestStaticStorageSourceInventoryRoleBounds(t *testing.T) {
	for _, test := range []struct {
		protocol string
		files    int
		bytes    int64
	}{
		{Protocol, 256, 16 << 20},
		{SDKCPUProtocol, 256, 16 << 20},
		{SDKGlobalsProtocol, 4096, 64 << 20},
		{"unknown", 256, 16 << 20},
	} {
		t.Run(test.protocol, func(t *testing.T) {
			budget := sourceBudget(test.protocol)
			if budget.files != test.files || budget.bytes != test.bytes {
				t.Fatal("source role borrowed another inventory budget", budget)
			}
			if err := budget.checkBytes(test.bytes-1, 1); err != nil {
				t.Fatal("exact complete byte boundary", err)
			}
			for _, test := range []struct {
				total  int64
				length int
			}{{test.bytes, 1}, {test.bytes + 1, 0}, {0, 16<<20 + 1}} {
				if !errors.Is(budget.checkBytes(test.total, test.length), ErrContext) {
					t.Fatal("over-bound bytes acquired source authority", test)
				}
			}
			source := make(map[string][]byte)
			for index := 0; index < test.files; index++ {
				source[fmt.Sprintf("source-%04d.go", index)] = nil
			}
			if err := validateSourceInventory(source, test.protocol); err != nil {
				t.Fatal("exact complete count boundary", err)
			}
			// Selected dependencies consume the same budget as the whole
			// original primary tree, never a second unlimited inventory.
			source["_sdk/dep/extra.go"] = nil
			if !errors.Is(validateSourceInventory(source, test.protocol), ErrContext) {
				t.Fatal("selected dependency bypassed shared complete count bound")
			}
			block := make([]byte, 16<<20)
			complete := make(map[string][]byte)
			for index := int64(0); index < test.bytes/(16<<20); index++ {
				complete[fmt.Sprintf("input-%d.go", index)] = block
			}
			if err := validateSourceInventory(complete, test.protocol); err != nil {
				t.Fatal("exact complete aggregate byte boundary", err)
			}
			complete["_sdk/dep/extra.go"] = []byte{1}
			if !errors.Is(validateSourceInventory(complete, test.protocol), ErrContext) {
				t.Fatal("selected dependency bypassed shared complete byte bound")
			}
		})
	}
}

func TestStaticStorageSnapshotRetainsCompleteRecursiveTree(t *testing.T) {
	directory := snapshotFixtureDirectory(t)
	for index := 0; index < 4096; index++ {
		name := fmt.Sprintf("nested/package/testdata/input-%04d", index)
		file := filepath.Join(directory, filepath.FromSlash(name))
		if index == 0 {
			if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(file, []byte(name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, protocol := range []string{Protocol, SDKCPUProtocol} {
		if _, err := snapshot(directory, protocol); !errors.Is(err, ErrContext) {
			t.Fatal("small module/CPU source role widened", protocol, err)
		}
	}
	source, err := snapshot(directory, SDKGlobalsProtocol)
	if err != nil || len(source) != 4096 || string(source["nested/package/testdata/input-4095"]) != "nested/package/testdata/input-4095" {
		t.Fatal("complete recursive SDK original tree omitted a member", len(source), err)
	}
	if err := os.WriteFile(filepath.Join(directory, "extra.go"), []byte("package extra\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshot(directory, SDKGlobalsProtocol); !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "source inventory bound exceeded") {
		t.Fatal("over-bound SDK recursive tree accepted", err)
	}
	// Verify uses that identical source budget and preserves its cause. It
	// fails before any actual command and permanently revokes this test state.
	observation := &Observation{ready: true, request: Request{Directory: directory}, report: Report{Protocol: SDKGlobalsProtocol}}
	encoded, err := json.Marshal(observation.report)
	if err != nil {
		t.Fatal(err)
	}
	observation.seal = sha256.Sum256(encoded)
	if err := observation.Verify(context.Background()); !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "source inventory bound exceeded") {
		t.Fatal("live snapshot discarded its identical original source bound", err)
	}
	if err := observation.Verify(context.Background()); !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "revoked") {
		t.Fatal("failed source inventory revived the observation", err)
	}
}

func TestStaticStorageSourceRootAndCPUFailuresRetainCause(t *testing.T) {
	directory := snapshotFixtureDirectory(t)
	request := Request{GoBinary: filepath.Join(directory, "bin", "go"), Directory: filepath.Join(directory, "missing"),
		PackagePath: "example.invalid/fixture", Target: "linux/amd64", Variables: []Reference{{"example.invalid/fixture", "V"}}}
	if _, err := Capture(context.Background(), request); !errors.Is(err, ErrContext) || !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing original source root lost its actual filesystem cause", err)
	}
	request.Directory, request.PackagePath = filepath.Join(directory, "src", "internal", "cpu"), "internal/cpu"
	if err := os.MkdirAll(request.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"GOCACHE", "GOMODCACHE", "GOPATH", "TMPDIR", "GOTMPDIR"} {
		request.Environment = append(request.Environment, key+"="+directory)
	}
	if _, err := CaptureSDKCPU(context.Background(), request); !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "original SDK CPU source inventory differs") {
		t.Fatal("pinned SDK CPU source role failure was discarded", err)
	}
}

func TestStaticStorageSourceUsageRejectsBeforeAddition(t *testing.T) {
	for _, protocol := range []string{Protocol, SDKCPUProtocol, SDKGlobalsProtocol} {
		t.Run(protocol, func(t *testing.T) {
			budget := sourceBudget(protocol)
			usage := sourceInventoryUsage{budget: budget, files: budget.files, bytes: 1}
			before := usage
			if !errors.Is(usage.add(1), ErrContext) || usage != before {
				t.Fatal("failed count addition altered retained inventory", usage)
			}
			usage.files, usage.bytes = 1, budget.bytes
			before = usage
			if !errors.Is(usage.add(1), ErrContext) || usage != before {
				t.Fatal("failed byte addition altered retained inventory", usage)
			}
			usage.bytes = budget.bytes - 1
			if err := usage.add(1); err != nil || usage.files != 2 || usage.bytes != budget.bytes {
				t.Fatal("exact complete boundary addition differs", usage, err)
			}
			original := map[string][]byte{"primary.go": {1, 2}, "_sdk/dep/dep.go": {3}}
			usage, err := sourceUsage(original, protocol)
			if err != nil || usage.files != 2 || usage.bytes != 3 {
				t.Fatal("complete initial primary/dependency accounting differs", usage, err)
			}
		})
	}
}
