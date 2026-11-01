package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestModuleInventoryRejectsForeignMissingAndDuplicate(t *testing.T) {
	dir := t.TempDir()
	pkg := map[string]any{
		"ImportPath": "example.org/complete",
		"Dir":        dir,
		"Module":     map[string]any{"Main": true, "Path": "example.org/complete", "Dir": dir, "GoMod": filepath.Join(dir, "go.mod")},
	}
	encode := func(value any) []byte {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	if packages, err := readModulePackages(encode(pkg), dir); err != nil || len(packages) != 1 || !packages[0].NoTestFiles || moduleOwner(packages[0]) != 0 {
		t.Fatalf("actual no-test root inventory: %+v %v", packages, err)
	}
	for _, name := range []string{"empty", "duplicate", "dependency", "escape", "loader-error", "truncated"} {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(encode(pkg), &value); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "dependency":
				value["Module"].(map[string]any)["Main"] = false
			case "escape":
				value["Dir"] = filepath.Dir(dir)
			case "loader-error":
				value["Error"] = map[string]any{"Err": "real loader failure"}
			}
			data := encode(value)
			switch name {
			case "empty":
				data = nil
			case "duplicate":
				data = append(data, data...)
			case "truncated":
				data = data[:len(data)-1]
			}
			if _, err := readModulePackages(data, dir); err == nil {
				t.Fatal("unproved package inventory accepted")
			}
		})
	}
	if got := moduleListFlags([]string{"-race", "-covermode", "atomic", "-tags=owned", "-p=2", "-coverpkg=./...", "-cover"}); !reflect.DeepEqual(got, []string{"-race", "-tags=owned", "-p=2"}) {
		t.Fatalf("test build selection changed for package list: %q", got)
	}
}

func TestModuleCoverageUnionKeepsAllFilesAndChecksCounters(t *testing.T) {
	write := func(name, contents string) string {
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	a := write("a.cover", "mode: atomic\na.go:1.1,2.1 1 3\nshared.go:1.1,2.1 2 4\n")
	b := write("b.cover", "mode: atomic\nb.go:1.1,2.1 1 5\nshared.go:1.1,2.1 2 6\n")
	merged, err := mergeModuleCoverage([]string{a, b})
	if err != nil || string(merged) != "mode: atomic\na.go:1.1,2.1 1 3\nb.go:1.1,2.1 1 5\nshared.go:1.1,2.1 2 10\n" {
		t.Fatalf("module union/overlap arithmetic: %s %v", merged, err)
	}
	for _, malformed := range []string{
		"mode: count\nb.go:1.1,2.1 1 5\n",
		"mode: atomic\nshared.go:1.1,2.1 3 6\n",
		"mode: atomic\nshared.go:1.1,2.1 2 18446744073709551615\n",
		"mode: atomic\nb.go:1.1,2.1 1 5\nb.go:1.1,2.1 1 5\n",
	} {
		if _, err := mergeModuleCoverage([]string{a, write("invalid.cover", malformed)}); err == nil {
			t.Fatalf("mode/statements/overflow/duplicate became valid coverage: %s", malformed)
		}
	}
	// Ordinary per-package coverage still requires its exact unchanged blocks.
	if _, err := mergeCoverage([]string{a, b}); err == nil {
		t.Fatal("module union weakened existing per-package block equality")
	}
}

func TestModuleEmptyPackageEventsRemainStrict(t *testing.T) {
	valid := "{\"Action\":\"start\",\"Package\":\"p\"}\n{\"Action\":\"skip\",\"Package\":\"p\"}\n"
	if _, err := validateSuiteEvents(strings.NewReader(valid), "p", nil, true, true); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{valid, strings.Replace(valid, "skip", "pass", 1), strings.Replace(valid, "skip", "fail", 1), valid + valid} {
		if _, err := validateEvents(strings.NewReader(input), "p", nil); err == nil {
			t.Fatal("ordinary empty inventory protocol changed")
		}
	}
	if _, err := validateSuiteEvents(strings.NewReader(valid), "p", nil, true, false); err == nil {
		t.Fatal("benchmark-only package silently skipped instead of running TestMain")
	}
	for _, input := range []string{valid + valid, strings.Replace(valid, "skip", "fail", 1), strings.Split(valid, "\n")[0] + "\n"} {
		if _, err := validateSuiteEvents(strings.NewReader(input), "p", nil, true, true); err == nil {
			t.Fatal("unknown/partial no-test package accepted")
		}
	}
}
