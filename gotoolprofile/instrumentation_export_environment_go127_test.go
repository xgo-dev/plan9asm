//go:build go1.27

package gotoolprofile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This exercises the production post-export file guard with unchanged actual
// SDK bytes copied into an owned directory. It is not another Go export or
// runtime certificate, and never changes the installed SDK.
func TestInstrumentationExportEnvironmentActualSDKPostCaptureGuards(t *testing.T) {
	for _, scenario := range []string{
		"unchanged", "driver bytes", "cache-copy producer bytes", "bootstrap bytes", "bootstrap default",
		"SDK environment bytes", "SDK environment removed",
		"absent environment created empty", "empty environment removed",
	} {
		t.Run(scenario, func(t *testing.T) {
			root := instrumentationExportOwnedSDKSourceFixture(t)
			environmentFile := filepath.Join(root, "go.env")
			if scenario == "absent environment created empty" {
				if err := os.Remove(environmentFile); err != nil && !os.IsNotExist(err) {
					t.Fatal(err)
				}
			}
			if scenario == "empty environment removed" {
				if err := os.WriteFile(environmentFile, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := captureInstrumentationExportEnvironment(root, runtime.Version())
			if err != nil {
				t.Fatal(err)
			}
			if err := recheckInstrumentationExportEnvironmentSources(root, runtime.Version(), before); err != nil {
				t.Fatalf("unchanged actual source guard: %v", err)
			}

			switch scenario {
			case "cache-copy producer bytes":
				instrumentationExportRewriteOwnedFile(t, root, "src/cmd/go/internal/work/buildid.go", func(data string) string {
					return data + "\n// changed after capture\n"
				})
			case "driver bytes":
				instrumentationExportRewriteOwnedFile(t, root, "src/cmd/go/internal/work/shell.go", func(data string) string {
					return data + "\n// changed after capture\n"
				})
			case "bootstrap bytes":
				instrumentationExportRewriteOwnedFile(t, root, instrumentationBootstrapSource, func(data string) string {
					return data + "\n// changed after capture\n"
				})
			case "bootstrap default":
				instrumentationExportRewriteOwnedFile(t, root, instrumentationBootstrapSource, func(data string) string {
					return strings.Replace(data, "`v1`", "`v2`", 1)
				})
			case "SDK environment bytes":
				if err := os.WriteFile(environmentFile, []byte("GOAMD64=v2\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "SDK environment removed", "empty environment removed":
				if err := os.Remove(environmentFile); err != nil {
					t.Fatal(err)
				}
			case "absent environment created empty":
				if err := os.WriteFile(environmentFile, nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err = recheckInstrumentationExportEnvironmentSources(root, runtime.Version(), before)
			if scenario == "unchanged" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("post-capture SDK source/default/environment mutation was accepted")
			}
		})
	}
}

func instrumentationExportOwnedSDKSourceFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	names := []string{instrumentationBootstrapSource, "go.env"}
	for name := range instrumentationExportEnvironmentSourceRegistration {
		names = append(names, name)
	}
	for _, name := range names {
		data, err := readInstrumentationRegistration(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
		if name == "go.env" && os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func instrumentationExportRewriteOwnedFile(t *testing.T, root, name string, rewrite func(string) string) {
	t.Helper()
	filename := filepath.Join(root, filepath.FromSlash(name))
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	changed := rewrite(string(data))
	if changed == string(data) {
		t.Fatal("mutation did not change the actual captured source")
	}
	if err := os.WriteFile(filename, []byte(changed), 0600); err != nil {
		t.Fatal(err)
	}
}
