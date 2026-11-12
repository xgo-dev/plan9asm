//go:build go1.27

package gostaticstorage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoSDKGlobalCompleteRuntimeSourceInventory(t *testing.T) {
	_, binary, _ := fixture(t)
	directory := filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "runtime")
	var count, total int
	err := filepath.WalkDir(directory, func(name string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		count++
		total += len(data)
		return nil
	})
	if err != nil || count <= 256 {
		t.Fatal("actual complete runtime counterexample absent", count, err)
	}
	observation, err := CaptureSDKGlobals(context.Background(), Request{
		GoBinary: binary, Directory: directory, PackagePath: "runtime", Target: "linux/amd64",
		Environment: fixtureEnv(t, "linux/amd64"), Variables: []Reference{{"runtime", "worldsema"}},
	})
	if err != nil {
		t.Fatal("complete actual SDK runtime source/storage capture", err)
	}
	defer observation.Close()
	report, err := observation.Readback(context.Background())
	if err != nil || ValidateReport(report) != nil {
		t.Fatal("complete original runtime report", err)
	}
	primaryCount, primaryBytes := 0, 0
	err = filepath.WalkDir(directory, func(name string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(directory, name)
		if err != nil || !bytes.Equal(report.Source[filepath.ToSlash(rel)], data) {
			t.Fatalf("original runtime member omitted/changed: %s (%v)", rel, err)
		}
		primaryCount++
		primaryBytes += len(data)
		return nil
	})
	if err != nil || primaryCount != count || primaryBytes != total {
		t.Fatal("complete recursive original inventory changed", err)
	}
	variable := report.Variables[0]
	if variable.NativeName != "runtime.worldsema" || variable.Size != 4 || variable.Kind != 5 ||
		len(variable.Numerical) != 1 || variable.Numerical[0] != (Span{0, 4}) {
		t.Fatal("actual original compiler/type numerical storage differs", variable)
	}
	// Unselected/test/nested originals remain live input guards. Matching
	// self-reported hashes cannot authenticate omission or edited bytes.
	for _, key := range []string{"asm_amd64.s", "sys_linux_amd64.s", "testdata/testprog/abort.go", "asm_arm64.s", "_sdk/internal/abi/abi.go"} {
		t.Run(key, func(t *testing.T) {
			if report.Source[key] == nil {
				t.Fatal("original input is absent", key)
			}
			changed := cloneReport(t, report)
			delete(changed.Source, key)
			delete(changed.SourceSHA256, key)
			if !errors.Is(observation.CheckReport(context.Background(), changed), ErrContext) {
				t.Fatal("omitted complete original member acquired authority", key)
			}
		})
	}
	for _, name := range []string{"iscgo", "g0", "cgoTraceback"} {
		t.Run("unsupported-storage-"+name, func(t *testing.T) {
			bad, err := CaptureSDKGlobals(context.Background(), Request{
				GoBinary: binary, Directory: directory, PackagePath: "runtime", Target: "linux/amd64",
				Environment: fixtureEnv(t, "linux/amd64"), Variables: []Reference{{"runtime", name}},
			})
			if bad != nil {
				bad.Close()
			}
			if !errors.Is(err, ErrContext) || strings.Contains(err.Error(), "source inventory bound") ||
				!strings.Contains(err.Error(), "aliased/linkname storage role") && !strings.Contains(err.Error(), "pointer-free variable") {
				t.Fatal("runtime source budget created an unsupported native storage role", name, err)
			}
		})
	}
	t.Run("offline-shared-count-bound", func(t *testing.T) {
		changed := cloneReport(t, report)
		for index := 0; len(changed.Source) <= 4096; index++ {
			name := fmt.Sprintf("_sdk/dep/extra-%04d.go", index)
			changed.Source[name], changed.SourceSHA256[name] = []byte{}, digest(nil)
		}
		if err := ValidateReport(changed); !errors.Is(err, ErrContext) || !strings.Contains(err.Error(), "source inventory bound exceeded") {
			t.Fatal("offline report lost the shared complete source count bound", err)
		}
	})
	t.Logf("complete runtime original inventory: files=%d bytes=%d; complete selected graph files=%d", count, total, len(report.Source))
}

func TestGoSDKGlobalRuntimeSourceAllTargets(t *testing.T) {
	_, binary, _ := fixture(t)
	directory := filepath.Join(filepath.Dir(filepath.Dir(binary)), "src", "runtime")
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			environment := fixtureEnv(t, target)
			// The discovering host-default numerical retry retains CGO=1.
			// Its runtime graph is still independently required to be pure Go.
			if target == "linux/amd64" {
				for index, pair := range environment {
					if strings.HasPrefix(pair, "CGO_ENABLED=") {
						environment[index] = "CGO_ENABLED=1"
					}
				}
			}
			observation, err := CaptureSDKGlobals(context.Background(), Request{
				GoBinary: binary, Directory: directory, PackagePath: "runtime", Target: target,
				Environment: environment, Variables: []Reference{{"runtime", "worldsema"}},
			})
			if err != nil {
				t.Fatal("complete actual target SDK runtime source/storage capture", err)
			}
			defer observation.Close()
			report, err := observation.Readback(context.Background())
			if err != nil || ValidateReport(report) != nil || len(report.Source) <= 256 ||
				report.Source["asm_amd64.s"] == nil || report.Source["testdata/testprog/abort.go"] == nil ||
				len(report.Variables) != 1 || report.Variables[0].NativeName != "runtime.worldsema" || report.Variables[0].Size != 4 {
				t.Fatal("complete target runtime inventory/source/native storage differs", err)
			}
			if target == "linux/amd64" && (report.Environment["CGO_ENABLED"] != "1" || report.CommandEnvironment["CGO_ENABLED"] != "1") {
				t.Fatal("runtime original profile was replaced with CGO=0")
			}
			t.Logf("complete actual %s runtime source graph: files=%d", target, len(report.Source))
		})
	}
}
