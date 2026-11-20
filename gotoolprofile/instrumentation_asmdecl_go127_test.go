//go:build go1.27

package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationOriginalAsmdeclRetainsExactOrdinarySourceUnit(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t),
		os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input := instrumentationOriginalFixture(t, marker.Early)
	module, err := os.ReadFile(filepath.Join(input.SourceRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod": string(module) + "\nrequire example.invalid/testonly v0.0.0\n" +
			"replace example.invalid/testonly => ./test-dependency-missing\n",
		"poison_test.go": "package markers\nimport _ \"example.invalid/testonly\"\n",
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(input.SourceRoot, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name], input.Headers[name] = bytesSHA256([]byte(source)), source
	}
	input.Directories["."] = append(input.Directories["."], "poison_test.go")
	sort.Strings(input.Directories["."])
	inventory, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, inventory, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	env := instrumentationFixtureEnvironment(os.Environ(), marker.Early)
	_, stderr, err := RunBounded(ctx, input.SourceRoot, env, binary, "vet", "-race", "-asmdecl",
		"-tests=false", "-p=1", "-mod=readonly", plan.PackagePath)
	if err == nil || !strings.Contains(string(stderr), "test-dependency-missing") {
		t.Fatalf("actual cmd/go still-loading-tests control did not fail: %v; %s", err, stderr)
	}
	proof, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(),
		input, inventory, marker, plan, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(proof.Package.GoFiles, []string{"base.go", "mode_race.go"}) ||
		!reflect.DeepEqual(proof.VetArgs, []string{"tool", "vet", "-asmdecl", "ordinary.cfg"}) {
		t.Fatal("ordinary source role was lost or replaced by a filtered test package")
	}

	// Each mutation starts from the actual freshly written config. Even if
	// native vet accepts a modified valid unit, its byte guard must reject it.
	for _, field := range []string{"ID", "GoFiles", "NonGoFiles", "VetxOnly", "SucceedOnTypecheckFailure"} {
		t.Run(field, func(t *testing.T) {
			changed := false
			run := func(ctx context.Context, dir string, env []string, name string, args ...string) ([]byte, []byte, error) {
				if reflect.DeepEqual(args, []string{"tool", "vet", "-asmdecl", "ordinary.cfg"}) {
					filename := filepath.Join(dir, "ordinary.cfg")
					data, err := os.ReadFile(filename)
					if err != nil {
						t.Fatal(err)
					}
					var config map[string]json.RawMessage
					if err := json.Unmarshal(data, &config); err != nil {
						t.Fatal(err)
					}
					switch field {
					case "ID":
						config[field] = json.RawMessage(`"other.invalid/source"`)
					case "GoFiles", "NonGoFiles":
						config[field] = json.RawMessage(`[]`)
					default:
						config[field] = json.RawMessage(`true`)
					}
					data, err = json.Marshal(config)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filename, data, 0600); err != nil {
						t.Fatal(err)
					}
					changed = true
				}
				return RunBounded(ctx, dir, env, name, args...)
			}
			_, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(),
				input, inventory, marker, plan, run)
			if !changed || err == nil {
				t.Fatalf("actual asmdecl config field %s mutation was not independently refused: %v", field, err)
			}
		})
	}
}
