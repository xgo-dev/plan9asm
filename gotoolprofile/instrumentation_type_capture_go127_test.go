//go:build go1.27

package gotoolprofile

// Actual mode export is a current-Go source role. Historical framework lanes
// run the complete portable source/layout tests, not an invented old-mode
// compiler observation; CaptureInstrumentationExportObservation rejects it.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationTypeSourceCaptureActualGoAndOriginMutation(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	original := instrumentationOriginalFixture(t, marker.Early)
	for name, source := range map[string]string{
		"base.go":     "package markers\nimport (renamed \"syscall\"; \"math/bits\")\nfunc marker(value [bits.UintSize / 8]byte) renamed.Errno\n",
		"mode_race.s": "//go:build race\n\n#include \"textflag.h\"\nTEXT ·marker(SB), NOSPLIT, $0-16\nRET\n",
	} {
		if err := os.WriteFile(filepath.Join(original.SourceRoot, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		original.Sources[name], original.Headers[name] = bytesSHA256([]byte(source)), source
	}
	inventory, err := CaptureInstrumentationOriginalSourceInventory(original, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(original, inventory, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewInstrumentationConsumerInput(original, inventory, marker, plan)
	if err != nil {
		t.Fatal(err)
	}
	env := instrumentationFixtureEnvironment(os.Environ(), marker.Early)
	proof, err := CaptureInstrumentationTypeSources(ctx, binary, original.SourceRoot, env, input, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Dependencies) == 0 || proof.RootImportMap["syscall"] != "syscall" || proof.RootImportMap["math/bits"] != "math/bits" {
		t.Fatal("original actual import graph was not preserved")
	}
	retained := make(map[string]bool)
	for _, pkg := range proof.Dependencies {
		if pkg.Contents != nil {
			retained[pkg.Dependency.Source.PackagePath] = true
		}
	}
	if !reflect.DeepEqual(retained, map[string]bool{"syscall": true, "math/bits": true}) {
		t.Fatalf("source capture retained unrelated ASTs or omitted required original source: %v", retained)
	}
	input.TypeSources = proof
	for name, change := range map[string]func(*instrumentationTypeListPackage){
		"SDK root": func(p *instrumentationTypeListPackage) { p.Dir = original.SourceRoot },
		"foreign module": func(p *instrumentationTypeListPackage) {
			p.Module = &instrumentationTypeListModule{Path: "example.invalid/foreign", Version: "v1.0.0", Dir: original.SourceRoot}
		},
		"local replacement": func(p *instrumentationTypeListPackage) {
			p.Module.Replace = &instrumentationTypeListModule{Path: original.SourceRoot, Dir: original.SourceRoot}
		},
		"module version":          func(p *instrumentationTypeListPackage) { p.Module.Version = "v1.0.0" },
		"import map":              func(p *instrumentationTypeListPackage) { p.ImportMap = map[string]string{"syscall": "math/bits"} },
		"missing selected source": func(p *instrumentationTypeListPackage) { p.CompiledGoFiles = p.CompiledGoFiles[1:] },
		"missing export":          func(p *instrumentationTypeListPackage) { p.Export = "" },
		"test role":               func(p *instrumentationTypeListPackage) { p.ForTest = plan.PackagePath },
		"embed role":              func(p *instrumentationTypeListPackage) { p.EmbedFiles = []string{"unbound.bin"} },
		"Cgo role":                func(p *instrumentationTypeListPackage) { p.CgoFiles = []string{"unbound.go"} },
	} {
		t.Run(name, func(t *testing.T) {
			changed := false
			run := func(ctx context.Context, dir string, env []string, command string, args ...string) ([]byte, []byte, error) {
				stdout, stderr, err := RunBounded(ctx, dir, env, command, args...)
				if err != nil || len(args) == 0 || args[0] != "list" || !containsString(args, "-export") {
					return stdout, stderr, err
				}
				decoder := json.NewDecoder(bytes.NewReader(stdout))
				var output bytes.Buffer
				for {
					var pkg instrumentationTypeListPackage
					if err := decoder.Decode(&pkg); err == io.EOF {
						break
					} else if err != nil {
						return nil, nil, err
					}
					target := plan.PackagePath
					if name == "SDK root" || name == "foreign module" {
						target = "syscall"
					}
					if pkg.ImportPath == target {
						change(&pkg)
						changed = true
					}
					if err := json.NewEncoder(&output).Encode(pkg); err != nil {
						return nil, nil, err
					}
				}
				return output.Bytes(), stderr, nil
			}
			if _, err := CaptureInstrumentationTypeSources(ctx, binary, original.SourceRoot, env, input, run); err == nil || !changed {
				t.Fatalf("changed actual source/origin/export/selection was accepted or fixture was not consumed: %v", err)
			}
		})
	}
	t.Run("actual source bytes", func(t *testing.T) {
		file := filepath.Join(original.SourceRoot, "base.go")
		if err := os.WriteFile(file, []byte(inventory.Contents["base.go"]+"\nconst Changed=1\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := CaptureInstrumentationTypeSources(ctx, binary, original.SourceRoot, env, input, RunBounded); err == nil || !strings.Contains(err.Error(), "source") {
			t.Fatalf("changed original source bytes acquired an imported type closure: %v", err)
		}
	})
	t.Log(fmt.Sprintf("actual stock-Go SDK source/alias/constant capture and %d origin/role/map/export negatives; no LLVM or runtime claim", 11))
}
