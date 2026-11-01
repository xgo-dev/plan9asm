//go:build go1.27

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationMetadataAndObjectsIgnoreOwnedUserGoEnv(t *testing.T) {
	// Prepare the actual marker, source inventory and mode plan before making
	// the caller's private Go configuration hostile. No SDK is copied or edited.
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	goBinary, err = filepath.Abs(goBinary)
	if err != nil {
		t.Fatal(err)
	}
	userFile := filepath.Join(t.TempDir(), "go-env")
	userConfig := []byte("GOFLAGS=-plan9asm-owned-user-env-invalid\n")
	if err := os.WriteFile(userFile, userConfig, 0600); err != nil {
		t.Fatal(err)
	}
	userEnv := instrumentationGoEnvFixtureEnvironment(os.Environ(), userFile)
	query := func(t *testing.T, env []string) map[string]string {
		t.Helper()
		stdout, stderr, err := gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, env, goBinary, "env", "-json", "GOENV", "GOFLAGS")
		if err != nil || len(stderr) != 0 {
			t.Fatalf("actual owned Go environment query: %v\n%s\n%s", err, stdout, stderr)
		}
		var observed map[string]string
		if err := json.Unmarshal(stdout, &observed); err != nil || len(observed) != 2 {
			t.Fatalf("incomplete actual owned Go environment: %v; %s", err, stdout)
		}
		return observed
	}
	if actual := query(t, userEnv); !reflect.DeepEqual(actual, map[string]string{
		"GOENV": userFile, "GOFLAGS": "-plan9asm-owned-user-env-invalid",
	}) {
		t.Fatalf("the original caller did not consume the real owned go/env: %#v", actual)
	}
	stdout, stderr, originalErr := gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, userEnv, goBinary, "list", "-mod=readonly", "./...")
	if originalErr == nil || !strings.Contains(string(stderr), "unknown flag -plan9asm-owned-user-env-invalid") {
		t.Fatalf("owned user go/env did not cause the actual stock-Go failure: %v\n%s\n%s", originalErr, stdout, stderr)
	}
	t.Logf("original inherited user GOENV failure: %v\n%s\n%s", originalErr, stdout, stderr)

	for _, scenario := range []string{"explicit off control", "inherited owned user config"} {
		t.Run(scenario, func(t *testing.T) {
			env := userEnv
			if scenario == "explicit off control" {
				env = instrumentationGoEnvFixtureEnvironment(userEnv, "off")
			}
			loadCalls := 0
			loader := func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
				loadCalls++
				if actual := query(t, config.Env); !reflect.DeepEqual(actual, map[string]string{"GOENV": "", "GOFLAGS": ""}) {
					t.Fatalf("actual mode package/export loader borrowed the user configuration: %#v", actual)
				}
				return packages.Load(config, patterns...)
			}
			metadata, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, env, t.TempDir(), loader)
			if err != nil {
				t.Fatalf("mode metadata inherited the unrelated user go/env after the original mode proof was prepared: %v", err)
			}
			if loadCalls == 0 {
				t.Fatal("mode metadata did not execute the actual package/export loader")
			}
			// The same private environment is handed to generated headers and
			// ordinary asmdecl, not only to the marker's separate reobserver.
			if actual := query(t, metadata.Source.Env); !reflect.DeepEqual(actual, map[string]string{"GOENV": "", "GOFLAGS": ""}) {
				t.Fatalf("mode header/asmdecl consumer retained a different actual context: %#v", actual)
			}
			encoded, err := json.Marshal(metadata.Metadata)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gotoolprofile.DecodeInstrumentationMetadata(strings.NewReader(string(encoded)), input, ".", nil); err != nil {
				t.Fatal(err)
			}
			output := instrumentationObjectFixtureOutput(t, input)
			proof, tools, err := consumeInstrumentationAssembly(ctx, input, metadata.Metadata, input.Original.SourceRoot, env, output)
			if err != nil {
				t.Fatalf("actual mode CPP/LLVM object inherited the user configuration: %v", err)
			}
			if proof.Status != "llvm_objects_only" || len(proof.Files) != 1 || proof.Files[0].Output.Object == "" {
				t.Fatal("mode consumer omitted its original object or claimed runtime")
			}
			encoded, err = json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gotoolprofile.DecodeInstrumentationConsumption(strings.NewReader(string(encoded)), input, metadata.Metadata, tools, ".", nil); err != nil {
				t.Fatal(err)
			}
			for _, file := range proof.Files {
				ir := filepath.Join(output, file.Output.Part)
				if actual, err := gotoolprofile.FileSHA256(ir); err != nil || actual != file.Output.IR {
					t.Fatalf("actual mode IR absent or changed: %v", err)
				}
				object := strings.TrimSuffix(ir, ".ll") + ".o"
				if actual, err := gotoolprofile.FileSHA256(object); err != nil || actual != file.Output.Object {
					t.Fatalf("actual LLVM22 object absent or changed: %v", err)
				}
			}
			recordInstrumentationObjectFixture(t, output, input, metadata.Metadata, tools, proof)
		})
	}
	if actual, err := os.ReadFile(userFile); err != nil || string(actual) != string(userConfig) {
		t.Fatalf("mode commands altered the original owned go/env witness: %v", err)
	}
}

func instrumentationGoEnvFixtureEnvironment(base []string, file string) []string {
	var env []string
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOENV" && key != "GOFLAGS" {
			env = append(env, entry)
		}
	}
	return append(env, "GOENV="+file)
}
