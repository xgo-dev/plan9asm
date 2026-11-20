//go:build go1.27

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// The missing dependency is an explicit local replacement, so this genuine
// cmd/go test-graph failure performs no network fetch. Ordinary compilation
// and its declaration checks have a separate actual source denominator.
func TestInstrumentationMetadataAsmdeclKeepsOrdinaryAndTestSourceScopes(t *testing.T) {
	for _, badAssembly := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary valid", true: "ordinary declaration invalid"}[badAssembly], func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
			dir := input.Original.SourceRoot
			mod, err := os.ReadFile(filepath.Join(dir, "go.mod"))
			if err != nil {
				t.Fatal(err)
			}
			files := map[string]string{
				"go.mod": string(mod) + "\nrequire example.invalid/testonly v0.0.0\n" +
					"replace example.invalid/testonly => ./test-dependency-missing\n",
				"poison_test.go": "package modeheader\nimport _ \"example.invalid/testonly\"\n",
			}
			if badAssembly {
				files["probe_arm64.s"] = strings.Replace(input.Original.Headers["probe_arm64.s"],
					"ret+0(FP)", "misspelled+0(FP)", 1)
			}
			for name, source := range files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
				input.Original.Sources[name] = featureBytesSHA256([]byte(source))
				if strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s") {
					input.Original.Headers[name] = source
				}
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			input.Original.Directories["."] = nil
			for _, entry := range entries {
				input.Original.Directories["."] = append(input.Original.Directories["."], entry.Name())
			}
			sort.Strings(input.Original.Directories["."])
			replanInstrumentationMetadataFixture(t, input)

			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			env := featureEnvironment(os.Environ(), input.Observation.Early.Environment)
			args := []string{"vet", "-asmdecl", "-race", "-tests=true", "-mod=readonly", "-p=1", input.Plan.PackagePath}
			_, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, binary, args...)
			if err == nil || !strings.Contains(string(stderr), "test-dependency-missing") {
				t.Fatalf("actual test-source failure was not reproduced: %v; %s", err, stderr)
			}

			consumer, err := captureInstrumentationMetadata(ctx, input, dir, os.Environ(), t.TempDir(), packages.Load)
			if badAssembly {
				if err == nil || !strings.Contains(err.Error(), "misspelled") || !strings.Contains(err.Error(), "asmdecl") {
					t.Fatalf("ordinary declaration error lost its own source scope: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unselected test dependency blocked valid ordinary metadata: %v", err)
			}
			if !reflect.DeepEqual(consumer.Metadata.Selection.Packages[0].GoFiles, []string{"base.go", "mode.go"}) ||
				!reflect.DeepEqual(consumer.Metadata.VetArgs, []string{"tool", "vet", "-asmdecl", "ordinary.cfg"}) {
				t.Fatal("ordinary compilation/asmdecl changed or lost its explicit source denominator")
			}
			if err := gotoolprofile.ValidateInstrumentationMetadata(input, ".", nil, consumer.Metadata); err != nil {
				t.Fatal(err)
			}
		})
	}
}
