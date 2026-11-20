package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestOrdinaryProfileUsesActualGoRoleForTestNamedAssembly(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		parts := strings.Split(target, "/")
		for _, name := range []string{"probe_test.s", "probe_test_" + parts[1] + ".s"} {
			t.Run(target+"/"+name, func(t *testing.T) {
				input, dir := ordinaryTestNamedFixture(t, target, name, true)
				t.Chdir(dir)
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				env := featureEnvironment(os.Environ(), input.Observed.Environment)
				listed, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, "go", "list", "-export", "-json", ".")
				if err != nil {
					t.Fatalf("actual ordinary Go export: %v\n%s", err, stderr)
				}
				var actual struct {
					SFiles      []string
					TestGoFiles []string
					Export      string
				}
				if err := json.Unmarshal(listed, &actual); err != nil {
					t.Fatal(err)
				}
				if len(actual.SFiles) != 1 || actual.SFiles[0] != name || actual.Export == "" || len(actual.TestGoFiles) != 1 {
					t.Fatalf("actual Go did not export the exact ordinary/test source roles: %s", listed)
				}

				metadataPath := filepath.Join(t.TempDir(), "metadata.json")
				args := []string{
					"-metadata-only", "-goos=" + parts[0], "-goarch=" + parts[1],
					"-patterns=.", "-module-path=" + input.Module, "-asm-files=" + name,
					"-feature-profile=" + writeFeatureInput(t, input),
					"-out=" + t.TempDir(), "-report=" + metadataPath,
				}
				encoded, err := json.Marshal(args)
				if err != nil {
					t.Fatal(err)
				}
				_, stderr, err = gotoolprofile.RunBounded(ctx, dir, append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded)), os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
				if err != nil {
					t.Fatalf("ordinary Go-selected .s name was incorrectly rejected by metadata CLI: %v\n%s", err, stderr)
				}
				data, err := os.ReadFile(metadataPath)
				if err != nil {
					t.Fatal(err)
				}
				var metadata gotoolprofile.MetadataProof
				if err := json.Unmarshal(data, &metadata); err != nil {
					t.Fatal(err)
				}
				if err := gotoolprofile.ValidateMetadata(input, &metadata, nil); err != nil {
					t.Fatal(err)
				}
				input.GeneratedHeaders = &metadata
				config, err := resolveCompileConfig(true, "", true, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
				report, _, err := runOneTarget(
					targetSpec{Goos: parts[0], Goarch: parts[1]}, []string{"."}, nil,
					input.AsmFiles, input.Module, t.TempDir(),
					false, 0, true, false, true, repo, config,
				)
				if err != nil || report.Success != 1 || report.Failed != 0 {
					t.Fatalf("ordinary Go-selected .s must translate and compile: %#v: %v", report, err)
				}
				proof := report.FeatureSelection
				if err := gotoolprofile.ValidateSelection(input, proof, nil, true); err != nil {
					t.Fatal(err)
				}
				if len(proof.Packages) != 1 || len(proof.Outputs) != 1 || proof.Outputs[0].Object == "" {
					t.Fatal("ordinary name regression lacks complete package/object evidence")
				}
				for _, file := range proof.Packages[0].CompiledGoFiles {
					if strings.HasSuffix(file, "_test.go") {
						t.Fatal("a filename heuristic loaded a test package into ordinary evidence")
					}
				}
			})
		}
	}
}

func TestOrdinaryProfileLoadsNoTestGoForTestNamedAssembly(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/386", "linux/amd64", "linux/arm", "linux/arm64", "js/wasm"} {
		parts := strings.Split(target, "/")
		for _, name := range []string{"probe_test.s", "probe_test_" + parts[1] + ".s"} {
			t.Run(target+"/"+name, func(t *testing.T) {
				input, dir := ordinaryTestNamedFixture(t, target, name, false)
				t.Chdir(dir)
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				config, err := resolveCompileConfig(true, "", true, 0)
				if err != nil {
					t.Fatal(err)
				}
				config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
				report, _, err := runOneTarget(
					targetSpec{Goos: parts[0], Goarch: parts[1]}, []string{"."}, nil,
					input.AsmFiles, input.Module, t.TempDir(),
					false, 0, true, false, true, repo, config,
				)
				if err != nil || report.Success != 1 || report.Failed != 0 {
					t.Fatalf("ordinary source loader must exclude poison_test.go: %#v: %v", report, err)
				}
				if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func ordinaryTestNamedFixture(t *testing.T, target, name string, generated bool) (*featureInput, string) {
	t.Helper()
	input, dir := generatedHeaderFixture(t, target)
	old := input.AsmFiles[0]
	if err := os.Rename(filepath.Join(dir, old), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	input.Sources[name], input.Headers[name] = input.Sources[old], input.Headers[old]
	delete(input.Sources, old)
	delete(input.Headers, old)
	input.AsmFiles = []string{name}
	if !generated {
		const source = "TEXT ·Probe(SB),$0-0\nRET\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name], input.Headers[name] = featureBytesSHA256([]byte(source)), source
	}
	for index, entry := range input.Directories["."] {
		if entry == old {
			input.Directories["."][index] = name
		}
	}

	// Go treats _test.go specially, not similarly named .s files. Loading a
	// test variant here would admit a different declaration/source contract.
	const testGo = "package header\nvar TestOnly = missingTestOnlyName\n"
	if err := os.WriteFile(filepath.Join(dir, "poison_test.go"), []byte(testGo), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["poison_test.go"] = featureBytesSHA256([]byte(testGo))
	input.Headers["poison_test.go"] = testGo
	input.Directories["."] = append(input.Directories["."], "poison_test.go")
	sort.Strings(input.Directories["."])
	return input, dir
}
