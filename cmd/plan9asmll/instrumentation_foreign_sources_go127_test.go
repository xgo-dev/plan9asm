//go:build go1.27

package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationForeignOriginalSourcesCLIRecaptureAndFinalGuard(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	const dependency = "example.invalid/cli-layout"
	foreignSources := map[string]string{
		"go.mod":          "module " + dependency + "\n\ngo 1.20\n",
		"model/layout.go": "package model\ntype Word uint64\nconst Words=2\ntype Header struct{Lo uint32; Pad [Words]byte; Hi uint16}\n",
	}
	proxy, cache := t.TempDir(), t.TempDir()
	var archive bytes.Buffer
	w := zip.NewWriter(&archive)
	for file, contents := range foreignSources {
		entry, err := w.Create(dependency + "@v1.0.0/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(contents)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(proxy, dependency, "@v")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for suffix, contents := range map[string][]byte{
		".zip": archive.Bytes(), ".mod": []byte(foreignSources["go.mod"]),
		".info": []byte(`{"Version":"v1.0.0","Time":"2026-10-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(directory, "v1.0.0"+suffix), contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		if err := filepath.Walk(cache, func(file string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return os.Chmod(file, 0700)
			}
			return nil
		}); err != nil {
			t.Error(err)
		}
	})
	// Only this owned synthetic file proxy has no SumDB certificate. It does
	// not substitute for the production original ZIP/mod authentication.
	proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
	if err != nil {
		t.Fatal(err)
	}
	env := featureEnvironment(os.Environ(), map[string]string{
		"GOPROXY": proxyURL, "GOSUMDB": "off", "GOMODCACHE": cache, "GOPATH": t.TempDir(),
	})
	mod := input.Original.SourceRoot + "/go.mod"
	modBytes, err := os.ReadFile(mod)
	if err != nil {
		t.Fatal(err)
	}
	modBytes = append(modBytes, []byte("require "+dependency+" v1.0.0\n")...)
	if err := os.WriteFile(mod, modBytes, 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Sources["go.mod"] = featureBytesSHA256(modBytes)
	source := strings.Replace(input.Original.Headers["mode.go"], "import \"example.invalid/modeheader/dep\"",
		"import (\"example.invalid/modeheader/dep\"; shape \""+dependency+"/model\")", 1)
	source = strings.Replace(source, "func Probe() uint64", "func Probe() shape.Word", 1)
	if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, "mode.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Sources["mode.go"], input.Original.Headers["mode.go"] = featureBytesSHA256([]byte(source)), source
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	data, stderr, err := gotoolprofile.RunBounded(ctx, input.Original.SourceRoot, env, binary, "mod", "download", "-json", dependency+"@v1.0.0")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("exact owned dependency: %v; %s", err, stderr)
	}
	var actual struct{ Dir, Zip, GoMod, Sum, GoModSum string }
	if err := json.Unmarshal(data, &actual); err != nil || actual.Dir == "" {
		t.Fatal("actual stock Go download omitted its physical identity")
	}
	for _, name := range []string{"go.mod", "go.sum"} {
		contents, err := os.ReadFile(filepath.Join(input.Original.SourceRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		input.Original.Sources[name] = featureBytesSHA256(contents)
	}
	input.Original.Directories["."] = nil
	entries, err := os.ReadDir(input.Original.SourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		input.Original.Directories["."] = append(input.Original.Directories["."], entry.Name())
	}
	replanInstrumentationMetadataFixture(t, input)
	resource := gotoolprofile.TestModuleSource{Protocol: gotoolprofile.TestDependencyModuleProtocol,
		SourceModule: dependency, SourceVersion: "v1.0.0", ModuleSum: actual.Sum, GoModSum: actual.GoModSum,
		GoModOrigin: gotoolprofile.TestModuleOriginalGoModOrigin,
		Sources:     map[string]string{}, Headers: map[string]string{}, Directories: map[string][]gotoolprofile.TestSourceEntry{}}
	resource.ZipSHA256, err = gotoolprofile.FileSHA256(actual.Zip)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".", "model"} {
		members, err := os.ReadDir(filepath.Join(actual.Dir, dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, member := range members {
			entry := gotoolprofile.TestSourceEntry{Name: member.Name(), Kind: "directory"}
			if !member.IsDir() {
				name := filepath.ToSlash(filepath.Join(dir, member.Name()))
				contents, err := os.ReadFile(filepath.Join(actual.Dir, name))
				if err != nil {
					t.Fatal(err)
				}
				entry.Kind, entry.SHA256 = "file", featureBytesSHA256(contents)
				resource.Sources[name] = entry.SHA256
				if strings.HasSuffix(name, ".go") {
					header, err := gotoolprofile.TestSelectionHeader(name, contents)
					if err != nil {
						t.Fatal(err)
					}
					resource.Headers[name] = header
				}
			}
			resource.Directories[dir] = append(resource.Directories[dir], entry)
		}
		sort.Slice(resource.Directories[dir], func(i, j int) bool { return resource.Directories[dir][i].Name < resource.Directories[dir][j].Name })
	}
	resource.GoModSHA256 = resource.Sources["go.mod"]
	modeEnv := featureEnvironment(env, input.Observation.Early.Environment)
	input.TypeSources, err = gotoolprofile.CaptureInstrumentationTypeSourcesWithModules(ctx, binary, input.Original.SourceRoot, modeEnv,
		input, []gotoolprofile.TestModuleSource{resource}, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	// The actual consumer uses a physical invocation directory. Re-observing
	// that same source must preserve all portable fields, including exports.
	physical, err := sourcepath.Resolve(input.Original.SourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	recaptured, err := gotoolprofile.CaptureInstrumentationTypeSources(ctx, binary, physical, modeEnv, input, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	expectedJSON, err := json.Marshal(input.TypeSources)
	if err != nil {
		t.Fatal(err)
	}
	actualJSON, err := json.Marshal(recaptured)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(input.TypeSources, recaptured) {
		t.Fatalf("same-source type recapture changed:\nexpected: %s\nactual: %s", expectedJSON, actualJSON)
	}
	consumer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, env, t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	if consumer.ForeignSources == nil {
		t.Fatal("CLI did not independently bind the original foreign resource")
	}
	proof, tools, err := consumeInstrumentationAssembly(ctx, input, consumer.Metadata, input.Original.SourceRoot, env, t.TempDir())
	if err != nil || gotoolprofile.ValidateInstrumentationConsumption(input, consumer.Metadata, tools, ".", nil, proof) != nil {
		t.Fatalf("actual same-mode foreign metadata/CPP/LLVM consumption: %v", err)
	}
	foreignFile := filepath.Join(actual.Dir, "model", "layout.go")
	if err := os.Chmod(foreignFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(foreignFile, []byte(foreignSources["model/layout.go"]+"\nconst Changed=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifySources(); err == nil {
		t.Fatal("final CLI boundary accepted mutated foreign original source after successful object consumption")
	}
	if err := os.WriteFile(foreignFile, []byte(foreignSources["model/layout.go"]), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifySources(); err != nil {
		t.Fatal(err)
	}
}
