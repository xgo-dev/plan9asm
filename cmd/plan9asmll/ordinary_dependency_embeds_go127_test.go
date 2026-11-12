//go:build go1.27

package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

// A normal imported package can own embedded bytes without becoming a test
// package or an assembly output. Both the actual Go export and the ordinary
// header/CPP/LLVM consumers must retain that independent input role.
func TestGeneratedHeaderOrdinaryDependencyEmbedActualConsumer(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, target)
			files := map[string]string{
				"dep/layout.go":    "package dep\nimport _ \"embed\"\nconst Value = 40\ntype Mixed struct { Small byte; Word uintptr; Bytes []byte }\n//go:embed defaults.bin\nvar Defaults []byte\n",
				"dep/defaults.bin": "ordinary dependency's original asset\n",
			}
			for name, contents := range files {
				if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[name] = featureBytesSHA256([]byte(contents))
				if strings.HasSuffix(name, ".go") {
					input.Headers[name] = contents
				}
			}
			input.Directories["dep"] = append(input.Directories["dep"], "defaults.bin")
			sort.Strings(input.Directories["dep"])
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			binary, err := exec.LookPath("go")
			if err != nil {
				t.Fatal(err)
			}
			data, stderr, err := gotoolprofile.RunBounded(ctx, dir, featureEnvironment(os.Environ(), input.Observed.Environment),
				binary, "list", "-export", "-json", "./dep")
			if err != nil {
				t.Fatalf("independent actual Go dependency export: %v\n%s", err, stderr)
			}
			var actual struct {
				ImportPath, Export        string
				EmbedPatterns, EmbedFiles []string
			}
			if err := json.Unmarshal(data, &actual); err != nil || actual.Export == "" ||
				actual.ImportPath != input.Module+"/dep" || len(actual.EmbedPatterns) != 1 ||
				len(actual.EmbedFiles) != 1 || actual.EmbedFiles[0] != "defaults.bin" {
				t.Fatalf("actual Go did not compile the exact original embedded dependency: %+v; %v", actual, err)
			}
			parts := strings.Split(target, "/")
			spec := targetSpec{Goos: parts[0], Goarch: parts[1]}
			input.GeneratedHeaders, err = queryGeneratedHeaders(spec, []string{"."}, nil, input.AsmFiles, input.Module,
				t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
			if err != nil {
				t.Fatalf("ordinary dependency embed role cannot reach the actual header consumer: %v", err)
			}
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module,
				t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Success != 1 || report.Failed != 0 {
				t.Fatalf("ordinary embed source/header/CPP/LLVM consumer: %+v; %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGeneratedHeaderOrdinaryForeignEmbedActualConsumer(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, target)
			const dependency = "example.invalid/asset-dependency"
			ordinaryFixtureDependency(t, input, dependency, map[string]string{
				"model/model.go":       "package model\nimport _ \"embed\"\nconst Value=40\n//go:embed all:assets\nvar Assets string\n",
				"model/assets/.hidden": "original hidden asset\n",
			})
			source := "package dep\nimport \"" + dependency + "/model\"\nconst Value = model.Value\ntype Mixed struct { Small byte; Word uintptr; Bytes []byte }\n"
			if err := os.WriteFile(filepath.Join(dir, "dep/layout.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["dep/layout.go"], input.Headers["dep/layout.go"] = featureBytesSHA256([]byte(source)), source
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()
			parts := strings.Split(target, "/")
			spec := targetSpec{Goos: parts[0], Goarch: parts[1]}
			input.GeneratedHeaders, err = queryGeneratedHeaders(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, pkg := range input.GeneratedHeaders.Dependencies.ExternalPackages {
				if pkg.Package.PackagePath == dependency+"/model" {
					found = pkg.SourceRootID == dependency+"@v1.0.0" && pkg.Embed.Files["model/assets/.hidden"] != "" && pkg.ExportSHA256 != ""
				}
			}
			if !found {
				t.Fatal("complete transitive ordinary embed/ZIP/export role missing")
			}
			config, err := resolveCompileConfig(true, "", true, 0)
			if err != nil {
				t.Fatal(err)
			}
			config.FeaturePath, config.Context = writeFeatureInput(t, input), ctx
			report, _, err := runOneTarget(spec, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), false, 0, true, false, true, repo, config)
			if err != nil || report.Success != 1 || report.Failed != 0 {
				t.Fatalf("foreign embed actual LLVM consumer: %+v; %v", report, err)
			}
			if err := gotoolprofile.ValidateSelection(input, report.FeatureSelection, nil, true); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(input.GeneratedHeaders)
			if err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*gotoolprofile.MetadataProof){
				"missing role":           func(p *gotoolprofile.MetadataProof) { p.Dependencies = nil },
				"old protocol":           func(p *gotoolprofile.MetadataProof) { p.Protocol = "actual_go_cpu_profile_metadata_v1" },
				"test role":              func(p *gotoolprofile.MetadataProof) { p.Dependencies.Protocol = gotoolprofile.TestDependencyProtocol },
				"missing import closure": func(p *gotoolprofile.MetadataProof) { p.Dependencies.ExternalPackages = nil },
				"missing module owner":   func(p *gotoolprofile.MetadataProof) { p.Dependencies.SourceModules = nil },
			} {
				t.Run(name, func(t *testing.T) {
					var changed gotoolprofile.MetadataProof
					if err := json.Unmarshal(data, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					if err := gotoolprofile.ValidateMetadata(input, &changed, nil); err == nil {
						t.Fatal("missing/old/changed ordinary role accepted")
					}
				})
			}
		})
	}
}

func TestGeneratedHeaderOrdinaryEmbedLiveMutation(t *testing.T) {
	for _, axis := range []string{"before bytes", "before directory", "before directive", "after bytes", "after directory", "after cancel"} {
		t.Run(axis, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, "linux/amd64")
			source := "package dep\nimport _ \"embed\"\nconst Value=40\ntype Mixed struct { Small byte; Word uintptr; Bytes []byte }\n//go:embed asset.bin\nvar Asset []byte\n"
			for name, text := range map[string]string{"dep/layout.go": source, "dep/asset.bin": "original"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				input.Sources[name] = featureBytesSHA256([]byte(text))
			}
			input.Headers["dep/layout.go"] = source
			input.Directories["dep"] = []string{"asset.bin", "layout.go"}
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
			if err != nil {
				t.Fatal(err)
			}
			mutate := func() {
				switch {
				case strings.HasSuffix(axis, "bytes"):
					if err := os.WriteFile(filepath.Join(dir, "dep/asset.bin"), []byte("changed"), 0600); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(axis, "directory"):
					if err := os.WriteFile(filepath.Join(dir, "dep/new.bin"), nil, 0600); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(axis, "directive"):
					if err := os.WriteFile(filepath.Join(dir, "dep/layout.go"), []byte(strings.Replace(source, "asset.bin", "all:asset.bin", 1)), 0600); err != nil {
						t.Fatal(err)
					}
				case strings.HasSuffix(axis, "cancel"):
					cancel()
				}
			}
			pkgs, err := loadGeneratedHeaderPackagesWithLoader(consumer, []string{"."}, nil, func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
				if strings.HasPrefix(axis, "before") && config.Mode&packages.NeedExportFile != 0 {
					mutate()
				}
				return packages.Load(config, patterns...)
			})
			if strings.HasPrefix(axis, "before") {
				if err == nil {
					t.Fatal("dependency mutation before compiler export accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := consumer.capturePackages(pkgs); err != nil {
				t.Fatal(err)
			}
			if _, err := captureGeneratedHeader(consumer, pkgs[0], consumer.Proof.Packages[0], t.TempDir()); err != nil {
				t.Fatal(err)
			}
			mutate()
			if err := consumer.verifySources(); err == nil {
				t.Fatal("dependency mutation after compiler header accepted")
			}
		})
	}
}

func TestGeneratedHeaderOrdinaryMetadataRequiresLiveOwner(t *testing.T) {
	for _, consumer := range []*featureConsumer{nil, {}, {OrdinaryDependencies: &ordinaryDependencyOwner{}}, {OrdinaryDependencies: &ordinaryDependencyOwner{Compiled: true}}} {
		if _, err := consumer.ordinaryDependencyProof(); err == nil {
			t.Fatal("metadata acquired absent/incomplete owner")
		}
		if consumer != nil {
			if err := consumer.captureGeneratedMetadata(nil, nil, t.TempDir()); err == nil {
				t.Fatal("metadata helper accepted missing source owner")
			}
		}
	}
}

func TestGeneratedHeaderOrdinaryCandidateOwnedLocalReplace(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	input.Version = "v1.0.0"
	work := t.TempDir()
	mod := "module example.invalid/workspace\n\ngo 1.24\nrequire " + input.Module + " v1.0.0\nreplace " + input.Module + " => " + filepath.ToSlash(dir) + "\n"
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	proof, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{input.Module}, nil,
		input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	if proof.Packages[0].SourceRole != "owned_local_replace" || proof.Dependencies.Packages[0].SourceRootID != "" {
		t.Fatal("explicit candidate owner was confused with an unbound foreign local replacement")
	}
}

func TestGeneratedHeaderOrdinaryForeignLocalReplaceRejected(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	foreign := t.TempDir()
	for name, text := range map[string]string{"go.mod": "module example.invalid/unbound\n\ngo 1.20\n", "source.go": "package unbound\nconst Value=40\n"} {
		if err := os.WriteFile(filepath.Join(foreign, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, text := range map[string]string{
		"go.mod":        "module " + input.Module + "\n\ngo 1.24\nrequire example.invalid/unbound v1.0.0\nreplace example.invalid/unbound => " + filepath.ToSlash(foreign) + "\n",
		"dep/layout.go": "package dep\nimport \"example.invalid/unbound\"\nconst Value=unbound.Value\ntype Mixed struct{Small byte; Word uintptr; Bytes []byte}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256([]byte(text))
		if strings.HasSuffix(name, ".go") {
			input.Headers[name] = text
		}
	}
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err == nil || !strings.Contains(err.Error(), "exact versioned Module/Replace") {
		t.Fatalf("foreign local replacement acquired ZIP authority: %v", err)
	}
}

func TestGeneratedHeaderOrdinaryForeignOwnerFinalGuards(t *testing.T) {
	for _, axis := range []string{"asset", "new member", "ZIP", "metadata"} {
		t.Run(axis, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, "linux/amd64")
			const dependency = "example.invalid/foreign-guard"
			foreign := ordinaryFixtureDependency(t, input, dependency, map[string]string{
				"source.go": "package external\nimport _ \"embed\"\nconst Value=40\n//go:embed asset.bin\nvar Asset []byte\n",
				"asset.bin": "original foreign asset",
			})
			source := "package dep\nimport external \"" + dependency + "\"\nconst Value=external.Value\ntype Mixed struct{Small byte; Word uintptr; Bytes []byte}\n"
			if err := os.WriteFile(filepath.Join(dir, "dep/layout.go"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			input.Sources["dep/layout.go"], input.Headers["dep/layout.go"] = featureBytesSHA256([]byte(source)), source
			t.Chdir(dir)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
			if err != nil {
				t.Fatal(err)
			}
			pkgs, err := loadGeneratedHeaderPackages(consumer, []string{"."}, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := consumer.capturePackages(pkgs); err != nil {
				t.Fatal(err)
			}
			if _, err := captureGeneratedHeader(consumer, pkgs[0], consumer.Proof.Packages[0], t.TempDir()); err != nil {
				t.Fatal(err)
			}
			owner := consumer.OrdinaryDependencies.Modules[dependency+"@v1.0.0"]
			if owner == nil {
				t.Fatal("actual owner absent")
			}
			switch axis {
			case "asset":
				file := filepath.Join(foreign, "asset.bin")
				if err := os.Chmod(file, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new member":
				if err := os.Chmod(foreign, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(foreign, "new.bin"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "ZIP":
				file, err := os.OpenFile(owner.ZIP, os.O_WRONLY|os.O_APPEND, 0600)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteString("changed archive bytes"); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			case "metadata":
				if err := os.Chmod(owner.DownloadedGoMod, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(owner.DownloadedGoMod, []byte("module example.invalid/changed\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := consumer.verifySources(); err == nil {
				t.Fatal("foreign asset/ZIP/metadata mutation survived final source guard")
			}
		})
	}
}

func TestGeneratedHeaderOrdinaryUnsignedLegacyMetadataRejected(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	const dependency = "example.invalid/unsigned-legacy"
	foreign := ordinaryFixtureDependencyOrigin(t, input, dependency, map[string]string{
		"source.go": "package legacy\nconst Value=40\n",
	}, false)
	if _, err := os.Stat(filepath.Join(foreign, "go.mod")); !os.IsNotExist(err) {
		t.Fatal("actual Go download fixture unexpectedly acquired an original go.mod")
	}
	// Deliberately invalid cached public metadata prevents any network repair.
	// GOSUMDB=off is allowed only for creating the first-party mechanics ZIP;
	// it must not authorize a legacy ordinary source's independent .mod origin.
	lookup := filepath.Join(os.Getenv("GOMODCACHE"), "cache/download/sumdb/sum.golang.org/lookup", dependency+"@v1.0.0")
	if err := os.MkdirAll(filepath.Dir(lookup), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lookup, []byte("not a signed record\n"), 0600); err != nil {
		t.Fatal(err)
	}
	source := "package dep\nimport legacy \"" + dependency + "\"\nconst Value=legacy.Value\ntype Mixed struct{Small byte; Word uintptr; Bytes []byte}\n"
	if err := os.WriteFile(filepath.Join(dir, "dep/layout.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["dep/layout.go"], input.Headers["dep/layout.go"] = featureBytesSHA256([]byte(source)), source
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module,
		t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err == nil || !strings.Contains(err.Error(), "proxy metadata authentication") {
		t.Fatalf("unsigned legacy metadata acquired an ordinary source role: %v", err)
	}
}
