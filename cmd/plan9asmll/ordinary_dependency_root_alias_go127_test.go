//go:build go1.27

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/tools/go/packages"
)

// The alias belongs above the module root, not within its source inventory.
// The actual Go driver keeps this spelling for a local replacement. An owner
// must accept that original spelling while retaining its canonical identity.
func ordinaryRootAliasFixture(t *testing.T, target string) (*featureInput, string, string) {
	t.Helper()
	input, dir := generatedHeaderFixture(t, target)
	input.Version = "v1.0.0"
	source := "package dep\nimport _ \"embed\"\nconst Value=40\ntype Mixed struct{Small byte; Word uintptr; Bytes []byte}\n//go:embed asset.bin\nvar Asset []byte\n"
	for name, text := range map[string]string{"dep/layout.go": source, "dep/asset.bin": "original asset"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256([]byte(text))
	}
	input.Headers["dep/layout.go"] = source
	input.Directories["dep"] = []string{"asset.bin", "layout.go"}
	parent, err := filepath.EvalSymlinks(filepath.Dir(dir))
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "ancestor")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	observed := filepath.Join(alias, filepath.Base(dir))
	work := t.TempDir()
	mod := "module example.invalid/workspace\n\ngo 1.24\nrequire " + input.Module + " v1.0.0\nreplace " + input.Module + " => " + filepath.ToSlash(observed) + "\n"
	if err := os.WriteFile(filepath.Join(work, "go.mod"), []byte(mod), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(work)
	return input, dir, alias
}

func TestGeneratedHeaderOrdinaryRootAliasActualLoad(t *testing.T) {
	for _, target := range []string{"linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			input, _, alias := ordinaryRootAliasFixture(t, target)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), target, input.Module, nil)
			if err != nil {
				t.Fatal(err)
			}
			observed := false
			pkgs, err := loadGeneratedHeaderPackagesWithLoader(consumer, []string{input.Module}, nil,
				func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
					pkgs, err := packages.Load(config, patterns...)
					if err == nil && len(pkgs) != 0 && len(pkgs[0].GoFiles) != 0 {
						observed = observed || strings.HasPrefix(pkgs[0].GoFiles[0], alias+string(filepath.Separator))
					}
					return pkgs, err
				})
			if err != nil {
				t.Fatal(err)
			}
			if !observed {
				t.Fatal("actual Go did not exercise the original ancestor-alias spelling")
			}
			if err := consumer.capturePackages(pkgs); err != nil {
				t.Fatal(err)
			}
			if _, err := captureGeneratedHeader(consumer, pkgs[0], consumer.Proof.Packages[0], t.TempDir()); err != nil {
				t.Fatal(err)
			}
			if _, err := consumer.ordinaryDependencyProof(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestGeneratedHeaderOrdinaryRootAliasRetainsIdentity(t *testing.T) {
	for _, phase := range []string{"before compiler", "after header", "cancelled", "internal source", "internal asset"} {
		t.Run(phase, func(t *testing.T) {
			input, dir, alias := ordinaryRootAliasFixture(t, "linux/amd64")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
			if err != nil {
				t.Fatal(err)
			}
			repoint := func() {
				parent := t.TempDir()
				copyRoot := filepath.Join(parent, filepath.Base(dir))
				for name := range input.Sources {
					data, err := os.ReadFile(filepath.Join(dir, name))
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(copyRoot, name)
					if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(file, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(parent, alias); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(phase, "internal") {
				name := "dep/layout.go"
				if phase == "internal asset" {
					name = "dep/asset.bin"
				}
				file := filepath.Join(dir, name)
				outside := filepath.Join(t.TempDir(), "same-bytes")
				data, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(outside, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(file); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, file); err != nil {
					t.Fatal(err)
				}
			}
			mutated := false
			pkgs, err := loadGeneratedHeaderPackagesWithLoader(consumer, []string{input.Module}, nil,
				func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
					if phase == "before compiler" && config.Mode&packages.NeedExportFile != 0 {
						repoint()
						mutated = true
					}
					return packages.Load(config, patterns...)
				})
			if phase == "before compiler" || strings.HasPrefix(phase, "internal") {
				if phase == "before compiler" && !mutated {
					t.Fatalf("owner never reached the actual compiler mutation boundary: %v", err)
				}
				if err == nil {
					t.Fatal("changed owner or internal source alias acquired ordinary authority")
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
			if phase == "cancelled" {
				cancel()
			} else {
				repoint()
			}
			if err := consumer.verifySources(); err == nil {
				t.Fatal("live root alias or context change survived the final owner guard")
			}
		})
	}
}
