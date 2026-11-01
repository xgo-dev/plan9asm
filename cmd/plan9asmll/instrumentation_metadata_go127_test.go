//go:build go1.27

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
	"golang.org/x/tools/go/packages"
)

func instrumentationMetadataFixture(t *testing.T, target string, mode gotoolprofile.InstrumentationMode, cgo string) (*gotoolprofile.InstrumentationConsumerInput, context.Context) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	t.Cleanup(cancel)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	marker, err := gotoolprofile.CaptureInstrumentationExportObservation(ctx, binary, t.TempDir(), os.Environ(), target, mode, cgo, nil, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	input := &featureInput{
		Protocol: featureInputProtocol, Module: "example.invalid/modeheader", SourceRoot: dir,
		Observed: marker.Early.BaselineFeatures, ID: gotoolprofile.ProfileID(marker.Early.BaselineFeatures),
		Sources: make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]string),
	}
	files := map[string]string{
		"go.mod":             "module example.invalid/modeheader\n\ngo 1.24\n",
		"base.go":            "package modeheader\n",
		"mode.go":            "//go:build race || msan || asan\n\npackage modeheader\nimport \"example.invalid/modeheader/dep\"\nconst Imported = dep.Value + 1\ntype Layout struct { First byte; External dep.Mixed; Last uintptr }\nfunc Probe() uint64\n",
		"dep/layout.go":      "package dep\ntype Mixed struct { Small byte; Word uintptr; Bytes []byte }\n",
		"dep/value_plain.go": "//go:build !race && !msan && !asan\n\npackage dep\nconst Value = 1\n",
		"dep/value_mode.go":  "//go:build race || msan || asan\n\npackage dep\nconst Value = 40\n",
		"probe_arm64.s":      "//go:build race || msan || asan\n\n#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-8\nMOVD $const_Imported, R0\nMOVD R0, ret+0(FP)\nRET\n",
	}
	assembly := "probe_arm64.s"
	if strings.HasSuffix(target, "/amd64") {
		assembly = "probe_amd64.s"
		delete(files, "probe_arm64.s")
		files[assembly] = "//go:build race || msan || asan\n\n#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-8\nMOVQ $const_Imported, AX\nMOVQ AX, ret+0(FP)\nRET\n"
	}
	for name, source := range files {
		file := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = featureBytesSHA256([]byte(source))
		if strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s") {
			input.Headers[name] = source
		}
	}
	for _, folder := range []string{".", "dep"} {
		entries, err := os.ReadDir(filepath.Join(dir, folder))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			input.Directories[folder] = append(input.Directories[folder], entry.Name())
		}
		sort.Strings(input.Directories[folder])
	}
	input.AsmFiles = []string{assembly}
	sources, err := gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input, sources, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := gotoolprofile.NewInstrumentationConsumerInput(input, sources, marker, plan)
	if err != nil {
		t.Fatal(err)
	}
	return wrapped, ctx
}

func TestInstrumentationMetadataActualSameModeDependencyAndHeader(t *testing.T) {
	for _, config := range []struct {
		target string
		mode   gotoolprofile.InstrumentationMode
		cgo    string
	}{
		{"darwin/arm64", gotoolprofile.InstrumentationRace, "0"},
		{"darwin/arm64", gotoolprofile.InstrumentationRace, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationMSan, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationASan, "1"},
	} {
		t.Run(config.target+"/"+string(config.mode)+"/cgo"+config.cgo, func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, config.target, config.mode, config.cgo)
			consumer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
			if err != nil {
				t.Fatal(err)
			}
			proof := consumer.Metadata
			if len(proof.Headers) != 1 || proof.Status != "consumer_pending" || len(consumer.Packages) != 1 {
				t.Fatalf("metadata became completion or lost actual packages: %#v", proof)
			}
			header := proof.Headers[0]
			if header.Header.Definitions["const_Imported"] != "41" || header.Header.Definitions["Layout__size"] != "56" ||
				!reflect.DeepEqual(header.CompilerFlags, append(append([]string(nil), input.Plan.BuildFlags...), input.Observation.BuildPlan.CodegenFlags...)) ||
				len(header.Header.Imports) != 1 || header.Header.Imports[0].GoSHA256["dep/value_mode.go"] == "" ||
				header.Header.Imports[0].GoSHA256["dep/value_plain.go"] != "" {
				t.Fatalf("typed header/exports did not consume the same actual mode: %#v", header)
			}
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := gotoolprofile.DecodeInstrumentationMetadata(strings.NewReader(string(data)), input, ".", nil); err != nil {
				t.Fatal(err)
			}
			if err := gotoolprofile.ValidateGeneratedHeader(input.Original, header.Header, proof.Selection.Packages[0]); err == nil {
				t.Fatal("mode header passed an ordinary reader")
			}
			checkInstrumentationMetadataMutations(t, input, data)
			if err := consumer.Source.verifySources(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func checkInstrumentationMetadataMutations(t *testing.T, input *gotoolprofile.InstrumentationConsumerInput, data []byte) {
	t.Helper()
	for name, mutate := range map[string]func(*gotoolprofile.InstrumentationMetadataProof){
		"ordinary protocol":       func(p *gotoolprofile.InstrumentationMetadataProof) { p.Protocol = gotoolprofile.MetadataProtocol },
		"ordinary identity":       func(p *gotoolprofile.InstrumentationMetadataProof) { p.ModeProfileID = input.Original.ID },
		"missing context":         func(p *gotoolprofile.InstrumentationMetadataProof) { p.InputSHA256 = "" },
		"missing selection":       func(p *gotoolprofile.InstrumentationMetadataProof) { p.Selection = nil },
		"missing header":          func(p *gotoolprofile.InstrumentationMetadataProof) { p.Headers = nil },
		"missing original export": func(p *gotoolprofile.InstrumentationMetadataProof) { p.OriginalExportSHA256 = "" },
		"missing invocation":      func(p *gotoolprofile.InstrumentationMetadataProof) { p.InvocationConfigSHA256 = nil },
		"ordinary load flags":     func(p *gotoolprofile.InstrumentationMetadataProof) { p.LoadBuildFlags = []string{"-mod=readonly"} },
		"ordinary vet flags": func(p *gotoolprofile.InstrumentationMetadataProof) {
			p.VetArgs = []string{"vet", "-asmdecl", input.Plan.PackagePath}
		},
		"missing dependencies": func(p *gotoolprofile.InstrumentationMetadataProof) { p.Dependencies = nil },
		"changed dependency": func(p *gotoolprofile.InstrumentationMetadataProof) {
			p.Dependencies[0].Source.ExportSHA256 = strings.Repeat("0", 64)
		},
		"ordinary header": func(p *gotoolprofile.InstrumentationMetadataProof) {
			p.Headers[0].Header.Protocol = gotoolprofile.GeneratedHeaderProtocol
		},
		"missing mode flags": func(p *gotoolprofile.InstrumentationMetadataProof) { p.Headers[0].CompilerFlags = nil },
		"unknown flags": func(p *gotoolprofile.InstrumentationMetadataProof) {
			p.Headers[0].CompilerFlags = append(p.Headers[0].CompilerFlags, "-N")
		},
		"missing import": func(p *gotoolprofile.InstrumentationMetadataProof) { p.Headers[0].Header.Imports = nil },
		"changed import source": func(p *gotoolprofile.InstrumentationMetadataProof) {
			p.Headers[0].Header.Imports[0].GoSHA256["dep/value_mode.go"] = strings.Repeat("0", 64)
		},
		"claim pass": func(p *gotoolprofile.InstrumentationMetadataProof) { p.Status = "passed" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.InstrumentationMetadataProof
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := gotoolprofile.ValidateInstrumentationMetadata(input, ".", nil, &changed); err == nil {
				t.Fatal("mode metadata accepted changed or downgraded context/consumption")
			}
		})
	}
	for _, bad := range []string{string(data) + "{}", strings.Replace(string(data), "\"protocol\":", "\"unknown\":true,\"protocol\":", 1)} {
		if _, err := gotoolprofile.DecodeInstrumentationMetadata(strings.NewReader(bad), input, ".", nil); err == nil {
			t.Fatal("mode metadata accepted trailing or unknown JSON")
		}
	}
}

func TestInstrumentationMetadataActualStandardLibraryClosure(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	source := strings.Replace(input.Original.Headers["mode.go"], "import \"example.invalid/modeheader/dep\"", "import (\"example.invalid/modeheader/dep\"; \"math/bits\")", 1)
	source += "const NativeWord = bits.UintSize\n"
	if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, "mode.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Headers["mode.go"], input.Original.Sources["mode.go"] = source, featureBytesSHA256([]byte(source))
	replanInstrumentationMetadataFixture(t, input)
	consumer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	if consumer.Metadata.Headers[0].Header.Definitions["const_NativeWord"] != "64" || len(consumer.Metadata.Dependencies) < 2 {
		t.Fatal("metadata omitted actual same-mode standard-library dependency exports")
	}
	if err := gotoolprofile.ValidateInstrumentationMetadata(input, ".", nil, consumer.Metadata); err != nil {
		t.Fatal(err)
	}
	for _, dep := range consumer.Metadata.Dependencies {
		if dep.Source.PackagePath == "math/bits" && dep.Source.SourceRole != "stdlib" {
			t.Fatal("standard-library source was relabeled as an external module")
		}
	}
}

func replanInstrumentationMetadataFixture(t *testing.T, input *gotoolprofile.InstrumentationConsumerInput) {
	t.Helper()
	var err error
	input.Sources, err = gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input.Original, ".")
	if err != nil {
		t.Fatal(err)
	}
	input.Plan, err = gotoolprofile.PlanInstrumentationOriginalPackage(input.Original, input.Sources, input.Observation.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestInstrumentationMetadataRejectsActualDependencyAndRoutingChanges(t *testing.T) {
	for _, scenario := range []string{"dependency during load", "ordinary load flags", "missing dependency export", "dependency after capture", "invocation after capture"} {
		t.Run(scenario, func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
			loader := func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
				if scenario == "dependency during load" && config.Mode&packages.NeedExportFile != 0 {
					if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, "dep/value_mode.go"), []byte("//go:build race || msan || asan\n\npackage dep\nconst Value = 41\n"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if scenario == "ordinary load flags" {
					config.BuildFlags = []string{"-mod=readonly"}
				}
				pkgs, err := packages.Load(config, patterns...)
				if scenario == "missing dependency export" && config.Mode&packages.NeedExportFile != 0 && len(pkgs) != 0 {
					for _, dep := range pkgs[0].Imports {
						dep.ExportFile = ""
					}
				}
				return pkgs, err
			}
			consumer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), loader)
			if strings.HasSuffix(scenario, "after capture") {
				if err != nil {
					t.Fatal(err)
				}
				file := "dep/value_mode.go"
				if scenario == "invocation after capture" {
					file = "go.mod"
				}
				if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, file), []byte("changed actual original bytes\n"), 0600); err != nil {
					t.Fatal(err)
				}
				err = consumer.verifySources()
			}
			if err == nil {
				t.Fatal("mode metadata accepted changed source/export/flags or caller configuration")
			}
		})
	}
}

func TestInstrumentationMetadataKeepsIndependentInvocationAndActualModuleIdentity(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	input.Original.Version = "v1.0.0"
	if _, err := gotoolprofile.PlanInstrumentationOriginalPackage(input.Original, input.Sources, input.Observation.Early, ".", nil); err == nil {
		t.Fatal("versioned owned source was accepted as an authenticated external identity")
	}
	invocation, env := instrumentationVersionedFixture(t, ctx, input)
	replanInstrumentationMetadataFixture(t, input)
	consumer, err := captureInstrumentationMetadata(ctx, input, invocation, env, t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	selected := consumer.Metadata.Selection.Packages[0]
	if selected.ModulePath != input.Original.Module || selected.ModuleVersion != "v1.0.0" ||
		selected.SourceRole != "module" || consumer.Source.Dir == consumer.Source.WorkDir ||
		consumer.Metadata.InvocationConfigSHA256["go.mod"] == input.Original.Sources["go.mod"] {
		t.Fatal("independent invocation was confused with the actual selected fixture source module")
	}
	// This is an explicit synthetic fileproxy fixture, not official-SumDB
	// evidence. It exercises actual packages.Load Module/Replace boundaries.
	for _, scenario := range []string{"selected version", "replacement directory"} {
		t.Run(scenario, func(t *testing.T) {
			load := func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
				pkgs, err := packages.Load(config, patterns...)
				if config.Mode&packages.NeedExportFile != 0 && len(pkgs) != 0 {
					if scenario == "selected version" {
						pkgs[0].Module.Version = "v1.0.1"
					} else {
						pkgs[0].Module.Replace = &packages.Module{Path: input.Original.Module, Dir: t.TempDir()}
					}
				}
				return pkgs, err
			}
			if _, err := captureInstrumentationMetadata(ctx, input, invocation, env, t.TempDir(), load); err == nil {
				t.Fatal("actual mode metadata accepted redirected module/version provenance")
			}
		})
	}
}

func instrumentationVersionedFixture(t *testing.T, ctx context.Context, input *gotoolprofile.InstrumentationConsumerInput) (string, []string) {
	t.Helper()
	proxy, invocation := t.TempDir(), t.TempDir()
	prefix := input.Original.Module + "@" + input.Original.Version + "/"
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name := range input.Original.Sources {
		data, err := os.ReadFile(filepath.Join(input.Original.SourceRoot, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		member, err := writer.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := member.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	mod, err := os.ReadFile(filepath.Join(input.Original.SourceRoot, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	versionDir := filepath.Join(proxy, filepath.FromSlash(input.Original.Module), "@v")
	if err := os.MkdirAll(versionDir, 0700); err != nil {
		t.Fatal(err)
	}
	for suffix, data := range map[string][]byte{
		".mod": mod, ".zip": archive.Bytes(),
		".info": []byte(`{"Version":"v1.0.0","Time":"2026-01-01T00:00:00Z"}`),
	} {
		if err := os.WriteFile(filepath.Join(versionDir, input.Original.Version+suffix), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caller := "module example.invalid/invocation\n\ngo 1.24\n\nrequire " + input.Original.Module + " " + input.Original.Version + "\n"
	if err := os.WriteFile(filepath.Join(invocation, "go.mod"), []byte(caller), 0600); err != nil {
		t.Fatal(err)
	}
	modules := t.TempDir()
	// Go deliberately makes extracted ZIP directories read-only. Restore only
	// this owned fixture cache's directory permissions after all source guards,
	// before testing.TempDir removes it; no shared module cache is touched.
	t.Cleanup(func() {
		if err := filepath.WalkDir(modules, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return os.Chmod(name, 0700)
			}
			return nil
		}); err != nil {
			t.Errorf("owned fileproxy cache cleanup: %v", err)
		}
	})
	proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
	if err != nil {
		t.Fatal(err)
	}
	env := featureEnvironment(os.Environ(), map[string]string{
		"GOPROXY": proxyURL, "GOSUMDB": "off",
		"GOMODCACHE": modules, "GOPATH": t.TempDir(),
	})
	stdout, stderr, err := gotoolprofile.RunBounded(ctx, invocation, env, "go", "mod", "download", "-json", input.Original.Module+"@"+input.Original.Version)
	if err != nil || len(stderr) != 0 {
		t.Fatalf("synthetic exact fileproxy download: %v; %s; %s", err, stdout, stderr)
	}
	var downloaded struct{ Dir string }
	if err := json.Unmarshal(stdout, &downloaded); err != nil || downloaded.Dir == "" {
		t.Fatalf("synthetic exact extraction: %v", err)
	}
	input.Original.SourceRoot, input.Original.SourceModule = downloaded.Dir, input.Original.Module
	return invocation, env
}
