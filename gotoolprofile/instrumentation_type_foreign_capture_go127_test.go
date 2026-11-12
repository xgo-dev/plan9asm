//go:build go1.27

package gotoolprofile

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

// This proxy is a first-party mechanics fixture, NOT official SumDB source
// authentication. Production capture must still use authenticated downloads.
func instrumentationForeignFixtureProxy(t *testing.T, root, module, version, declaration string) {
	t.Helper()
	files := map[string]string{
		"go.mod":          "module example.invalid/layoutdep\n\ngo 1.20\n",
		"model/layout.go": declaration,
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entry, err := writer.Create(module + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(entry, files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, filepath.FromSlash(module), "@v")
	for suffix, contents := range map[string][]byte{
		".mod":  []byte(files["go.mod"]),
		".info": []byte(fmt.Sprintf("{\"Version\":%q,\"Time\":\"2026-01-01T00:00:00Z\"}\n", version)),
		".zip":  buffer.Bytes(),
	} {
		writeInstrumentationFixture(t, directory, version+suffix, contents)
	}
}

func instrumentationForeignFixtureResource(t *testing.T, data []byte) TestModuleSource {
	t.Helper()
	var download struct{ Path, Version, Dir, Zip, Sum, GoModSum string }
	if err := json.Unmarshal(data, &download); err != nil {
		t.Fatal(err)
	}
	resource := TestModuleSource{Protocol: TestDependencyModuleProtocol, SourceModule: download.Path, SourceVersion: download.Version,
		ModuleSum: download.Sum, GoModSum: download.GoModSum, GoModOrigin: TestModuleOriginalGoModOrigin,
		Sources: make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]TestSourceEntry)}
	for _, directory := range []string{".", "model"} {
		entries, err := os.ReadDir(filepath.Join(download.Dir, directory))
		if err != nil {
			t.Fatal(err)
		}
		resource.Directories[directory] = []TestSourceEntry{}
		for _, entry := range entries {
			member := TestSourceEntry{Name: entry.Name(), Kind: "directory"}
			if !entry.IsDir() {
				member.Kind = "file"
				name := filepath.ToSlash(filepath.Join(directory, entry.Name()))
				contents, err := os.ReadFile(filepath.Join(download.Dir, filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				member.SHA256 = bytesSHA256(contents)
				resource.Sources[name] = member.SHA256
				if strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".s") {
					resource.Headers[name], err = TestSelectionHeader(name, contents)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			resource.Directories[directory] = append(resource.Directories[directory], member)
		}
	}
	resource.GoModSHA256 = resource.Sources["go.mod"]
	var err error
	resource.ZipSHA256, err = FileSHA256(download.Zip)
	if err != nil {
		t.Fatal(err)
	}
	return resource
}

func TestInstrumentationForeignTypeSourceActualDualModule(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, fixture := range []struct {
		name               string
		replaced, bodyOnly bool
		blankUnsafeImport  bool
	}{
		{name: "version_replacement_false"},
		{name: "version_replacement_true", replaced: true},
		{name: "ordinary_body_only", bodyOnly: true},
		{name: "ordinary_body_blank_import", bodyOnly: true, blankUnsafeImport: true},
	} {
		replaced := fixture.replaced
		t.Run(fixture.name, func(t *testing.T) {
			proxy := instrumentationMarkerDirectory(t)
			cache := instrumentationMarkerDirectory(t)
			t.Cleanup(func() {
				// Go intentionally extracts this owned fixture read-only. Restore
				// only its directory modes before testing removes the private tree.
				if err := filepath.Walk(cache, func(name string, info os.FileInfo, err error) error {
					if err == nil && info.IsDir() {
						return os.Chmod(name, 0700)
					}
					return err
				}); err != nil {
					t.Error(err)
				}
			})
			archive := "example.invalid/layoutdep"
			mod := "module " + instrumentationExportModule + "\n\ngo 1.20\nrequire example.invalid/layoutdep v1.0.0\n"
			if replaced {
				archive = "example.invalid/layout-archive"
				mod += "replace example.invalid/layoutdep v1.0.0 => " + archive + " v1.0.0\n"
			}
			foreignSource := "package model\n"
			if fixture.blankUnsafeImport {
				foreignSource += "import _ \"unsafe\"\n"
			}
			foreignSource += "const Words=2\ntype Header struct { Lo uint32; Pad [Words]byte; Hi uint16 }\n"
			instrumentationForeignFixtureProxy(t, proxy, archive, "v1.0.0", foreignSource)
			proxyURL, err := gooriginalsrc.FileProxyURL(proxy)
			if err != nil {
				t.Fatal(err)
			}
			env := replaceEnv(os.Environ(), map[string]string{
				"GOPROXY": proxyURL, "GOSUMDB": "off", "GONOSUMDB": "", "GOPRIVATE": "",
				"GOMODCACHE": cache, "GOPATH": instrumentationMarkerDirectory(t),
			})
			marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), env,
				"darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			original := instrumentationOriginalFixture(t, marker.Early)
			rootSource := "package markers\nimport shape \"example.invalid/layoutdep/model\"\nfunc marker(value shape.Header) uint64\n"
			if fixture.bodyOnly {
				rootSource = "package markers\nimport shape \"example.invalid/layoutdep/model\"\nfunc marker(value uint64) uint64\nfunc ordinary() shape.Header { return shape.Header{} }\n"
			}
			for name, source := range map[string]string{
				"go.mod":      mod,
				"base.go":     rootSource,
				"mode_race.s": "//go:build race\n\n#include \"textflag.h\"\nTEXT ·marker(SB),NOSPLIT,$0-16\nMOVD $0,R0\nMOVD R0,ret+8(FP)\nRET\n",
			} {
				writeInstrumentationFixture(t, original.SourceRoot, name, []byte(source))
				original.Sources[name], original.Headers[name] = bytesSHA256([]byte(source)), source
			}
			env = instrumentationFixtureEnvironment(env, marker.Early)
			download, downloadStderr, downloadErr := RunBounded(ctx, original.SourceRoot, env, binary,
				"mod", "download", "-json", archive+"@v1.0.0")
			if downloadErr != nil {
				t.Fatalf("first-party fixture download: %v; %s", downloadErr, downloadStderr)
			}
			t.Logf("actual first-party download (not official authentication): %s; stderr=%q", download, downloadStderr)
			// Keep raw stock-Go records before capture fails. These are actual
			// Module/Replace/ImportMap records, not reconstructed expected roots.
			args := []string{"list", "-mod=mod", "-deps", "-compiled", "-export", "-json", "-race", original.Module}
			stdout, stderr, commandErr := RunBounded(ctx, original.SourceRoot, env, binary, args...)
			if commandErr != nil || len(stderr) != 0 {
				t.Fatalf("actual dual-module graph setup: %v; %s", commandErr, stderr)
			}
			// Freeze actual invocation metadata only after stock Go has written
			// its first-party checksums. Capture may not mutate the inventory.
			sum, err := os.ReadFile(filepath.Join(original.SourceRoot, "go.sum"))
			if err != nil {
				t.Fatal(err)
			}
			original.Sources["go.sum"], original.Headers["go.sum"] = bytesSHA256(sum), string(sum)
			original.Directories["."] = append(original.Directories["."], "go.sum")
			sort.Strings(original.Directories["."])
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
			decoder := json.NewDecoder(bytes.NewReader(stdout))
			found := false
			for {
				var pkg instrumentationTypeListPackage
				if err := decoder.Decode(&pkg); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if pkg.ImportPath == plan.PackagePath {
					record, err := json.Marshal(pkg)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("actual root package: %s", record)
				}
				if pkg.ImportPath == "example.invalid/layoutdep/model" {
					found = true
					if pkg.Module == nil || pkg.Module.Path != "example.invalid/layoutdep" || pkg.Module.Version != "v1.0.0" ||
						(pkg.Module.Replace != nil) != replaced || pkg.Export == "" {
						t.Fatalf("actual dependency identity lost: %+v", pkg)
					}
					record, err := json.Marshal(pkg)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("actual foreign package: %s", record)
				}
			}
			if !found {
				t.Fatal("stock Go omitted the foreign package")
			}
			t.Logf("actual tool=%s sha256=%s graph_sha256=%s argv=%q; first-party file proxy is not a SumDB certificate",
				binary, marker.Early.BaselineFeatures.DriverSHA256, bytesSHA256(stdout), args)
			resource := instrumentationForeignFixtureResource(t, download)
			proof, err := CaptureInstrumentationTypeSourcesWithModules(ctx, binary, original.SourceRoot, env, input, []TestModuleSource{resource}, RunBounded)
			if err != nil {
				if !strings.Contains(err.Error(), "authenticated foreign module source closure") {
					t.Fatalf("unexpected actual graph failure: %v", err)
				}
				t.Fatalf("actual dual-module source role remains unavailable: %v", err)
			}
			if proof == nil {
				t.Fatal("capture returned no independent source proof")
			}
			if len(proof.SourceModules) != 1 || len(proof.Dependencies) != 1 || proof.Dependencies[0].SourceRootID != archive+"@v1.0.0" {
				t.Fatal("v2 capture omitted the exact source-only foreign resource")
			}
			input.TypeSources = proof
			encoded, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.bodyOnly {
				if proof.Dependencies[0].Contents != nil {
					t.Fatal("ordinary body import unexpectedly obtained a declaration-AST role")
				}
				if err := ValidateInstrumentationTypeSources(input, proof); err != nil {
					t.Fatalf("actual body-only original graph failed portable replay: %v", err)
				}
				mutations := map[string]func(*InstrumentationConsumerInput){}
				if fixture.blankUnsafeImport {
					mutations["deleted actual blank import"] = func(p *InstrumentationConsumerInput) {
						p.TypeSources.Dependencies[0].Dependency.ImportMap = map[string]string{}
						p.TypeSources.UnsafeSHA256 = ""
					}
					mutations["redirected actual blank spelling"] = func(p *InstrumentationConsumerInput) {
						p.TypeSources.Dependencies[0].Dependency.ImportMap = map[string]string{"example.invalid/not-in-original": "unsafe"}
					}
				} else {
					root, stderr, err := RunBounded(ctx, original.SourceRoot, env, binary, "env", "GOROOT")
					if err != nil || len(stderr) != 0 {
						t.Fatalf("actual SDK unsafe-source origin: %v; %s", err, stderr)
					}
					unsafeSHA, err := FileSHA256(filepath.Join(strings.TrimSpace(string(root)), "src", "unsafe", "unsafe.go"))
					if err != nil {
						t.Fatal(err)
					}
					mutations["invented unsafe import"] = func(p *InstrumentationConsumerInput) {
						p.TypeSources.Dependencies[0].Dependency.ImportMap["unsafe"] = "unsafe"
						p.TypeSources.UnsafeSHA256 = unsafeSHA
					}
				}
				for name, mutate := range mutations {
					t.Run(name, func(t *testing.T) {
						var changed InstrumentationConsumerInput
						if err := json.Unmarshal(encoded, &changed); err != nil {
							t.Fatal(err)
						}
						mutate(&changed)
						// Only the claimed topology changes; actual Go selection,
						// source/header/ZIP bytes and export/tool receipts stay fixed.
						if err := ValidateInstrumentationTypeSources(&changed, changed.TypeSources); err == nil {
							t.Fatal("portable reader accepted changed ImportMap without declaration Contents")
						}
					})
				}
				return
			}
			for name, mutate := range map[string]func(*InstrumentationConsumerInput){
				"inventory deleted": func(p *InstrumentationConsumerInput) { p.TypeSources.SourceModules = nil },
				"inventory emptied": func(p *InstrumentationConsumerInput) { p.TypeSources.SourceModules = []TestModuleSource{} },
				"v1 downgrade": func(p *InstrumentationConsumerInput) {
					p.TypeSources.Protocol = "actual_go_instrumentation_type_sources_v1"
				},
				"resource identity":      func(p *InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].SourceRootID += "-changed" },
				"foreign source version": func(p *InstrumentationConsumerInput) { p.TypeSources.SourceModules[0].SourceVersion = "v1.0.1" },
				"Go source removed": func(p *InstrumentationConsumerInput) {
					p.TypeSources.Dependencies[0].Dependency.Source.GoSHA256 = map[string]string{}
				},
				"assembly added": func(p *InstrumentationConsumerInput) {
					p.TypeSources.Dependencies[0].SFiles = []string{"model/unbound.s"}
				},
				"directory truncated": func(p *InstrumentationConsumerInput) {
					p.TypeSources.SourceModules[0].Directories["model"] = []TestSourceEntry{}
				},
				"header deleted": func(p *InstrumentationConsumerInput) {
					delete(p.TypeSources.SourceModules[0].Headers, "model/layout.go")
				},
				"ZIP hash": func(p *InstrumentationConsumerInput) {
					p.TypeSources.SourceModules[0].ZipSHA256 = strings.Repeat("0", 64)
				},
				"module h1": func(p *InstrumentationConsumerInput) {
					p.TypeSources.SourceModules[0].ModuleSum = "h1:" + strings.Repeat("A", 43) + "="
				},
				"metadata h1": func(p *InstrumentationConsumerInput) {
					p.TypeSources.SourceModules[0].GoModSum = "h1:" + strings.Repeat("A", 43) + "="
				},
				"ordinary role": func(p *InstrumentationConsumerInput) {
					p.TypeSources.Dependencies[0].Dependency.Source.SourceRole = "main"
				},
				"actual export": func(p *InstrumentationConsumerInput) {
					p.TypeSources.Dependencies[0].Dependency.Source.ExportSHA256 = strings.Repeat("0", 64)
				},
			} {
				t.Run(name, func(t *testing.T) {
					var changed InstrumentationConsumerInput
					if err := json.Unmarshal(encoded, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(&changed)
					actual, err := CaptureInstrumentationTypeSources(ctx, binary, original.SourceRoot, env, &changed, RunBounded)
					if err == nil && reflect.DeepEqual(actual, changed.TypeSources) {
						t.Fatal("changed foreign resources acquired an independent actual consumer proof")
					}
				})
			}
			guard, err := BindInstrumentationTypeModuleSources(ctx, binary, original.SourceRoot, env, proof.SourceModules, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			var downloaded struct{ Dir string }
			if err := json.Unmarshal(download, &downloaded); err != nil {
				t.Fatal(err)
			}
			foreignFile := filepath.Join(downloaded.Dir, "model", "layout.go")
			originalBytes, err := os.ReadFile(foreignFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(foreignFile, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(foreignFile, append(originalBytes, []byte("\n// actual post-load mutation\n")...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := guard.Verify(ctx); err == nil {
				t.Fatal("live final foreign source guard ignored actual original byte mutation")
			}
			if err := os.WriteFile(foreignFile, originalBytes, 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
}
