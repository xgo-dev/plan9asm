package gotoolprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The source below is a controlled first-party fixture. Only its metadata
// identity uses an existing independently signed public checksum record; this
// test does not authenticate, translate or execute that external module.
func instrumentationTypeLegacyMetadataFixture(t *testing.T) (*InstrumentationConsumerInput, instrumentationTypeListPackage, string) {
	t.Helper()
	metadata := fixtureProxyGoMod(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	const source = "package legacy\nvar Value byte\n"
	if err := os.WriteFile(filepath.Join(root, "legacy.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	metadataDirectory, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(metadataDirectory, "download.mod")
	if err := os.WriteFile(filename, []byte(metadata.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	original := &ConsumerInput{
		Module: metadata.Module, Version: metadata.Version, SourceModule: metadata.Module,
		SourceRoot: root, Sources: map[string]string{"legacy.go": bytesSHA256([]byte(source))},
		Directories: map[string][]string{".": {"legacy.go"}},
		ProxyGoMod:  metadata, ProxyGoModPath: filename,
	}
	pkg := instrumentationTypeListPackage{
		Dir: root, ImportPath: metadata.Module, Name: "legacy",
		GoFiles: []string{"legacy.go"}, CompiledGoFiles: []string{"legacy.go"},
		Module: &instrumentationTypeListModule{
			Path: metadata.Module, Version: metadata.Version, Dir: root, GoMod: filename,
		},
	}
	return &InstrumentationConsumerInput{Original: original}, pkg, filename
}

func instrumentationTypeMetadataCapture(input *InstrumentationConsumerInput, pkg instrumentationTypeListPackage) (*instrumentationTypeGraph, error) {
	graph := &instrumentationTypeGraph{
		hashes: make(map[string]string), paths: make(map[string]string),
		files: make(map[string]map[string]string),
	}
	_, err := captureInstrumentationTypePackage(input, nil, pkg, graph, false)
	return graph, err
}

func TestInstrumentationTypeMetadataAcceptsAuthenticatedLegacyOrigin(t *testing.T) {
	for _, replaced := range []bool{false, true} {
		name := "module"
		if replaced {
			name = "exact_version_replacement"
		}
		t.Run(name, func(t *testing.T) {
			input, pkg, metadata := instrumentationTypeLegacyMetadataFixture(t)
			if replaced {
				replacement := *pkg.Module
				pkg.Module.Replace = &replacement
			}
			graph, err := instrumentationTypeMetadataCapture(input, pkg)
			if err != nil {
				t.Fatalf("signed legacy metadata is a distinct origin, not a missing ZIP member: %v", err)
			}
			if graph.hashes[metadata] != input.Original.ProxyGoMod.SHA256 || graph.paths[metadata] != metadata {
				t.Fatal("capture omitted the actual metadata byte/path guard")
			}
			if _, invented := input.Original.Sources["go.mod"]; invented {
				t.Fatal("proxy metadata was added to the original source inventory")
			}
		})
	}
}

func TestInstrumentationTypeMetadataKeepsOriginalZIPOrigin(t *testing.T) {
	input, pkg, _ := instrumentationTypeLegacyMetadataFixture(t)
	metadata := filepath.Join(input.Original.SourceRoot, "go.mod")
	contents := input.Original.ProxyGoMod.Contents
	if err := os.WriteFile(metadata, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.ProxyGoMod, input.Original.ProxyGoModPath = nil, ""
	input.Original.Sources["go.mod"] = bytesSHA256([]byte(contents))
	input.Original.Directories["."] = []string{"go.mod", "legacy.go"}
	pkg.Module.GoMod = metadata
	graph, err := instrumentationTypeMetadataCapture(input, pkg)
	if err != nil || graph.hashes[metadata] != input.Original.Sources["go.mod"] {
		t.Fatalf("ordinary original metadata lost its unchanged byte guard: %v", err)
	}
}

func TestInstrumentationTypeMetadataRejectsChangedOriginsAndPaths(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *InstrumentationConsumerInput, *instrumentationTypeListPackage){
		"missing proof": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.ProxyGoMod = nil
		},
		"signed proof changed": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.ProxyGoMod.SignedTree += "changed"
		},
		"missing inclusion": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.ProxyGoMod.Inclusion = nil
		},
		"foreign version": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.ProxyGoMod.Version = "v1.0.0"
		},
		"missing original namespace": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.SourceModule = ""
		},
		"unproved ZIP member": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.Sources["go.mod"] = i.Original.ProxyGoMod.SHA256
		},
		"invented ZIP member": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.Directories["."] = []string{"go.mod", "legacy.go"}
		},
		"missing download path": func(_ *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			i.Original.ProxyGoModPath = ""
		},
		"relative actual path": func(_ *testing.T, _ *InstrumentationConsumerInput, p *instrumentationTypeListPackage) {
			p.Module.GoMod = "download.mod"
		},
		"different equal-byte metadata": func(t *testing.T, i *InstrumentationConsumerInput, p *instrumentationTypeListPackage) {
			filename := filepath.Join(t.TempDir(), "copy.mod")
			if err := os.WriteFile(filename, []byte(i.Original.ProxyGoMod.Contents), 0600); err != nil {
				t.Fatal(err)
			}
			p.Module.GoMod = filename
		},
		"metadata inside ZIP root": func(t *testing.T, i *InstrumentationConsumerInput, p *instrumentationTypeListPackage) {
			filename := filepath.Join(i.Original.SourceRoot, "go.mod")
			if err := os.WriteFile(filename, []byte(i.Original.ProxyGoMod.Contents), 0600); err != nil {
				t.Fatal(err)
			}
			i.Original.ProxyGoModPath, p.Module.GoMod = filename, filename
		},
		"metadata symlink": func(t *testing.T, i *InstrumentationConsumerInput, p *instrumentationTypeListPackage) {
			filename := filepath.Join(t.TempDir(), "link.mod")
			if err := os.Symlink(i.Original.ProxyGoModPath, filename); err != nil {
				t.Fatal(err)
			}
			i.Original.ProxyGoModPath, p.Module.GoMod = filename, filename
		},
		"metadata bytes changed": func(t *testing.T, i *InstrumentationConsumerInput, _ *instrumentationTypeListPackage) {
			if err := os.WriteFile(i.Original.ProxyGoModPath, []byte(i.Original.ProxyGoMod.Contents+"// changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			input, pkg, _ := instrumentationTypeLegacyMetadataFixture(t)
			mutate(t, input, &pkg)
			if _, err := instrumentationTypeMetadataCapture(input, pkg); err == nil {
				t.Fatal("unbound legacy metadata acquired original imported-type authority")
			}
		})
	}
}

func TestInstrumentationTypeMetadataCannotTrustPairedUnsignedBytes(t *testing.T) {
	input, pkg, _ := instrumentationTypeLegacyMetadataFixture(t)
	proof := input.Original.ProxyGoMod
	proof.Contents += "// fabricated metadata\n"
	proof.SHA256 = bytesSHA256([]byte(proof.Contents))
	proof.SignedTree = strings.Replace(proof.SignedTree, "sum.golang.org", "untrusted.invalid", 1)
	if err := os.WriteFile(input.Original.ProxyGoModPath, []byte(proof.Contents), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := instrumentationTypeMetadataCapture(input, pkg); err == nil {
		t.Fatal("paired proof/path/hash agreement replaced the signed original origin")
	}
}
