package gotoolprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstrumentationOriginalModuleNamespaceBindsOriginalBytesAndArchive(t *testing.T) {
	contents := "module example.invalid/canonical\n\ngo 1.20\n"
	input := &ConsumerInput{
		Module: "example.invalid/canonical", SourceModule: "example.invalid/archive", Version: "v1.0.0",
		SourceRoot: "/original-offline", Sources: map[string]string{"go.mod": bytesSHA256([]byte(contents))},
		Directories: map[string][]string{".": {"go.mod", "probe.go"}},
	}
	body := "package probe\n"
	input.Sources["probe.go"] = bytesSHA256([]byte(body))
	inventory := &InstrumentationOriginalSourceInventory{
		Protocol: instrumentationOriginalSourcesProtocol, Module: input.Module, Version: input.Version, Directory: ".",
		Contents: map[string]string{"probe.go": body}, ModuleMetadata: contents,
	}
	if err := ValidateInstrumentationOriginalSourceInventory(input, ".", inventory); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(struct {
		Input   *ConsumerInput
		Sources *InstrumentationOriginalSourceInventory
	}{input, inventory})
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ConsumerInput, *InstrumentationOriginalSourceInventory){
		"missing original bytes": func(_ *ConsumerInput, p *InstrumentationOriginalSourceInventory) { p.ModuleMetadata = "" },
		"changed original bytes": func(_ *ConsumerInput, p *InstrumentationOriginalSourceInventory) { p.ModuleMetadata += "// changed\n" },
		"changed namespace": func(i *ConsumerInput, p *InstrumentationOriginalSourceInventory) {
			i.Module, p.Module = "example.invalid/other", "example.invalid/other"
		},
		"missing original member": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) { delete(i.Sources, "go.mod") },
		"missing directory member": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) {
			i.Directories["."] = []string{"probe.go"}
		},
		"duplicate directory member": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) {
			i.Directories["."] = []string{"go.mod", "go.mod", "probe.go"}
		},
		"unbound metadata digest": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) {
			i.Sources["go.mod"] = strings.Repeat("0", 64)
		},
		"main instead of archive": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) { i.SourceModule = "" },
		"malformed archive path":  func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) { i.SourceModule = "bad archive" },
		"wrong version major": func(i *ConsumerInput, p *InstrumentationOriginalSourceInventory) {
			i.Version, p.Version = "v2.0.0", "v2.0.0"
		},
		"proxy instead of ZIP origin": func(i *ConsumerInput, _ *InstrumentationOriginalSourceInventory) { i.ProxyGoMod = &ProxyGoModProof{} },
		"paired alias deletion": func(i *ConsumerInput, p *InstrumentationOriginalSourceInventory) {
			i.Module, p.Module = i.SourceModule, i.SourceModule
			// Retaining the original metadata cannot authorize this requested
			// namespace: the actual source declaration still says canonical.
		},
	} {
		t.Run(name, func(t *testing.T) {
			var copied struct {
				Input   *ConsumerInput
				Sources *InstrumentationOriginalSourceInventory
			}
			if err := json.Unmarshal(encoded, &copied); err != nil {
				t.Fatal(err)
			}
			change(copied.Input, copied.Sources)
			if err := ValidateInstrumentationOriginalSourceInventory(copied.Input, ".", copied.Sources); err == nil {
				t.Fatal("accepted an unbound original module namespace")
			}
		})
	}
}

func TestInstrumentationOriginalModuleNamespaceRejectsInvalidMetadata(t *testing.T) {
	for _, contents := range []string{
		"", "go 1.20\n", "module bad module\n", "module example.invalid/a\nmodule example.invalid/b\n",
		"module example.invalid/a\nunknown_directive x\n", strings.Repeat("x", instrumentationOriginalFileLimit+1),
	} {
		if _, err := InstrumentationOriginalModulePath(contents, bytesSHA256([]byte(contents))); err == nil {
			t.Fatalf("accepted invalid or over-bound original module metadata (%d bytes)", len(contents))
		}
	}
}

func TestInstrumentationOriginalModuleNamespaceCaptureRejectsChangedAndRedirectedSource(t *testing.T) {
	root := t.TempDir()
	metadata := "module example.invalid/canonical\n\ngo 1.20\n"
	body := "package probe\n"
	for name, value := range map[string]string{"go.mod": metadata, "probe.go": body} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	input := &ConsumerInput{
		Module: "example.invalid/canonical", SourceModule: "example.invalid/archive", Version: "v1.0.0", SourceRoot: root,
		Sources:     map[string]string{"go.mod": bytesSHA256([]byte(metadata)), "probe.go": bytesSHA256([]byte(body))},
		Directories: map[string][]string{".": {"go.mod", "probe.go"}},
	}
	captured, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil || captured.ModuleMetadata != metadata {
		t.Fatalf("capture changed the complete original namespace bytes: %v", err)
	}
	filename := filepath.Join(root, "go.mod")
	if err := os.WriteFile(filename, []byte(metadata+"// changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInstrumentationOriginalSourceInventory(input, "."); err == nil {
		t.Fatal("captured source changed after registration")
	}
	if err := os.Remove(filename); err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(copy, []byte(metadata), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(copy, filename); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureInstrumentationOriginalSourceInventory(input, "."); err == nil {
		t.Fatal("captured symlink instead of the original module member")
	}
}
