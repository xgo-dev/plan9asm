package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ordinarySourceClosureFixture(t *testing.T) (*ConsumerInput, *MetadataProof, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":        "module example.invalid/ordinary\n\ngo 1.20\n",
		"root.go":       "package ordinary\nimport _ \"example.invalid/ordinary/dep\"\n",
		"dep/dep.go":    "package dep\nimport _ \"embed\"\n//go:embed asset.bin\nvar Asset []byte\n",
		"dep/asset.bin": "original asset\n",
	}
	for file, text := range files {
		filename := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(filename), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filename, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	var inventory SourceInventory
	if err := CaptureSourceDirectory(context.Background(), &inventory, root, root, true); err != nil {
		t.Fatal(err)
	}
	input := inventoryInput(&ConsumerInput{Module: "example.invalid/ordinary", Observed: &Observation{
		Target: "linux/amd64", GoVersion: "go1.27.1", Environment: map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
	}}, inventory)
	makePackage := func(name, file string) SourcePackageProof {
		pkg := PackageProof{PackagePath: name, ModulePath: input.Module, SourceModule: input.Module, SourceRole: "main",
			GoFiles: []string{file}, CompiledGoFiles: []string{file}, SourceSHA256: map[string]string{file: inventory.Sources[file]},
		}
		return SourcePackageProof{Package: pkg, VariantID: name, ImportMap: make(map[string]string)}
	}
	rootPackage := makePackage(input.Module, "root.go")
	rootPackage.ImportMap[input.Module+"/dep"] = input.Module + "/dep"
	rootPackage.Embed, err = CaptureTestEmbedSelection(rootPackage.Package, root, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	dep := makePackage(input.Module+"/dep", "dep/dep.go")
	dep.ImportMap["embed"] = "embed"
	dep.Embed, err = CaptureTestEmbedSelection(dep.Package, root, []string{"asset.bin"}, []string{"dep/asset.bin"})
	if err != nil {
		t.Fatal(err)
	}
	stdlib := ModuleSourceSnapshot{Protocol: TestDependencyModuleProtocol, GoVersion: input.Observed.GoVersion,
		Sources:     map[string]string{"embed/embed.go": bytesSHA256([]byte("package embed\n"))},
		Headers:     map[string]string{"embed/embed.go": "package embed\n"},
		Directories: map[string][]TestSourceEntry{".": {{Name: "embed", Kind: "directory"}}, "embed": {{Name: "embed.go", Kind: "file", SHA256: bytesSHA256([]byte("package embed\n"))}}},
	}
	embed := SourcePackageProof{Package: PackageProof{PackagePath: "embed", SourceRole: "stdlib", GoFiles: []string{"embed/embed.go"}, CompiledGoFiles: []string{"embed/embed.go"}, SourceSHA256: stdlib.Sources},
		VariantID: "embed", ImportMap: map[string]string{}, SourceRootID: stdlib.ID(), ExportSHA256: strings.Repeat("a", 64),
		Embed: &EmbedSelection{Protocol: TestEmbedProtocol, Directives: map[string]string{"embed/embed.go": ""}, Files: map[string]string{}},
	}
	metadata := &MetadataProof{Dependencies: &OrdinaryDependencyProof{Protocol: OrdinaryDependencyProtocol,
		Candidate: inventory, Packages: []SourcePackageProof{rootPackage, dep}, ExternalPackages: []SourcePackageProof{embed}, SourceModules: []ModuleSourceSnapshot{stdlib}},
		Packages: []PackageProof{rootPackage.Package}, Headers: []GeneratedHeaderProof{{PackagePath: input.Module, ImportMap: rootPackage.ImportMap,
			Imports: []ImportExport{{ImportPath: dep.Package.PackagePath, PackagePath: dep.Package.PackagePath, ModulePath: input.Module, SourceModule: input.Module, SourceRole: "main", GoSHA256: dep.Package.SourceSHA256, ExportSHA256: strings.Repeat("b", 64)}}}},
	}
	if err := ValidateOrdinaryDependencies(input, metadata, nil); err != nil {
		t.Fatal(err)
	}
	return input, metadata, root
}

func TestOrdinaryDependencyCompleteClosureRejectsMutation(t *testing.T) {
	input, proof, _ := ordinarySourceClosureFixture(t)
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*MetadataProof){
		"missing role":            func(p *MetadataProof) { p.Dependencies = nil },
		"test role":               func(p *MetadataProof) { p.Dependencies.Protocol = TestDependencyProtocol },
		"missing empty selection": func(p *MetadataProof) { p.Dependencies.Packages[0].Embed = nil },
		"missing selected asset":  func(p *MetadataProof) { p.Dependencies.Packages[1].Embed.Files = map[string]string{} },
		"extra selected asset": func(p *MetadataProof) {
			p.Dependencies.Packages[1].Embed.Files["root.go"] = p.Dependencies.Candidate.Sources["root.go"]
		},
		"missing original pattern":   func(p *MetadataProof) { p.Dependencies.Packages[1].Embed.Patterns = nil },
		"test variant":               func(p *MetadataProof) { p.Dependencies.Packages[1].VariantID += " [test]" },
		"foreign dependency removed": func(p *MetadataProof) { p.Dependencies.ExternalPackages = nil },
		"foreign inventory removed":  func(p *MetadataProof) { p.Dependencies.SourceModules = nil },
		"transitive edge removed":    func(p *MetadataProof) { p.Dependencies.Packages[1].ImportMap = map[string]string{} },
		"transitive edge changed":    func(p *MetadataProof) { p.Dependencies.Packages[1].ImportMap["embed"] = "missing" },
		"new generated source": func(p *MetadataProof) {
			p.Dependencies.Packages[1].Package.CompiledGoFiles = []string{"dep/generated.go"}
		},
		"candidate directory omitted": func(p *MetadataProof) { delete(p.Dependencies.Candidate.Directories, "dep") },
		"candidate bytes changed":     func(p *MetadataProof) { p.Dependencies.Candidate.Sources["dep/asset.bin"] = strings.Repeat("f", 64) },
		"unbound export":              func(p *MetadataProof) { p.Dependencies.ExternalPackages[0].ExportSHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed MetadataProof
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := ValidateOrdinaryDependencies(input, &changed, nil); err == nil {
				t.Fatal("changed ordinary source/selection/role accepted")
			}
		})
	}
}

func TestOrdinarySourceInventoryLiveGuards(t *testing.T) {
	for _, axis := range []string{"bytes", "new file", "missing file", "symlink", "header", "cancelled"} {
		t.Run(axis, func(t *testing.T) {
			_, proof, root := ordinarySourceClosureFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			asset := filepath.Join(root, "dep", "asset.bin")
			switch axis {
			case "bytes":
				if err := os.WriteFile(asset, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "new file":
				if err := os.WriteFile(filepath.Join(root, "dep", "new.bin"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "missing file":
				if err := os.Remove(asset); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Remove(asset); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(root, "root.go"), asset); err != nil {
					t.Fatal(err)
				}
			case "header":
				proof.Dependencies.Candidate.Headers["root.go"] = "package fake\n"
			case "cancelled":
				cancel()
			}
			if err := VerifySourceInventory(ctx, proof.Dependencies.Candidate, root); err == nil {
				t.Fatal("changed original source inventory accepted")
			}
		})
	}
}

func TestSourceInventoryCaptureRejectsIncompleteAndOversizedProjection(t *testing.T) {
	_, _, root := ordinarySourceClosureFixture(t)
	for _, inventory := range []SourceInventory{
		{Sources: map[string]string{}},
		{Headers: map[string]string{}},
		{Directories: map[string][]TestSourceEntry{}},
		{Sources: map[string]string{}, Headers: map[string]string{}, Directories: map[string][]TestSourceEntry{"unrelated": make([]TestSourceEntry, 65536)}},
	} {
		if err := CaptureSourceDirectory(context.Background(), &inventory, root, root, false); err == nil {
			t.Fatal("incomplete/unbounded source projection was silently initialized or expanded")
		}
	}
}
