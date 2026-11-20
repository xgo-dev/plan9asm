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

func TestGeneratedHeaderMetadataCLIUsesActualImportExports(t *testing.T) {
	for _, target := range []string{"linux/amd64", "linux/386", "linux/arm", "linux/arm64", "js/wasm"} {
		t.Run(target, func(t *testing.T) {
			input, dir := generatedHeaderFixture(t, target)
			parts := strings.Split(target, "/")
			report := filepath.Join(t.TempDir(), "metadata.json")
			args := []string{
				"-goos=" + parts[0], "-goarch=" + parts[1], "-patterns=.",
				"-module-path=" + input.Module, "-asm-files=" + input.AsmFiles[0],
				"-feature-profile=" + writeFeatureInput(t, input), "-feature-timeout=2m",
				"-metadata-only", "-out=" + t.TempDir(), "-report=" + report,
			}
			encoded, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded))
			stdout, stderr, err := gotoolprofile.RunBounded(ctx, dir, env, os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
			if err != nil {
				t.Fatalf("actual metadata-only CLI: %v\n%s\n%s", err, stdout, stderr)
			}
			data, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]json.RawMessage
			if err := json.Unmarshal(data, &result); err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"success", "total_asm", "outputs", "targets", "feature_selection"} {
				if _, present := result[forbidden]; present {
					t.Fatalf("metadata was reported as translation evidence: %s", data)
				}
			}
			if len(result["headers"]) == 0 || len(result["packages"]) == 0 {
				t.Fatalf("metadata lacks actual header and package selection: %s", data)
			}
			var proof gotoolprofile.MetadataProof
			if err := json.Unmarshal(data, &proof); err != nil {
				t.Fatal(err)
			}
			if err := gotoolprofile.ValidateMetadata(input, &proof, nil); err != nil {
				t.Fatal(err)
			}
			if len(proof.Headers) != 1 || len(proof.Headers[0].Imports) != 1 || proof.Headers[0].Imports[0].ImportPath != input.Module+"/dep" {
				t.Fatalf("actual compiler did not bind the imported package export: %s", data)
			}
			header := proof.Headers[0]
			size, last := "56", "48"
			if parts[1] == "386" || parts[1] == "arm" {
				size, last = "28", "24"
			}
			if header.Definitions["const_Imported"] != "41" || header.Definitions["Layout__size"] != size || header.Definitions["Alias_Last"] != last || header.Definitions["const_Fraction"] != "" {
				t.Fatalf("actual full definitions have the wrong import/target/presence semantics: %v", header.Definitions)
			}
			var translation gotoolprofile.SelectionProof
			if err := json.Unmarshal(data, &translation); err != nil {
				t.Fatal(err)
			}
			if err := gotoolprofile.ValidateSelection(input, &translation, nil, true); err == nil {
				t.Fatal("metadata-only output was accepted as an assembly translation PASS")
			}
			checkGeneratedHeaderMutations(t, input, data)
		})
	}
}

func TestGeneratedHeaderMetadataRejectsDependencyMutationDuringActualLoad(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	dep := ordinaryFixtureDependency(t, input, "example.invalid/external", map[string]string{
		"layout.go": "package external\ntype Mixed struct { Word uintptr }\nfunc Body() int { return 1 }\n",
	})
	goFile := filepath.Join(dep, "layout.go")
	for name, source := range map[string]string{
		"layout.go": "package header\nimport \"example.invalid/external\"\ntype Layout struct { Value external.Mixed }\nfunc Probe()\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name], input.Headers[name] = featureBytesSHA256([]byte(source)), source
	}
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer, err := loadFeatureConsumer(ctx, writeFeatureInput(t, input), t.TempDir(), "linux/amd64", input.Module, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = loadGeneratedHeaderPackagesWithLoader(consumer, []string{"."}, nil, func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
		if config.Mode&packages.NeedExportFile != 0 {
			// Mutate only this test's external dependency, after source
			// selection but before actual Go exports/type checking. Root
			// pre-load hashes cannot cover a different dependency module.
			if err := os.Chmod(goFile, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(goFile, []byte("package external\ntype Mixed struct { Word uintptr }\nfunc Body() int { return 2 }\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		return packages.Load(config, patterns...)
	})
	if err == nil || !strings.Contains(err.Error(), "dependency/source selection changed") {
		t.Fatalf("metadata accepted a dependency changed during actual load: %v", err)
	}
}

func checkGeneratedHeaderMutations(t *testing.T, input *featureInput, canonical []byte) {
	t.Helper()
	for name, mutate := range map[string]func(*gotoolprofile.MetadataProof){
		"old selection protocol": func(p *gotoolprofile.MetadataProof) { p.Protocol = gotoolprofile.ConsumerProtocol },
		"missing full header":    func(p *gotoolprofile.MetadataProof) { p.Headers = nil },
		"target":                 func(p *gotoolprofile.MetadataProof) { p.Headers[0].Target = "linux/mips" },
		"profile":                func(p *gotoolprofile.MetadataProof) { p.Headers[0].ProfileID = strings.Repeat("0", 64) },
		"version":                func(p *gotoolprofile.MetadataProof) { p.Headers[0].GoVersion = "go1.26.1" },
		"language version":       func(p *gotoolprofile.MetadataProof) { p.Headers[0].LanguageVersion = "go1.28" },
		"compiler":               func(p *gotoolprofile.MetadataProof) { p.Headers[0].CompileToolSHA256 = strings.Repeat("0", 64) },
		"missing object":         func(p *gotoolprofile.MetadataProof) { p.Headers[0].ObjectSHA256 = "" },
		"missing header":         func(p *gotoolprofile.MetadataProof) { p.Headers[0].HeaderSHA256 = "" },
		"definition value":       func(p *gotoolprofile.MetadataProof) { p.Headers[0].Definitions["const_Imported"] = "42" },
		"definition presence":    func(p *gotoolprofile.MetadataProof) { p.Headers[0].Definitions["const_Fraction"] = "1.25" },
		"definition omission":    func(p *gotoolprofile.MetadataProof) { delete(p.Headers[0].Definitions, "Layout__size") },
		"selected source": func(p *gotoolprofile.MetadataProof) {
			p.Headers[0].CompiledGoSHA256["layout.go"] = strings.Repeat("0", 64)
		},
		"package role":          func(p *gotoolprofile.MetadataProof) { p.Packages[0].SourceRole = "module" },
		"module":                func(p *gotoolprofile.MetadataProof) { p.Packages[0].ModulePath += "/other" },
		"module version":        func(p *gotoolprofile.MetadataProof) { p.Packages[0].ModuleVersion = "v1.2.3" },
		"omitted import export": func(p *gotoolprofile.MetadataProof) { p.Headers[0].Imports[0].ExportSHA256 = "" },
		"omitted exports":       func(p *gotoolprofile.MetadataProof) { p.Headers[0].Imports = nil },
		"omitted ImportMap":     func(p *gotoolprofile.MetadataProof) { p.Headers[0].ImportMap = nil },
		"different ImportMap":   func(p *gotoolprofile.MetadataProof) { p.Headers[0].ImportMap[input.Module+"/dep"] += "/other" },
		"import source role":    func(p *gotoolprofile.MetadataProof) { p.Headers[0].Imports[0].SourceRole = "stdlib" },
		"import source bytes": func(p *gotoolprofile.MetadataProof) {
			p.Headers[0].Imports[0].GoSHA256["dep/layout.go"] = strings.Repeat("0", 64)
		},
		"duplicate export": func(p *gotoolprofile.MetadataProof) {
			p.Headers[0].Imports = append(p.Headers[0].Imports, p.Headers[0].Imports[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.MetadataProof
			if err := json.Unmarshal(canonical, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := gotoolprofile.ValidateMetadata(input, &changed, nil); err == nil {
				t.Fatal("changed generated-header/source/tool scope was accepted")
			}
		})
	}
}

func TestGeneratedHeaderMetadataWithActualStandardLibraryImport(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	source := []byte("package header\nimport \"time\"\nconst StdSeconds = time.Second\ntype StdLayout struct { First byte; Value time.Time }\nfunc Probe()\n")
	if err := os.WriteFile(filepath.Join(dir, "layout.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["layout.go"], input.Headers["layout.go"] = featureBytesSHA256(source), string(source)
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	proof, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	header := proof.Headers[0]
	if header.ImportMap["time"] != "time" || len(header.Imports) != 1 || header.Imports[0].SourceRole != "stdlib" || header.Definitions["const_StdSeconds"] != "1000000000" || header.Definitions["StdLayout__size"] != "32" {
		t.Fatalf("actual stdlib export/source/typed layout did not bind: %#v", header)
	}
}

func TestGeneratedHeaderMetadataPreservesActualGoSourceDiagnostics(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	file := filepath.Join(dir, "layout.go")
	source, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	source = append(source, []byte("var Broken = missingActualGoName\n")...)
	if err := os.WriteFile(file, source, 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["layout.go"] = featureBytesSHA256(source)
	input.Headers["layout.go"] = string(source)
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	_, err = queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err == nil || !strings.Contains(err.Error(), "layout.go:") || !strings.Contains(err.Error(), "undefined: missingActualGoName") {
		t.Fatalf("actual Go source rejection lost its concrete location/diagnostic: %v", err)
	}
}

func TestGeneratedHeaderMetadataEmptyDefinitionsRoundtrip(t *testing.T) {
	input, dir := generatedHeaderFixture(t, "linux/amd64")
	source := []byte("package header\nfunc Probe()\n")
	if err := os.WriteFile(filepath.Join(dir, "layout.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	input.Sources["layout.go"], input.Headers["layout.go"] = featureBytesSHA256(source), string(source)
	t.Chdir(dir)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	proof, err := queryGeneratedHeaders(targetSpec{Goos: "linux", Goarch: "amd64"}, []string{"."}, nil, input.AsmFiles, input.Module, t.TempDir(), compileConfig{FeaturePath: writeFeatureInput(t, input), Context: ctx})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	var replay gotoolprofile.MetadataProof
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if len(replay.Headers[0].Definitions) != 0 || replay.Headers[0].Definitions == nil || replay.Headers[0].ImportMap == nil {
		t.Fatalf("actual empty complete definition inventory was lost: %s", data)
	}
	if err := gotoolprofile.ValidateMetadata(input, &replay, nil); err != nil {
		t.Fatal(err)
	}
	replay.Headers[0].Definitions = nil
	if err := gotoolprofile.ValidateMetadata(input, &replay, nil); err == nil {
		t.Fatal("missing header inventory was accepted as an actual empty inventory")
	}
}

func TestGeneratedHeaderMetadataCLIRejectsTranslationModes(t *testing.T) {
	for _, mode := range []string{"missing-profile", "missing-report", "compile", "list-only", "all-targets", "limit=1"} {
		t.Run(mode, func(t *testing.T) {
			args := []string{"-metadata-only", "-feature-profile=must-not-be-read", "-report=" + filepath.Join(t.TempDir(), "metadata.json")}
			switch mode {
			case "missing-profile":
				args = []string{"-metadata-only"}
			case "missing-report":
				args = args[:2]
			default:
				args = append(args, "-"+mode)
			}
			data, err := json.Marshal(args)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			_, stderr, err := gotoolprofile.RunBounded(ctx, t.TempDir(), append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(data)), os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
			if err == nil || !strings.Contains(string(stderr), "metadata-only requires one explicit ordinary profile") {
				t.Fatalf("metadata mixed with translation/list/matrix behavior: %v\n%s", err, stderr)
			}
		})
	}
}

func generatedHeaderFixture(t *testing.T, target string) (*featureInput, string) {
	t.Helper()
	dir := t.TempDir()
	arch := strings.Split(target, "/")[1]
	files := map[string]string{
		"go.mod": "module example.invalid/header\n\ngo 1.24\n",
		"layout.go": `package header
import "example.invalid/header/dep"
const Imported = dep.Value + 1
const Huge = 1234567890123456789012345678901234567890
const Quoted = "header\nvalue"
const Fraction = 1.25
type Layout struct { First byte; External dep.Mixed; Last uintptr }
type Alias = Layout
func Probe()
`,
		"dep/layout.go":        "package dep\nconst Value = 40\ntype Mixed struct { Small byte; Word uintptr; Bytes []byte }\n",
		"probe_" + arch + ".s": "#include \"go_asm.h\"\nTEXT ·Probe(SB),$0-0\nRET\n",
	}
	input := &featureInput{
		Protocol: featureInputProtocol, Module: "example.invalid/header", SourceRoot: dir,
		Sources: make(map[string]string), Headers: make(map[string]string),
		Directories: map[string][]string{".": {"dep", "go.mod", "layout.go", "probe_" + arch + ".s"}, "dep": {"layout.go"}},
		AsmFiles:    []string{"probe_" + arch + ".s"},
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
	for _, names := range input.Directories {
		sort.Strings(names)
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	input.Observed, err = gotoolprofile.Capture(ctx, binary, t.TempDir(), os.Environ(), target, nil, gotoolprofile.RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input.ID = gotoolprofile.ProfileID(input.Observed)
	return input, dir
}
