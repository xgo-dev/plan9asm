package gotoolprofile

import (
	"strings"
	"testing"
)

func testDependencyAssemblyScopeFixture() (*ConsumerInput, *TestDependencyProof) {
	const module = "example.invalid/scope"
	const file = "helper/asm.s"
	source := TestSourcePackage{
		Package: PackageProof{
			PackagePath: module + "/helper", ModulePath: module, ModuleVersion: "v1.0.0",
			SourceModule: module, SourceVersion: "v1.0.0", SourceRole: "module",
			GoFiles: []string{"helper/helper.go"}, CompiledGoFiles: []string{"helper/helper.go"}, SFiles: []string{file},
			SourceSHA256: map[string]string{
				"helper/helper.go": bytesSHA256([]byte("package helper\n")), file: bytesSHA256(nil),
			},
		},
		VariantID: module + "/helper", ImportMap: map[string]string{},
	}
	input := &ConsumerInput{
		ID:     strings.Repeat("a", 64),
		Module: module, Version: "v1.0.0", SourceModule: module,
		Observed: &Observation{
			GoVersion: "go1.27.1", Target: "darwin/amd64",
			Environment: map[string]string{"GOOS": "darwin", "GOARCH": "amd64"},
		},
		Sources: map[string]string{
			"helper/helper.go": source.Package.SourceSHA256["helper/helper.go"], file: source.Package.SourceSHA256[file],
		},
		Headers:             map[string]string{"helper/helper.go": "package helper\n", file: ""},
		Directories:         map[string][]string{"helper": {"asm.s", "helper.go"}},
		OrdinaryAsmPackages: []string{"registered"},
	}
	rootFiles := map[string]string{
		"root.go":       "package scope\n",
		"root_test.go":  "package scope\nimport \"example.invalid/scope/helper\"\n",
		"probe_amd64.s": "TEXT ·probe(SB),$0-0\nRET\n",
	}
	root := TestSourcePackage{
		Package: PackageProof{
			PackagePath: module, ModulePath: module, ModuleVersion: "v1.0.0",
			SourceModule: module, SourceVersion: "v1.0.0", SourceRole: "module",
			GoFiles: []string{"root.go", "root_test.go"}, CompiledGoFiles: []string{"root.go", "root_test.go"},
			SFiles: []string{"probe_amd64.s"}, SourceSHA256: make(map[string]string),
		},
		VariantID: module + " [" + module + ".test]",
		ImportMap: map[string]string{module + "/helper": module + "/helper"},
	}
	for file, data := range rootFiles {
		input.Sources[file] = bytesSHA256([]byte(data))
		input.Headers[file] = data
		root.Package.SourceSHA256[file] = input.Sources[file]
	}
	input.Headers["probe_amd64.s"] = ""
	input.Directories["."] = []string{"helper", "probe_amd64.s", "root.go", "root_test.go"}
	for _, selected := range []*TestSourcePackage{&root, &source} {
		selected.Embed = &TestEmbedSelection{Protocol: TestEmbedProtocol, Directives: make(map[string]string), Files: make(map[string]string)}
		for _, file := range selected.Package.GoFiles {
			selected.Embed.Directives[file] = ""
		}
	}
	return input, &TestDependencyProof{Packages: []TestSourcePackage{root, source}}
}

func TestTestDependencyAssemblyScopeDiagnosticBindsActualPair(t *testing.T) {
	input, dependency := testDependencyAssemblyScopeFixture()
	input.Sources["helper/asm.s"] = bytesSHA256([]byte("// nonempty\n"))
	dependency.Packages[1].Package.SourceSHA256["helper/asm.s"] = input.Sources["helper/asm.s"]
	err := validateTestSourceClosure(input, dependency, map[string]bool{input.Module: true}, []string{"chosen"})
	if err == nil {
		t.Fatal("unregistered assembly acquired a source-only translation role")
	}
	for _, detail := range []string{
		"package=example.invalid/scope/helper", "module=example.invalid/scope@v1.0.0",
		"source_root=\"\"", "directory=helper", "selected_asm=[\"helper/asm.s\"]",
		"ordinary_asm_packages=[\"registered\"]",
		"target=darwin/amd64", "profile=" + input.ID, "tags=[\"chosen\"]",
	} {
		if !strings.Contains(err.Error(), detail) {
			t.Errorf("actual assembly-scope diagnostic lacks %s: %v", detail, err)
		}
	}
}

func TestTestDependencySourceOnlyZeroAssemblyKeepsActualSelection(t *testing.T) {
	input, dependency := testDependencyAssemblyScopeFixture()
	// An imported ordinary package is not a supplemental test root. Its
	// actual zero-byte SFile must remain selected without claiming an object.
	if err := validateTestSourceClosure(input, dependency, map[string]bool{input.Module: true}, nil); err != nil {
		t.Fatal(err)
	}
	if len(dependency.Packages[1].Package.SFiles) != 1 {
		t.Fatal("source-only empty sibling disappeared from actual Go selection")
	}
}

func TestTestDependencySourceOnlyZeroAssemblyRejectsMissingAndNonzeroEvidence(t *testing.T) {
	const file = "helper/asm.s"
	for name, mutate := range map[string]func(*ConsumerInput, *TestDependencyProof){
		"missing header is not empty": func(i *ConsumerInput, _ *TestDependencyProof) { delete(i.Headers, file) },
		"nonempty header":             func(i *ConsumerInput, _ *TestDependencyProof) { i.Headers[file] = "\n" },
		"missing original member": func(i *ConsumerInput, _ *TestDependencyProof) {
			i.Directories["helper"] = []string{"helper.go"}
		},
		"missing original bytes": func(i *ConsumerInput, _ *TestDependencyProof) { delete(i.Sources, file) },
		"missing actual bytes":   func(_ *ConsumerInput, d *TestDependencyProof) { delete(d.Packages[1].Package.SourceSHA256, file) },
		"paired byte deletion": func(i *ConsumerInput, d *TestDependencyProof) {
			delete(i.Sources, file)
			delete(d.Packages[1].Package.SourceSHA256, file)
		},
		"paired selected role and byte deletion": func(_ *ConsumerInput, d *TestDependencyProof) {
			d.Packages[1].Package.SFiles = nil
			delete(d.Packages[1].Package.SourceSHA256, file)
		},
		"same hash absent original member and header": func(i *ConsumerInput, _ *TestDependencyProof) {
			delete(i.Headers, file)
			i.Directories["helper"] = []string{"helper.go"}
		},
		"unknown same-module role": func(_ *ConsumerInput, d *TestDependencyProof) { d.Packages[1].Package.SourceRole = "stdlib" },
		"different module version": func(_ *ConsumerInput, d *TestDependencyProof) { d.Packages[1].Package.ModuleVersion = "v1.0.1" },
		"different source root":    func(_ *ConsumerInput, d *TestDependencyProof) { d.Packages[1].SourceRootID = "other@v1.0.0" },
		"mixed nonempty sibling": func(i *ConsumerInput, d *TestDependencyProof) {
			other := "helper/nonempty.s"
			i.Sources[other] = bytesSHA256([]byte("// not zero\n"))
			i.Headers[other] = "//\n"
			i.Directories["helper"] = append(i.Directories["helper"], "nonempty.s")
			d.Packages[1].Package.SFiles = append(d.Packages[1].Package.SFiles, other)
			d.Packages[1].Package.SourceSHA256[other] = i.Sources[other]
		},
	} {
		t.Run(name, func(t *testing.T) {
			input, dependency := testDependencyAssemblyScopeFixture()
			mutate(input, dependency)
			if err := validateTestSourceClosure(input, dependency, map[string]bool{input.Module: true}, nil); err == nil {
				t.Fatal("source-only zero-byte role accepted missing or contradictory actual source/selection evidence")
			}
		})
	}
	for _, data := range []string{"\n", "  \n", "// comment\n", "#define VALUE 1\n", "TEXT ·x(SB),$0-0\nRET\n"} {
		t.Run("nonzero "+data, func(t *testing.T) {
			input, dependency := testDependencyAssemblyScopeFixture()
			input.Sources[file] = bytesSHA256([]byte(data))
			dependency.Packages[1].Package.SourceSHA256[file] = input.Sources[file]
			if err := validateTestSourceClosure(input, dependency, map[string]bool{input.Module: true}, nil); err == nil {
				t.Fatal("nonzero source acquired the exact zero-byte source-only role")
			}
		})
	}
}
