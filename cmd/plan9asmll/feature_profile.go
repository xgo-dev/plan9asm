package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

const featureInputProtocol = gotoolprofile.ConsumerProtocol

type featureInput = gotoolprofile.ConsumerInput

// A consumer is populated only after reobserving the actual driver and its
// finite marker package. Supplying JSON alone does not create this proof.
type featureConsumer struct {
	OrdinaryDependencies      *ordinaryDependencyOwner
	ID                        string
	Observed                  *gotoolprofile.Observation
	Root                      string
	Env                       []string
	Context                   context.Context
	Input                     *featureInput
	Dir                       string
	WorkDir                   string
	Proof                     *featureSelectionProof
	GeneratedGuard            map[string]string
	TestDeclarationPackages   map[string]*packages.Package
	TestDeclarationCandidates map[string]map[string]error
	TestModuleGuards          map[string]testDependencyModuleGuard
	TestEmbedGuards           map[string]testDependencyEmbedGuard
}

type featureSelectionProof = gotoolprofile.SelectionProof
type featurePackageProof = gotoolprofile.PackageProof
type featureCPPProof = gotoolprofile.CPPProof
type featureOutputProof = gotoolprofile.OutputProof

func loadFeatureConsumer(ctx context.Context, filename, output, target, module string, tags []string) (*featureConsumer, error) {
	if ctx == nil {
		return nil, fmt.Errorf("explicit feature consumer requires a live deadline context")
	}
	reader, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	input, err := gotoolprofile.DecodeConsumerInput(reader)
	if err != nil {
		return nil, err
	}
	if input.Protocol != featureInputProtocol || module == "" || input.Module != module || input.Observed == nil || input.Observed.Target != target || gotoolprofile.ProfileID(input.Observed) != input.ID {
		return nil, fmt.Errorf("explicit feature input identity differs from target/module")
	}
	if err := gotoolprofile.Validate(input.Observed); err != nil {
		return nil, err
	}
	for _, tag := range tags {
		if gotoolprofile.ReservedTag(tag) {
			return nil, fmt.Errorf("custom build tag cannot enable the Go feature namespace: %s", tag)
		}
	}
	if !sort.StringsAreSorted(tags) {
		return nil, fmt.Errorf("custom profile tags must have canonical ordering")
	}
	for index := 1; index < len(tags); index++ {
		if tags[index] == tags[index-1] {
			return nil, fmt.Errorf("duplicate custom profile tag")
		}
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	workDir, err := sourcepath.Resolve(dir)
	if err != nil {
		return nil, err
	}
	if !filepath.IsAbs(input.SourceRoot) {
		return nil, fmt.Errorf("feature consumer requires an explicit absolute source root")
	}
	dir, err = sourcepath.Resolve(input.SourceRoot)
	if err != nil {
		return nil, err
	}
	consumer := &featureConsumer{
		ID: input.ID, Observed: input.Observed, Context: ctx,
		Input: input, Dir: dir, WorkDir: workDir,
		Proof: &featureSelectionProof{
			Protocol: featureInputProtocol, ProfileID: input.ID,
			SignatureSourceProtocol:      input.SignatureSourceProtocol,
			TestDependencySourceProtocol: input.TestDependencySourceProtocol,
			CPPSourceProtocol:            input.CPPSourceProtocol,
			CustomTags:                   append([]string(nil), tags...),
			RegisteredAsmFiles:           append([]string(nil), input.RegisteredAsmFiles...),
			CPPIncludeSearchMisses:       append([]gotoolprofile.CPPPackageSearchMiss(nil), input.CPPIncludeSearchMisses...),
		},
	}
	if err := consumer.verifySources(); err != nil {
		return nil, err
	}
	env := featureEnvironment(os.Environ(), input.Observed.Environment)
	// Resolve actual cache/config/temp paths before both reobservation and
	// package selection. Source observers retain this same environment and
	// own their separate temporary children until their existing Close calls.
	goos, goarch, _ := strings.Cut(target, "/")
	env, err = featurePackageEnvironment(goos, goarch, env)
	if err != nil {
		return nil, err
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return nil, err
	}
	consumer.Env = env
	if err := os.MkdirAll(output, 0755); err != nil {
		return nil, err
	}
	if err := consumer.reobserve(binary, output); err != nil {
		return nil, err
	}
	data, _, err := gotoolprofile.RunBounded(ctx, dir, env, binary, "env", "GOROOT")
	if err != nil {
		return nil, err
	}
	consumer.Root = strings.TrimSpace(string(data))
	if !filepath.IsAbs(consumer.Root) {
		return nil, fmt.Errorf("actual feature driver returned an invalid source root")
	}
	if err := consumer.verifySources(); err != nil {
		return nil, err
	}
	return consumer, nil
}

func featureEnvironment(base []string, actual map[string]string) []string {
	replacements := map[string]string{
		"GOTOOLCHAIN": "local", "GOWORK": "off", "GOFLAGS": "", "GOPACKAGESDRIVER": "off",
	}
	for key, value := range actual {
		if key != "GOVERSION" {
			replacements[key] = value
		}
	}
	var result []string
	for _, item := range base {
		key, _, _ := strings.Cut(item, "=")
		if _, replace := replacements[key]; !replace {
			result = append(result, item)
		}
	}
	for key, value := range replacements {
		result = append(result, key+"="+value)
	}
	sort.Strings(result)
	return result
}

func (consumer *featureConsumer) reobserve(binary, output string) error {
	marker, err := os.MkdirTemp(output, ".feature-markers-")
	if err != nil {
		return err
	}
	// Retain the finite marker artifact with the output proof. It is not a
	// dependency cache and no caller-owned directory is removed here.
	observed, err := gotoolprofile.Capture(consumer.Context, binary, marker, consumer.Env, consumer.Observed.Target, nil, gotoolprofile.RunBounded)
	if err != nil {
		return fmt.Errorf("reobserve actual feature driver: %w", err)
	}
	if gotoolprofile.ProfileID(observed) != consumer.ID {
		return fmt.Errorf("actual marker/environment/source/tool identity differs from the requested feature profile")
	}
	return consumer.verifySources()
}

func (consumer *featureConsumer) verifySources() error {
	if consumer.Context != nil && consumer.Context.Err() != nil {
		return consumer.Context.Err()
	}
	if consumer.Input == nil || len(consumer.Input.Directories) == 0 {
		return fmt.Errorf("feature consumer requires exact pre-load module source hashes")
	}
	if proof := consumer.Input.ProxyGoMod; proof != nil {
		if err := gotoolprofile.ValidateProxyGoMod(proof); err != nil {
			return err
		}
		if consumer.Input.Sources["go.mod"] != "" || consumer.Input.Module != proof.Module ||
			consumer.Input.SourceModule != proof.Module || consumer.Input.Version != proof.Version ||
			!filepath.IsAbs(consumer.Input.ProxyGoModPath) {
			return fmt.Errorf("proxy metadata differs from its exact non-ZIP module role")
		}
		if _, err := os.Stat(filepath.Join(consumer.Dir, "go.mod")); !os.IsNotExist(err) {
			return fmt.Errorf("proxy metadata cannot impersonate original ZIP go.mod")
		}
		resolved, err := sourcepath.Resolve(consumer.Input.ProxyGoModPath)
		if err != nil || resolved != consumer.Input.ProxyGoModPath {
			return fmt.Errorf("authenticated proxy metadata is missing or redirected")
		}
		actual, err := gotoolprofile.FileSHA256(resolved)
		if err != nil || actual != proof.SHA256 {
			return fmt.Errorf("authenticated proxy metadata changed before or after package loading")
		}
	} else if consumer.Input.Sources["go.mod"] == "" || consumer.Input.ProxyGoModPath != "" {
		return fmt.Errorf("feature consumer requires exact ZIP go.mod or independently authenticated proxy metadata")
	}
	for dir, expected := range consumer.Input.Directories {
		if filepath.IsAbs(dir) || filepath.ToSlash(filepath.Clean(dir)) != dir || strings.HasPrefix(dir, "../") || strings.Contains(dir, "\\") {
			return fmt.Errorf("unsafe feature source directory %q", dir)
		}
		entries, err := os.ReadDir(filepath.Join(consumer.Dir, filepath.FromSlash(dir)))
		if err != nil {
			return err
		}
		var actual []string
		for _, entry := range entries {
			actual = append(actual, entry.Name())
		}
		if !reflect.DeepEqual(actual, expected) {
			return fmt.Errorf("feature source directory membership changed: %s", dir)
		}
	}
	for file, expected := range consumer.Input.Sources {
		if consumer.Context != nil && consumer.Context.Err() != nil {
			return consumer.Context.Err()
		}
		if filepath.IsAbs(file) || filepath.ToSlash(filepath.Clean(file)) != file || file == "." || strings.HasPrefix(file, "../") || strings.Contains(file, "\\") {
			return fmt.Errorf("unsafe feature source identity %q", file)
		}
		filename := filepath.Join(consumer.Dir, filepath.FromSlash(file))
		resolved, err := sourcepath.Resolve(filename)
		if err != nil || resolved != filename {
			return fmt.Errorf("feature source cannot be a redirected path: %s", file)
		}
		actual, err := gotoolprofile.FileSHA256(filename)
		if err != nil || actual != expected {
			return fmt.Errorf("feature source differs from its pre-load proof: %s", file)
		}
	}
	if consumer.Root != "" {
		if err := gotoolprofile.ValidateCPPIncludeSearch(consumer.Input, nil); err != nil {
			return err
		}
		for _, miss := range consumer.Input.CPPIncludeSearchMisses {
			if err := gotoolprofile.VerifyCPPPackageSearchMiss(miss, consumer.Dir, consumer.Root); err != nil {
				return err
			}
		}
		for file, expected := range consumer.Input.ToolSources {
			name, err := gotoolprofile.CPPRegularSource(consumer.Root, file)
			if err != nil {
				return err
			}
			actual, err := gotoolprofile.FileSHA256(name)
			if err != nil || actual != expected {
				return fmt.Errorf("feature tool header differs from its pre-load proof: %s", file)
			}
		}
	}
	for file, expected := range consumer.GeneratedGuard {
		if consumer.Context != nil && consumer.Context.Err() != nil {
			return consumer.Context.Err()
		}
		actual, err := gotoolprofile.FileSHA256(file)
		if err != nil || actual != expected {
			return fmt.Errorf("generated-header dependency/export changed before final object proof")
		}
	}
	if err := consumer.verifyOrdinaryOwner(consumer.OrdinaryDependencies); err != nil {
		return err
	}
	return consumer.verifyTestModuleSources()
}

func (consumer *featureConsumer) capturePackages(pkgs []*packages.Package) error {
	if err := consumer.verifySources(); err != nil {
		return err
	}
	if len(pkgs) == 0 {
		return fmt.Errorf("feature consumer has no actual package observation")
	}
	for _, pkg := range pkgs {
		proof, err := consumer.captureSourcePackage(pkg, func(packagePath string) (*gotoolprofile.AssemblerMacros, error) {
			return gotoolprofile.CaptureAssemblerMacros(consumer.Root, consumer.Observed, packagePath)
		})
		if err != nil {
			return err
		}
		consumer.Proof.Packages = append(consumer.Proof.Packages, proof)
	}
	if consumer.Input.RegisteredAsmFiles != nil {
		if err := gotoolprofile.ValidatePackageSelection(consumer.Input, consumer.Proof.Packages, consumer.Proof.CustomTags); err != nil {
			return fmt.Errorf("actual complete package assembly registration: %w", err)
		}
	}
	return consumer.verifySources()
}

// Source capture shares exact native Module/Dir/Replace and original byte
// boundaries, never profile identity. Callers provide their separately
// validated assembler registration; no result becomes an ordinary proof here.
func (consumer *featureConsumer) captureSourcePackage(pkg *packages.Package, captureMacros func(string) (*gotoolprofile.AssemblerMacros, error)) (featurePackageProof, error) {
	var proof featurePackageProof
	if pkg == nil || pkg.Module == nil || pkg.Module.Path != consumer.Input.Module || pkg.Module.Version != consumer.Input.Version || isTestVariantPackage(pkg) || captureMacros == nil {
		return proof, fmt.Errorf("actual package role/module differs from the explicit source scope")
	}
	moduleDir, err := sourcepath.Resolve(pkg.Module.Dir)
	if err != nil || moduleDir != consumer.Dir {
		return proof, fmt.Errorf("actual package module directory differs from the explicit source proof")
	}
	if pkg.Module.Replace != nil {
		replacement, err := sourcepath.Resolve(pkg.Module.Replace.Dir)
		if err != nil || replacement != consumer.Dir {
			return proof, fmt.Errorf("actual Go module replacement differs from the exact owned source root")
		}
	}
	macros, err := captureMacros(pkg.PkgPath)
	if err != nil {
		return proof, err
	}
	if macros == nil || macros.PackageRole == "allow_asm_abi_path" {
		return proof, fmt.Errorf("source consumer cannot consume an unproved special assembler package role")
	}
	proof = featurePackageProof{
		PackagePath: pkg.PkgPath, ModulePath: pkg.Module.Path, ModuleVersion: pkg.Module.Version,
		SourceModule: pkg.Module.Path, SourceVersion: pkg.Module.Version, SourceRole: "module",
		Macros: macros, SourceSHA256: make(map[string]string),
	}
	if metadata := consumer.Input.ProxyGoMod; metadata != nil {
		used := pkg.Module.GoMod
		if pkg.Module.Replace != nil {
			used = pkg.Module.Replace.GoMod
		}
		resolved, err := sourcepath.Resolve(used)
		if err != nil || resolved != consumer.Input.ProxyGoModPath {
			return proof, fmt.Errorf("actual package used different proxy go.mod metadata")
		}
		proof.GoModOrigin, proof.GoModSHA256, proof.GoModSum = metadata.Protocol, metadata.SHA256, metadata.GoModSum
	}
	if pkg.Module.Main {
		proof.SourceRole = "main"
	}
	if replacement := pkg.Module.Replace; replacement != nil {
		proof.SourceRole = "owned_local_replace"
		if replacement.Version != "" {
			proof.SourceModule, proof.SourceVersion = replacement.Path, replacement.Version
			proof.SourceRole = "version_replace"
		}
	}
	if err := gotoolprofile.ValidatePackageModule(consumer.Input, proof); err != nil {
		return proof, err
	}
	capture := func(files []string, assemblyOnly bool) ([]string, error) {
		var names []string
		for _, filename := range files {
			if assemblyOnly && filepath.Ext(filename) != ".s" {
				continue
			}
			name, err := consumer.sourceName(filename)
			if err != nil {
				return nil, err
			}
			proof.SourceSHA256[name] = consumer.Input.Sources[name]
			names = append(names, name)
		}
		sort.Strings(names)
		return names, nil
	}
	if proof.GoFiles, err = capture(pkg.GoFiles, false); err != nil {
		return proof, err
	}
	if proof.CompiledGoFiles, err = capture(pkg.CompiledGoFiles, false); err != nil {
		return proof, err
	}
	if proof.SFiles, err = capture(pkg.OtherFiles, true); err != nil {
		return proof, err
	}
	if len(proof.GoFiles) == 0 || len(proof.CompiledGoFiles) == 0 {
		return proof, fmt.Errorf("source consumer requires actual non-test Go selection")
	}
	return proof, nil
}

func (consumer *featureConsumer) sourceName(filename string) (string, error) {
	name, err := consumer.moduleSourceName(filename)
	if err != nil {
		return "", err
	}
	if _, present := consumer.Input.Directories[filepath.ToSlash(filepath.Dir(name))]; !present {
		return "", fmt.Errorf("actual selected source lacks complete directory membership proof: %s", name)
	}
	return name, nil
}

// CPP resources have exact registered byte/origin proofs, but a shared header
// directory need not be a selected Go package or its ancestor. Go package
// capture still uses sourceName and retains its separate membership check.
func (consumer *featureConsumer) moduleSourceName(filename string) (string, error) {
	filename, err := sourcepath.Resolve(filename)
	if err != nil {
		return "", err
	}
	name, err := filepath.Rel(consumer.Dir, filename)
	name = filepath.ToSlash(name)
	if err != nil || strings.HasPrefix(name, "../") || consumer.Input.Sources[name] == "" {
		return "", fmt.Errorf("actual selected source has no pre-load proof: %s", filename)
	}
	return name, nil
}

func (consumer *featureConsumer) packageMacros(pkg *packages.Package) (*gotoolprofile.AssemblerMacros, error) {
	actual, err := gotoolprofile.CaptureAssemblerMacros(consumer.Root, consumer.Observed, pkg.PkgPath)
	if err != nil {
		return nil, err
	}
	if consumer.Proof != nil {
		for _, proof := range consumer.Proof.Packages {
			if proof.PackagePath == pkg.PkgPath {
				if !reflect.DeepEqual(actual, proof.Macros) {
					return nil, fmt.Errorf("actual assembler registration changed during consumption")
				}
				return actual, nil
			}
		}
		return nil, fmt.Errorf("package has no same-load feature selection proof")
	}
	return actual, nil // focused unit fixture, never the CLI proof path
}

var featureIncludeRE = regexp.MustCompile(`^#include[ \t]+"([^"\r\n]+)"[ \t]*(?://.*)?$`)

// The legacy reader resolves nested local includes relative to the including
// header. Actual Go searches from the original assembly package directory.
// Until that reader supports the exact policy, reject any differing binding.
func (consumer *featureConsumer) captureCPPInputs(asm string) (map[string]string, error) {
	inputs := make(map[string]string)
	packageDir := filepath.Dir(asm)
	active := make(map[string]bool)
	var visit func(string, int) error
	visit = func(file string, depth int) error {
		if consumer.Context != nil && consumer.Context.Err() != nil {
			return consumer.Context.Err()
		}
		if depth > 32 || len(inputs) >= 512 || active[file] {
			return fmt.Errorf("feature CPP input nesting/cycle exceeds its explicit bound")
		}
		active[file] = true
		defer delete(active, file)
		reader, err := os.Open(file)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, 64<<20+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || len(data) > 64<<20 {
			return fmt.Errorf("read bounded actual feature CPP source: %s: %v (close: %v)", file, readErr, closeErr)
		}
		id, err := consumer.moduleSourceName(file)
		var expected string
		if err == nil {
			expected = consumer.Input.Sources[id]
			id = "module/" + id
		} else {
			name, relErr := filepath.Rel(consumer.Root, file)
			name = filepath.ToSlash(name)
			if relErr != nil || consumer.Input.ToolSources[name] == "" {
				return fmt.Errorf("CPP source lacks exact module/tool input proof: %s", file)
			}
			id = "tool/" + name
			expected = consumer.Input.ToolSources[name]
		}
		actual := featureBytesSHA256(data)
		if actual != expected {
			return fmt.Errorf("consumed CPP bytes differ from exact pre-load source: %s", id)
		}
		inputs[id] = actual
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "#include") {
				continue
			}
			match := featureIncludeRE.FindStringSubmatch(line)
			if match == nil || filepath.IsAbs(match[1]) || strings.Contains(match[1], "\\") {
				return fmt.Errorf("feature CPP include needs exact literal binding: %s", line)
			}
			preferred := filepath.Clean(filepath.Join(packageDir, filepath.FromSlash(match[1])))
			actual := preferred
			if _, err := os.Stat(actual); os.IsNotExist(err) {
				actual = filepath.Clean(filepath.Join(consumer.Root, "pkg", "include", filepath.FromSlash(match[1])))
			}
			legacy := filepath.Clean(filepath.Join(filepath.Dir(file), filepath.FromSlash(match[1])))
			if _, err := os.Stat(legacy); os.IsNotExist(err) {
				legacy = filepath.Clean(filepath.Join(consumer.Root, "pkg", "include", filepath.FromSlash(match[1])))
			}
			if actual != legacy {
				return fmt.Errorf("CPP include binding differs between actual Go and the translator: %s", match[1])
			}
			if err := visit(actual, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if err := visit(asm, 0); err != nil {
		return nil, err
	}
	return inputs, consumer.verifySources()
}
