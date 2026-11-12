package main

import (
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

func queryGeneratedHeaders(spec targetSpec, patterns, tags, asmFiles []string, module, output string, cfg compileConfig) (*gotoolprofile.MetadataProof, error) {
	consumer, err := loadFeatureConsumer(cfg.Context, cfg.FeaturePath, output, spec.Goos+"/"+spec.Goarch, module, tags)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(asmFiles, consumer.Input.AsmFiles) || len(asmFiles) == 0 {
		return nil, fmt.Errorf("metadata query requires its exact registered ordinary assembly scope")
	}
	pkgs, err := loadGeneratedHeaderPackages(consumer, patterns, tags)
	if err != nil {
		return nil, err
	}
	if err := consumer.capturePackages(pkgs); err != nil {
		return nil, err
	}
	dependencies, err := consumer.ordinaryDependencyProof()
	if err != nil {
		return nil, err
	}
	proof := &gotoolprofile.MetadataProof{
		Protocol: gotoolprofile.MetadataProtocol, ProfileID: consumer.ID,
		CustomTags: append([]string(nil), tags...), Packages: consumer.Proof.Packages,
		Dependencies: dependencies,
	}
	for index, pkg := range pkgs {
		header, err := captureGeneratedHeader(consumer, pkg, proof.Packages[index], output)
		if err != nil {
			return nil, err
		}
		proof.Headers = append(proof.Headers, header)
	}
	if err := consumer.verifySources(); err != nil {
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
	if err := consumer.reobserve(binary, output); err != nil {
		return nil, err
	}
	if err := gotoolprofile.ValidateMetadata(consumer.Input, proof, tags); err != nil {
		return nil, err
	}
	return proof, nil
}

func loadGeneratedHeaderPackages(consumer *featureConsumer, patterns, tags []string) ([]*packages.Package, error) {
	return loadGeneratedHeaderPackagesWithLoader(consumer, patterns, tags, packages.Load)
}

func loadGeneratedHeaderPackagesWithLoader(consumer *featureConsumer, patterns, tags []string, load func(*packages.Config, ...string) ([]*packages.Package, error)) ([]*packages.Package, error) {
	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedModule | packages.NeedDeps |
			packages.NeedImports | packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax |
			packages.NeedCompiledGoFiles | packages.NeedExportFile | packages.NeedEmbedFiles | packages.NeedEmbedPatterns,
		Context: consumer.Context, Env: consumer.Env, Dir: consumer.WorkDir,
		BuildFlags: []string{"-mod=mod"},
	}
	if len(tags) != 0 {
		config.BuildFlags = append(config.BuildFlags, "-tags="+strings.Join(tags, ","))
	}
	return loadGeneratedHeaderPackagesForRole(consumer, config, patterns, load, true)
}

// Config is private, constructed only by the ordinary entry above or an
// independently validated actual instrumentation source context. Both paths
// retain identical pre/post source/type/export guards and concrete errors.
func loadGeneratedHeaderPackagesConfigured(consumer *featureConsumer, config *packages.Config, patterns []string, load func(*packages.Config, ...string) ([]*packages.Package, error)) ([]*packages.Package, error) {
	return loadGeneratedHeaderPackagesForRole(consumer, config, patterns, load, false)
}

func loadGeneratedHeaderPackagesForRole(consumer *featureConsumer, config *packages.Config, patterns []string, load func(*packages.Config, ...string) ([]*packages.Package, error), ordinary bool) ([]*packages.Package, error) {
	// Discover the actual dependency source set without compiling exports,
	// then pin it before the source/type/export load. Root hashes alone do
	// not guard stdlib or other dependency modules during that load.
	preConfig := *config
	preConfig.Mode &^= packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedExportFile
	before, err := load(&preConfig, patterns...)
	if err != nil {
		return nil, err
	}
	captureGuard := func(pkgs []*packages.Package) (*generatedHeaderLoadGuard, error) {
		if ordinary {
			return captureTypedSourceLoadGuardWithEmbeds(consumer.Context, pkgs, nil, consumer.verifyOrdinaryEmbedPackage)
		}
		return captureGeneratedHeaderLoadGuard(consumer.Context, pkgs)
	}
	if ordinary {
		if err := consumer.captureOrdinaryDependencies(before); err != nil {
			return nil, err
		}
	}
	guard, err := captureGuard(before)
	if err != nil {
		return nil, err
	}
	pkgs, err := load(config, patterns...)
	if err != nil {
		return nil, err
	}
	// Keep concrete compiler/list diagnostics, including dependency errors,
	// rather than replacing them with an opaque package-loading count.
	var diagnostics []string
	packages.Visit(pkgs, nil, func(pkg *packages.Package) {
		for _, err := range pkg.Errors {
			diagnostics = append(diagnostics, err.Error())
		}
		// NeedSyntax explicitly asks x/tools to typecheck selected source,
		// not decode Go 1.27's newer binary export format. The actual exports
		// remain compiler inputs; syntax trees are not retained in this proof.
		pkg.Syntax = nil
	})
	if len(diagnostics) != 0 {
		sort.Strings(diagnostics)
		return nil, fmt.Errorf("actual generated-header Go package compilation:\n%s", strings.Join(diagnostics, "\n"))
	}
	after, err := captureGuard(pkgs)
	if err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(guard, after) {
		return nil, fmt.Errorf("generated-header dependency/source selection changed during actual Go export/type load")
	}
	if ordinary {
		if err := consumer.finishOrdinaryDependencies(pkgs); err != nil {
			return nil, err
		}
	}
	if err := consumer.retainGeneratedGuard(guard.Sources); err != nil {
		return nil, err
	}
	pkgs = filterPackagesByModule(pkgs, consumer.Input.Module)
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("generated-header query selected no exact ordinary package")
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].PkgPath < pkgs[j].PkgPath })
	return pkgs, consumer.verifySources()
}

func captureGeneratedHeader(consumer *featureConsumer, pkg *packages.Package, selected gotoolprofile.PackageProof, output string) (gotoolprofile.GeneratedHeaderProof, error) {
	return captureGeneratedHeaderConfigured(consumer, pkg, selected, output, generatedHeaderCaptureContext{
		protocol: gotoolprofile.GeneratedHeaderProtocol, id: consumer.ID,
		validate: func(proof gotoolprofile.GeneratedHeaderProof) error {
			return gotoolprofile.ValidateGeneratedHeader(consumer.Input, proof, selected)
		},
	})
}

type generatedHeaderCaptureContext struct {
	protocol      string
	id            string
	compilerFlags []string
	validate      func(gotoolprofile.GeneratedHeaderProof) error
}

func captureGeneratedHeaderConfigured(consumer *featureConsumer, pkg *packages.Package, selected gotoolprofile.PackageProof, output string, context generatedHeaderCaptureContext) (gotoolprofile.GeneratedHeaderProof, error) {
	var proof gotoolprofile.GeneratedHeaderProof
	if context.validate == nil || pkg == nil || isTestVariantPackage(pkg) || pkg.Types == nil || len(pkg.EmbedFiles) != 0 || len(pkg.EmbedPatterns) != 0 {
		return proof, fmt.Errorf("generated-header metadata requires an ordinary typed package without unbound embed/test roles")
	}
	if err := consumer.verifySources(); err != nil {
		return proof, err
	}
	owned, err := os.MkdirTemp(output, ".generated-header-")
	if err != nil {
		return proof, err
	}
	// Retain these owned oracle artifacts. They are not Go dependency cache
	// files and their existence is not assembly translation evidence.
	imports, exports, importcfg, sourceGuard, err := generatedHeaderImports(consumer, pkg)
	if err != nil {
		return proof, err
	}
	for _, guard := range []map[string]string{exports, sourceGuard} {
		if err := consumer.retainGeneratedGuard(guard); err != nil {
			return proof, err
		}
	}
	configFile := filepath.Join(owned, "importcfg")
	if err := os.WriteFile(configFile, []byte(importcfg), 0600); err != nil {
		return proof, err
	}
	configSHA, err := gotoolprofile.FileSHA256(configFile)
	if err != nil {
		return proof, err
	}
	headerFile, objectFile := filepath.Join(owned, "go_asm.h"), filepath.Join(owned, "go.o")
	goVersion := "1.16" // The Go command's default for a module without a go directive.
	if pkg.Module != nil && pkg.Module.GoVersion != "" {
		goVersion = pkg.Module.GoVersion
	}
	lang := version.Lang("go" + goVersion)
	if lang == "" {
		return proof, fmt.Errorf("actual selected module has no valid Go language version")
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return proof, err
	}
	if err := verifyGeneratedHeaderCompiler(consumer, binary); err != nil {
		return proof, err
	}
	args := []string{"tool", "compile", "-p", pkg.PkgPath, "-lang=" + lang,
		"-importcfg", configFile, "-asmhdr", headerFile, "-o", objectFile}
	args = append(args, context.compilerFlags...)
	args = append(args, pkg.CompiledGoFiles...)
	if _, _, err := gotoolprofile.RunBounded(consumer.Context, consumer.WorkDir, consumer.Env, binary, args...); err != nil {
		return proof, fmt.Errorf("actual Go compiler -asmhdr: %w", err)
	}
	if err := verifyGeneratedHeaderCompiler(consumer, binary); err != nil {
		return proof, err
	}
	for file, expected := range exports {
		actual, err := gotoolprofile.FileSHA256(file)
		if err != nil || actual != expected {
			return proof, fmt.Errorf("actual dependency export changed during generated-header compilation")
		}
	}
	for file, expected := range sourceGuard {
		actual, err := gotoolprofile.FileSHA256(file)
		if err != nil || actual != expected {
			return proof, fmt.Errorf("actual dependency Go source changed during generated-header compilation")
		}
	}
	actualConfigSHA, err := gotoolprofile.FileSHA256(configFile)
	if err != nil || actualConfigSHA != configSHA {
		return proof, fmt.Errorf("actual compiler importcfg changed during generated-header compilation")
	}
	if err := consumer.verifySources(); err != nil {
		return proof, err
	}
	data, err := os.ReadFile(headerFile)
	if err != nil {
		return proof, err
	}
	definitions, err := gotoolprofile.HeaderDefinitions(data)
	if err != nil {
		return proof, err
	}
	typed, err := plan9asm.GoAssemblyHeader(plan9asm.GoPackage{Path: pkg.PkgPath, Types: pkg.Types}, consumer.Observed.Environment["GOARCH"])
	if err != nil {
		return proof, err
	}
	typedDefinitions, err := gotoolprofile.HeaderDefinitions(typed)
	if err != nil || !reflect.DeepEqual(definitions, typedDefinitions) {
		return proof, fmt.Errorf("full generated-header definitions differ from actual Go -asmhdr: actual=%v typed=%v: %v", definitions, typedDefinitions, err)
	}
	info, err := os.Stat(objectFile)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return proof, fmt.Errorf("actual generated-header compiler did not create a nonempty Go object")
	}
	objectSHA, err := gotoolprofile.FileSHA256(objectFile)
	if err != nil {
		return proof, err
	}
	proof = gotoolprofile.GeneratedHeaderProof{
		Protocol: context.protocol, PackagePath: pkg.PkgPath,
		ProfileID: context.id, Target: consumer.Observed.Target, GoVersion: consumer.Observed.GoVersion,
		LanguageVersion:   lang,
		CompileToolSHA256: consumer.Observed.ToolBinarySHA256["compile"],
		HeaderSHA256:      featureBytesSHA256(data), ObjectSHA256: objectSHA,
		Definitions: definitions, DefinitionsSHA256: gotoolprofile.HeaderDefinitionSHA256(definitions),
		CompiledGoSHA256: make(map[string]string), ImportMap: make(map[string]string), Imports: imports,
	}
	for name, dep := range pkg.Imports {
		proof.ImportMap[name] = dep.PkgPath
	}
	for _, file := range selected.CompiledGoFiles {
		proof.CompiledGoSHA256[file] = selected.SourceSHA256[file]
	}
	return proof, context.validate(proof)
}

func verifyGeneratedHeaderCompiler(consumer *featureConsumer, binary string) error {
	data, _, err := gotoolprofile.RunBounded(consumer.Context, consumer.WorkDir, consumer.Env, binary, "tool", "-n", "compile")
	if err != nil {
		return err
	}
	route := strings.TrimSpace(string(data))
	if !filepath.IsAbs(route) || strings.ContainsAny(route, "\r\n") {
		return fmt.Errorf("actual generated-header compiler route is not one executable")
	}
	actual, err := gotoolprofile.FileSHA256(route)
	if err != nil || actual != consumer.Observed.ToolBinarySHA256["compile"] {
		return fmt.Errorf("generated-header compiler differs from the actual registered profile tool")
	}
	return nil
}

func generatedHeaderImports(consumer *featureConsumer, pkg *packages.Package) ([]gotoolprofile.ImportExport, map[string]string, string, map[string]string, error) {
	return generatedHeaderImportsForRole(consumer, pkg, false)
}

func generatedHeaderImportsForRole(consumer *featureConsumer, pkg *packages.Package, boundTestEmbeds bool) ([]gotoolprofile.ImportExport, map[string]string, string, map[string]string, error) {
	var imports []gotoolprofile.ImportExport
	var config strings.Builder
	exports, sources := make(map[string]string), make(map[string]string)
	var names []string
	for name := range pkg.Imports {
		if name != "unsafe" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		dep := pkg.Imports[name]
		if dep == nil || dep.ExportFile == "" || strings.ContainsAny(dep.ExportFile, "\r\n") || isTestVariantPackage(dep) || len(dep.CompiledGoFiles) == 0 || strings.ContainsAny(name+dep.PkgPath, "\r\n=\\") {
			return nil, nil, "", nil, fmt.Errorf("generated header requires actual ordinary same-profile dependency exports")
		}
		if len(dep.EmbedFiles) != 0 || len(dep.EmbedPatterns) != 0 {
			verify := consumer.verifyOrdinaryEmbedPackage
			if boundTestEmbeds {
				verify = consumer.verifyTestEmbedPackage
			}
			if err := verify(dep); err != nil {
				return nil, nil, "", nil, err
			}
			for _, file := range dep.EmbedFiles {
				digest, err := gotoolprofile.FileSHA256(file)
				if err != nil {
					return nil, nil, "", nil, err
				}
				sources[file] = digest
			}
		}
		digest, err := gotoolprofile.FileSHA256(dep.ExportFile)
		if err != nil {
			return nil, nil, "", nil, err
		}
		imported := gotoolprofile.ImportExport{ImportPath: name, PackagePath: dep.PkgPath, ExportSHA256: digest, GoSHA256: make(map[string]string), SourceRole: "stdlib"}
		root := filepath.Join(consumer.Root, "src")
		if dep.Module != nil {
			root = dep.Module.Dir
			imported.ModulePath, imported.Version = dep.Module.Path, dep.Module.Version
			imported.SourceModule, imported.SourceVersion, imported.SourceRole = dep.Module.Path, dep.Module.Version, "module"
			if dep.Module.Main {
				imported.SourceRole = "main"
			}
			if dep.Module.Replace != nil {
				root, imported.SourceRole = dep.Module.Replace.Dir, "owned_local_replace"
				if dep.Module.Replace.Version != "" {
					imported.SourceModule, imported.SourceVersion = dep.Module.Replace.Path, dep.Module.Replace.Version
					imported.SourceRole = "version_replace"
				}
			}
		}
		root, err = sourcepath.Resolve(root)
		if err != nil {
			return nil, nil, "", nil, err
		}
		for _, file := range dep.CompiledGoFiles {
			resolved, err := sourcepath.Resolve(file)
			if err != nil {
				return nil, nil, "", nil, err
			}
			rel, err := filepath.Rel(root, resolved)
			if err != nil || !filepath.IsLocal(rel) {
				return nil, nil, "", nil, fmt.Errorf("dependency compiler source has an unbound generated/cgo role")
			}
			digest, err := gotoolprofile.FileSHA256(resolved)
			if err != nil {
				return nil, nil, "", nil, err
			}
			imported.GoSHA256[filepath.ToSlash(rel)], sources[resolved] = digest, digest
		}
		if name != dep.PkgPath {
			fmt.Fprintf(&config, "importmap %s=%s\n", name, dep.PkgPath)
		}
		fmt.Fprintf(&config, "packagefile %s=%s\n", dep.PkgPath, dep.ExportFile)
		exports[dep.ExportFile] = digest
		imports = append(imports, imported)
	}
	return imports, exports, config.String(), sources, nil
}
