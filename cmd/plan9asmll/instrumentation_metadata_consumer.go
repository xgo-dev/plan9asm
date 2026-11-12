package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
	"golang.org/x/tools/go/packages"
)

// This private adapter is not wired into the ordinary CLI/report. Source uses
// only its original immutable byte guards; it has no ordinary SelectionProof.
// All selected/export/header results retain their separate actual mode input.
type instrumentationMetadataConsumer struct {
	Input            *gotoolprofile.InstrumentationConsumerInput
	Source           *featureConsumer
	Packages         []*packages.Package
	Metadata         *gotoolprofile.InstrumentationMetadataProof
	InvocationConfig map[string]string
	ForeignSources   *gotoolprofile.InstrumentationTypeModuleGuard
	ArtifactRoot     string
	Artifacts        []gotoolprofile.InstrumentationLLVMArtifacts
}

func captureInstrumentationMetadata(ctx context.Context, input *gotoolprofile.InstrumentationConsumerInput, invocation string, env []string, output string, load func(*packages.Config, ...string) ([]*packages.Package, error)) (*instrumentationMetadataConsumer, error) {
	if ctx == nil || ctx.Err() != nil || input == nil || input.Plan == nil || load == nil || !filepath.IsAbs(invocation) {
		return nil, fmt.Errorf("mode metadata needs a live actual source/export context")
	}
	plan := input.Plan
	if err := gotoolprofile.ValidateInstrumentationConsumerInput(input, plan.PackageDirectory, plan.CustomTags); err != nil {
		return nil, err
	}
	if len(plan.CgoFiles) != 0 {
		return nil, fmt.Errorf("mode metadata cannot bind generated cgo compiler inputs without their original source mapping")
	}
	dir, err := sourcepath.Resolve(input.Original.SourceRoot)
	if err != nil {
		return nil, err
	}
	invocation, err = sourcepath.Resolve(invocation)
	if err != nil {
		return nil, err
	}
	configuration, err := gotoolprofile.CaptureInstrumentationInvocationConfig(invocation)
	if err != nil {
		return nil, err
	}
	modeActual := make(map[string]string, len(input.Observation.Early.Environment)+1)
	for key, value := range input.Observation.Early.Environment {
		modeActual[key] = value
	}
	// The independently observed mode disables user go/env. Every metadata,
	// header, analyzer and object consumer must execute under that same policy.
	modeActual["GOENV"] = "off"
	modeEnv := featureEnvironment(env, modeActual)
	source := &featureConsumer{
		ID: input.Original.ID, Observed: input.Original.Observed, Input: input.Original,
		Context: ctx, Dir: dir, WorkDir: invocation, Env: modeEnv,
	}
	consumer := &instrumentationMetadataConsumer{Input: input, Source: source, InvocationConfig: configuration}
	if err := source.verifySources(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(output, 0700); err != nil {
		return nil, err
	}
	if err := consumer.reobserve(output); err != nil {
		return nil, err
	}
	binary, err := exec.LookPath("go")
	if err != nil {
		return nil, err
	}
	if input.TypeSources != nil {
		consumer.ForeignSources, err = gotoolprofile.BindInstrumentationTypeModuleSources(ctx, binary, invocation, modeEnv, input.TypeSources.SourceModules, gotoolprofile.RunBounded)
		if err != nil {
			return nil, err
		}
		actual, err := gotoolprofile.CaptureInstrumentationTypeSources(ctx, binary, invocation, modeEnv, input, gotoolprofile.RunBounded)
		if err != nil || !reflect.DeepEqual(actual, input.TypeSources) {
			return nil, fmt.Errorf("original imported type source input differs from independent actual consumption: %v", err)
		}
	}
	root, stderr, err := gotoolprofile.RunBounded(ctx, invocation, modeEnv, binary, "env", "GOROOT")
	if err != nil || len(stderr) != 0 || !filepath.IsAbs(strings.TrimSpace(string(root))) {
		return nil, fmt.Errorf("actual mode source root: %v; %s", err, stderr)
	}
	source.Root = strings.TrimSpace(string(root))
	flags, err := gotoolprofile.InstrumentationPackageLoadFlags(input)
	if err != nil {
		return nil, err
	}
	config := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedModule | packages.NeedDeps | packages.NeedImports |
			packages.NeedTypes | packages.NeedTypesSizes | packages.NeedSyntax | packages.NeedCompiledGoFiles |
			packages.NeedExportFile | packages.NeedEmbedFiles | packages.NeedEmbedPatterns,
		Context: ctx, Env: modeEnv, Dir: invocation, BuildFlags: flags,
	}
	pkgs, err := loadGeneratedHeaderPackagesConfigured(source, config, []string{plan.PackagePath}, load)
	if err != nil {
		return nil, err
	}
	if len(pkgs) != 1 || pkgs[0].PkgPath != plan.PackagePath || pkgs[0].Name != plan.PackageName {
		return nil, fmt.Errorf("mode metadata selected a changed original package scope")
	}
	selected, err := source.captureSourcePackage(pkgs[0], func(packagePath string) (*gotoolprofile.AssemblerMacros, error) {
		return gotoolprofile.CaptureInstrumentationAssemblerMacros(source.Root, input, packagePath)
	})
	if err != nil {
		return nil, err
	}
	selection := &gotoolprofile.InstrumentationPackageSelectionProof{
		Protocol: gotoolprofile.InstrumentationPackageSelectionProtocol, ModeProfileID: input.ID,
		InputSHA256: gotoolprofile.InstrumentationConsumerInputSHA256(input),
		CustomTags:  append([]string(nil), plan.CustomTags...), Packages: []gotoolprofile.PackageProof{selected}, Status: "consumer_pending",
	}
	if err := gotoolprofile.ValidateInstrumentationPackageSelection(input, plan.PackageDirectory, plan.CustomTags, selection); err != nil {
		return nil, err
	}
	headerFlags, err := gotoolprofile.InstrumentationHeaderCompilerFlags(input)
	if err != nil {
		return nil, err
	}
	header, err := captureGeneratedHeaderConfigured(source, pkgs[0], selected, output, generatedHeaderCaptureContext{
		protocol: gotoolprofile.InstrumentationGeneratedHeaderProtocol, id: input.ID, compilerFlags: headerFlags,
		validate: func(header gotoolprofile.GeneratedHeaderProof) error {
			return gotoolprofile.ValidateInstrumentationGeneratedHeader(input, gotoolprofile.InstrumentationGeneratedHeader{Header: header, CompilerFlags: headerFlags}, selected)
		},
	})
	if err != nil {
		return nil, err
	}
	dependencies, err := captureInstrumentationMetadataDependencies(source, pkgs)
	if err != nil {
		return nil, err
	}
	declarations, err := captureInstrumentationPackageDeclarations(input, pkgs[0])
	if err != nil {
		return nil, err
	}
	exportSHA, err := gotoolprofile.FileSHA256(pkgs[0].ExportFile)
	if err != nil || pkgs[0].ExportFile == "" {
		return nil, fmt.Errorf("actual original mode export is absent: %v", err)
	}
	if err := source.retainGeneratedGuard(map[string]string{pkgs[0].ExportFile: exportSHA}); err != nil {
		return nil, err
	}
	vetArgs := gotoolprofile.InstrumentationPackageVetArgs(input)
	exports := map[string]string{selected.PackagePath: exportSHA}
	for _, dependency := range dependencies {
		exports[dependency.Source.PackagePath] = dependency.Source.ExportSHA256
	}
	if err := gotoolprofile.RunInstrumentationOrdinaryAsmdecl(ctx, binary, invocation, modeEnv, input.Original,
		plan, &selected, exports, gotoolprofile.RunBounded); err != nil {
		return nil, err
	}
	proof := &gotoolprofile.InstrumentationMetadataProof{
		Protocol: gotoolprofile.InstrumentationMetadataProtocol, ModeProfileID: input.ID,
		InputSHA256: gotoolprofile.InstrumentationConsumerInputSHA256(input), Selection: selection,
		Headers:      []gotoolprofile.InstrumentationGeneratedHeader{{Header: header, CompilerFlags: headerFlags}},
		Dependencies: dependencies, Status: "consumer_pending",
		Declarations:         declarations,
		OriginalExportSHA256: exportSHA, InvocationConfigSHA256: configuration, LoadBuildFlags: flags, VetArgs: vetArgs,
	}
	if err := gotoolprofile.ValidateInstrumentationMetadata(input, plan.PackageDirectory, plan.CustomTags, proof); err != nil {
		return nil, err
	}
	consumer.Packages, consumer.Metadata = pkgs, proof
	if err := consumer.reobserve(output); err != nil {
		return nil, err
	}
	return consumer, consumer.verifySources()
}

func (consumer *instrumentationMetadataConsumer) reobserve(output string) error {
	binary, err := exec.LookPath("go")
	if err != nil {
		return err
	}
	binary, err = filepath.Abs(binary)
	if err != nil {
		return err
	}
	owned, err := os.MkdirTemp(output, ".instrumentation-markers-")
	if err != nil {
		return err
	}
	input, source := consumer.Input, consumer.Source
	early := input.Observation.Early
	actual, err := gotoolprofile.CaptureInstrumentationExportObservation(source.Context, binary, owned, source.Env, early.Target, early.Mode, early.CGOEnabled, nil, gotoolprofile.RunBounded)
	if err != nil {
		return fmt.Errorf("reobserve actual same-mode metadata driver: %w", err)
	}
	if gotoolprofile.InstrumentationEarlyProfileID(actual.Early) != input.ID || !reflect.DeepEqual(actual.BuildPlan, input.Observation.BuildPlan) || !reflect.DeepEqual(actual.Routing, input.Observation.Routing) {
		return fmt.Errorf("mode source/tool/environment/compiler routing changed before or after metadata capture")
	}
	return consumer.verifySources()
}

func (consumer *instrumentationMetadataConsumer) verifySources() error {
	if err := consumer.Source.verifySources(); err != nil {
		return err
	}
	if consumer.ForeignSources != nil {
		if err := consumer.ForeignSources.Verify(consumer.Source.Context); err != nil {
			return err
		}
	}
	budget := &gotoolprofile.InstrumentationLLVMArtifactBudget{}
	for index := range consumer.Artifacts {
		if err := consumer.Source.Context.Err(); err != nil {
			return err
		}
		actual, err := gotoolprofile.CaptureInstrumentationLLVMArtifacts(consumer.ArtifactRoot, index, budget)
		if err != nil || !reflect.DeepEqual(actual, &consumer.Artifacts[index]) {
			return fmt.Errorf("mode generated LLVM artifact changed before final consumption: %v", err)
		}
	}
	actual, err := gotoolprofile.CaptureInstrumentationInvocationConfig(consumer.Source.WorkDir)
	if err != nil || !reflect.DeepEqual(actual, consumer.InvocationConfig) {
		return fmt.Errorf("mode invocation configuration changed before or after consumption: %v", err)
	}
	return nil
}

func captureInstrumentationMetadataDependencies(source *featureConsumer, pkgs []*packages.Package) ([]gotoolprofile.InstrumentationDependencyExport, error) {
	byPath := make(map[string]gotoolprofile.InstrumentationDependencyExport)
	var captureErr error
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if captureErr != nil {
			return false
		}
		if pkg.PkgPath == "unsafe" {
			return false
		}
		imports, exports, _, sources, err := generatedHeaderImports(source, pkg)
		if err != nil {
			captureErr = err
			return false
		}
		for _, guard := range []map[string]string{exports, sources} {
			if err := source.retainGeneratedGuard(guard); err != nil {
				captureErr = err
				return false
			}
		}
		for _, imported := range imports {
			imported.ImportPath = imported.PackagePath
			dep := pkg.Imports[imported.PackagePath]
			if dep == nil {
				for _, candidate := range pkg.Imports {
					if candidate.PkgPath == imported.PackagePath {
						dep = candidate
					}
				}
			}
			if dep == nil || len(byPath) >= 4096 {
				captureErr = fmt.Errorf("actual mode dependency closure lost its package or exceeded its bound")
				return false
			}
			entry := gotoolprofile.InstrumentationDependencyExport{Source: imported, ImportMap: make(map[string]string)}
			for name, child := range dep.Imports {
				entry.ImportMap[name] = child.PkgPath
			}
			if prior, found := byPath[imported.PackagePath]; found && !reflect.DeepEqual(prior, entry) {
				captureErr = fmt.Errorf("actual mode dependency source/export changed between reachable imports")
				return false
			}
			byPath[imported.PackagePath] = entry
		}
		return true
	}, nil)
	if captureErr != nil {
		return nil, captureErr
	}
	result := make([]gotoolprofile.InstrumentationDependencyExport, 0, len(byPath))
	for _, dep := range byPath {
		result = append(result, dep)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Source.PackagePath < result[j].Source.PackagePath })
	return result, source.verifySources()
}
