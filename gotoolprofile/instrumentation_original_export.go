package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const instrumentationOriginalExportProtocol = "actual_go_instrumentation_original_export_v1"

// InstrumentationOriginalExportProof establishes stock-Go compilation/export
// and asmdecl for the original package, never CPP/LLVM consumption or runtime.
// Phase 1 admits only original compiled Go files with no imports: generated
// CGO and dependency source roles need their own same-mode closure first.
// The existing original ZIP/metadata authentication is a prerequisite supplied
// by the caller, not established by a directory hash or this portable reader.
type InstrumentationOriginalExportProof struct {
	Protocol               string                              `json:"protocol"`
	Plan                   *InstrumentationOriginalPackagePlan `json:"plan"`
	MarkerObservationID    string                              `json:"marker_observation_id"`
	Package                PackageProof                        `json:"package"`
	ExportArgs             []string                            `json:"export_args"`
	VetArgs                []string                            `json:"vet_args"`
	InvocationConfigSHA256 map[string]string                   `json:"invocation_config_sha256"`
	ArchiveSHA256          string                              `json:"archive_sha256"`
	Status                 string                              `json:"status"`
}

func CaptureInstrumentationOriginalExport(ctx context.Context, binary, invocationDir string, env []string, input *ConsumerInput, inventory *InstrumentationOriginalSourceInventory, marker *InstrumentationExportObservation, plan *InstrumentationOriginalPackagePlan, run Runner) (*InstrumentationOriginalExportProof, error) {
	if ctx == nil || ctx.Err() != nil || run == nil || !filepath.IsAbs(binary) || !filepath.IsAbs(invocationDir) {
		return nil, fmt.Errorf("original export requires a live context, bounded runner and absolute owned invocation")
	}
	if err := ValidateInstrumentationExportObservation(marker); err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, fmt.Errorf("missing original same-mode planning scope")
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input, inventory, marker.Early, plan.PackageDirectory, plan.CustomTags, plan); err != nil {
		return nil, err
	}
	if err := recheckInstrumentationOriginalSources(input); err != nil {
		return nil, err
	}
	configs, err := captureInstrumentationInvocationConfig(invocationDir)
	if err != nil {
		return nil, err
	}
	replacements := copyInstrumentationHashes(marker.Early.Environment)
	delete(replacements, "GOVERSION")
	replacements["GOTOOLCHAIN"], replacements["GOWORK"], replacements["GOFLAGS"], replacements["GOPACKAGESDRIVER"] = "local", "off", "", "off"
	replacements["GOENV"] = "off"
	modeEnv := replaceEnv(env, replacements)
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, invocationDir, modeEnv, run)
	if err != nil {
		return nil, err
	}
	if err := recheckInstrumentationExportEnvironment(actual, commandContext, marker.Early); err != nil {
		return nil, err
	}
	before, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil || !instrumentationExportToolsMatch(before, marker.Early.ModeTools) {
		return nil, fmt.Errorf("actual original export tool routing differs from the same-mode observation: %v", err)
	}
	proof := &InstrumentationOriginalExportProof{
		Protocol: instrumentationOriginalExportProtocol, Plan: plan, Status: "consumer_pending",
		MarkerObservationID: instrumentationObjectSHA(marker), InvocationConfigSHA256: configs,
		ExportArgs: instrumentationOriginalCommand(plan, false), VetArgs: instrumentationOriginalCommand(plan, true),
	}
	stdout, stderr, commandErr := run(ctx, invocationDir, modeEnv, binary, proof.ExportArgs...)
	if commandErr != nil || len(stderr) != 0 {
		return nil, fmt.Errorf("original same-mode export failed or emitted unregistered diagnostics (not source N/A): %v; %s", commandErr, stderr)
	}
	archive, pkg, err := decodeInstrumentationOriginalExport(stdout, input, plan, actual["GOCACHE"])
	if err != nil {
		return nil, err
	}
	var metadata struct {
		Module struct{ GoMod string }
	}
	if err := json.Unmarshal(stdout, &metadata); err != nil {
		return nil, err
	}
	metadataHash, err := FileSHA256(metadata.Module.GoMod)
	if err != nil {
		return nil, err
	}
	proof.Package = *pkg
	proof.ArchiveSHA256, err = FileSHA256(archive)
	if err != nil {
		return nil, err
	}
	if err := RunInstrumentationOrdinaryAsmdecl(ctx, binary, invocationDir, modeEnv, input, plan, pkg,
		map[string]string{pkg.PackagePath: proof.ArchiveSHA256}, run); err != nil {
		return nil, err
	}
	if err := recheckInstrumentationOriginalSources(input); err != nil {
		return nil, err
	}
	afterConfigs, err := captureInstrumentationInvocationConfig(invocationDir)
	if err != nil || !reflect.DeepEqual(configs, afterConfigs) {
		return nil, fmt.Errorf("owned invocation configuration changed during original export")
	}
	after, afterContext, err := instrumentationObserverEnvironment(ctx, binary, invocationDir, modeEnv, run)
	if err != nil || !reflect.DeepEqual(actual, after) || !reflect.DeepEqual(commandContext, afterContext) {
		return nil, fmt.Errorf("actual original export mode/environment changed")
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil || !equalDiscoveryFeatureToolStates(before, tools) {
		return nil, fmt.Errorf("actual original export compiler/assembler/vet identity changed")
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(sources, marker.Early.SourceRules) {
		return nil, fmt.Errorf("actual original export source-rule registration changed")
	}
	if hash, err := FileSHA256(binary); err != nil || hash != marker.Early.BaselineFeatures.DriverSHA256 {
		return nil, fmt.Errorf("actual original export driver changed")
	}
	for name, expected := range marker.Early.BaselineFeatures.ToolSourceSHA256 {
		if hash, err := FileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(name))); err != nil || hash != expected {
			return nil, fmt.Errorf("actual original export CPU/experiment source changed: %s", name)
		}
	}
	if hash, err := FileSHA256(archive); err != nil || hash != proof.ArchiveSHA256 {
		return nil, fmt.Errorf("actual original export archive changed during asmdecl")
	}
	if hash, err := FileSHA256(metadata.Module.GoMod); err != nil || hash != metadataHash {
		return nil, fmt.Errorf("actual original module metadata changed during asmdecl")
	}
	if err := ValidateInstrumentationOriginalExport(input, inventory, marker, plan, proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateInstrumentationOriginalExport(input *ConsumerInput, inventory *InstrumentationOriginalSourceInventory, marker *InstrumentationExportObservation, expected *InstrumentationOriginalPackagePlan, proof *InstrumentationOriginalExportProof) error {
	if proof == nil || proof.Protocol != instrumentationOriginalExportProtocol || expected == nil || proof.Status != "consumer_pending" {
		return fmt.Errorf("missing original export protocol or inappropriate completed outcome")
	}
	if err := ValidateInstrumentationExportObservation(marker); err != nil {
		return err
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input, inventory, marker.Early, expected.PackageDirectory, expected.CustomTags, proof.Plan); err != nil {
		return err
	}
	if !reflect.DeepEqual(expected, proof.Plan) || proof.MarkerObservationID != instrumentationObjectSHA(marker) ||
		!reflect.DeepEqual(proof.ExportArgs, instrumentationOriginalCommand(expected, false)) ||
		!reflect.DeepEqual(proof.VetArgs, instrumentationOriginalCommand(expected, true)) ||
		!discoverySHA256Pattern.MatchString(proof.ArchiveSHA256) ||
		len(proof.InvocationConfigSHA256) < 1 || len(proof.InvocationConfigSHA256) > 2 {
		return fmt.Errorf("original export differs from its expected same-mode source/command scope")
	}
	for name, hash := range proof.InvocationConfigSHA256 {
		if name != "go.mod" && name != "go.sum" || !discoverySHA256Pattern.MatchString(hash) {
			return fmt.Errorf("original export has an unknown or missing invocation config identity")
		}
	}
	if proof.InvocationConfigSHA256["go.mod"] == "" {
		return fmt.Errorf("original export has no immutable invocation module")
	}
	if proof.Package.SourceRole == "main" && proof.InvocationConfigSHA256["go.mod"] != input.Sources["go.mod"] {
		return fmt.Errorf("versionless main invocation metadata differs from its original source")
	}
	if err := ValidatePackageModule(input, proof.Package); err != nil {
		return err
	}
	if proof.Package.PackagePath != expected.PackagePath || !reflect.DeepEqual(proof.Package.GoFiles, expected.GoFiles) ||
		!reflect.DeepEqual(proof.Package.CompiledGoFiles, expected.GoFiles) || !reflect.DeepEqual(proof.Package.SFiles, expected.SFiles) || proof.Package.Macros != nil || len(expected.CgoFiles) != 0 {
		return fmt.Errorf("original export lost source roles or invented generated/CPP consumption")
	}
	hashes := make(map[string]string)
	for _, files := range [][]string{expected.GoFiles, expected.SFiles} {
		for _, file := range files {
			hashes[file] = input.Sources[file]
		}
	}
	if !reflect.DeepEqual(hashes, proof.Package.SourceSHA256) {
		return fmt.Errorf("actual selected original source hashes differ")
	}
	return nil
}

func instrumentationOriginalCommand(plan *InstrumentationOriginalPackagePlan, vet bool) []string {
	args := []string{"list", "-export", "-compiled", "-json", "-mod=readonly", "-p=1"}
	if vet {
		return instrumentationOrdinaryAsmdeclArgs()
	}
	args = append(args, plan.BuildFlags...)
	if len(plan.CustomTags) != 0 {
		args = append(args, "-tags="+strings.Join(plan.CustomTags, ","))
	}
	return append(args, plan.PackagePath)
}

func decodeInstrumentationOriginalExport(data []byte, input *ConsumerInput, plan *InstrumentationOriginalPackagePlan, cache string) (string, *PackageProof, error) {
	if len(data) == 0 || len(data) > commandOutputLimit {
		return "", nil, fmt.Errorf("missing or over-bound actual original export JSON")
	}
	var pkg struct {
		Dir, ImportPath, Name, Export, BuildID                               string
		GoFiles, CompiledGoFiles, SFiles                                     []string
		CgoFiles, CFiles, CXXFiles, FFiles, SwigFiles, SwigCXXFiles, Imports []string
		Incomplete                                                           bool
		Error                                                                json.RawMessage
		DepsErrors                                                           []json.RawMessage
		Module                                                               *struct {
			Path, Version, Dir, GoMod string
			Main                      bool
			Replace                   json.RawMessage
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&pkg); err != nil {
		return "", nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", nil, fmt.Errorf("actual original export contains multiple packages or trailing text")
	}
	root, err := sourcepath.Resolve(input.SourceRoot)
	if err != nil {
		return "", nil, err
	}
	actualDir, dirErr := sourcepath.Resolve(pkg.Dir)
	if dirErr != nil || actualDir != filepath.Join(root, filepath.FromSlash(plan.PackageDirectory)) || pkg.ImportPath != plan.PackagePath ||
		pkg.Name != plan.PackageName || pkg.BuildID == "" || pkg.Incomplete || len(pkg.Error) != 0 || len(pkg.DepsErrors) != 0 ||
		len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles) != 0 {
		return "", nil, fmt.Errorf("actual original export has unbound generated/native source roles or failed package metadata")
	}
	if len(pkg.Imports) != 0 {
		return "", nil, fmt.Errorf("original export requires an independent same-mode dependency source closure")
	}
	if pkg.Module == nil || pkg.Module.Path != input.Module || pkg.Module.Version != input.Version || len(pkg.Module.Replace) != 0 ||
		pkg.Module.Main != (input.SourceModule == "") || input.SourceModule != "" && input.SourceModule != input.Module {
		return "", nil, fmt.Errorf("actual original export module/version/main/replacement differs from immutable source identity")
	}
	moduleDir, err := sourcepath.Resolve(pkg.Module.Dir)
	if err != nil || moduleDir != root {
		return "", nil, fmt.Errorf("actual module directory differs from the original source root")
	}
	selected := &PackageProof{
		PackagePath: pkg.ImportPath, ModulePath: pkg.Module.Path, ModuleVersion: pkg.Module.Version,
		SourceModule: pkg.Module.Path, SourceVersion: pkg.Module.Version, SourceRole: "module", SourceSHA256: make(map[string]string),
	}
	if pkg.Module.Main {
		selected.SourceRole = "main"
	}
	for index, list := range [][]string{pkg.GoFiles, pkg.CompiledGoFiles, pkg.SFiles} {
		var files []string
		for _, name := range list {
			if filepath.IsAbs(name) {
				name, err = filepath.Rel(pkg.Dir, name)
				if err != nil {
					return "", nil, err
				}
			}
			if path.Base(name) != name || !validInstrumentationSourcePath(name) {
				return "", nil, fmt.Errorf("compiled Go path has no exact original role: %s", name)
			}
			file := path.Join(plan.PackageDirectory, name)
			if input.Sources[file] == "" {
				return "", nil, fmt.Errorf("actual compiled source has no original byte identity: %s", file)
			}
			files = append(files, file)
			selected.SourceSHA256[file] = input.Sources[file]
		}
		sort.Strings(files)
		switch index {
		case 0:
			selected.GoFiles = files
		case 1:
			selected.CompiledGoFiles = files
		case 2:
			selected.SFiles = files
		}
	}
	if input.ProxyGoMod != nil {
		if err := ValidateProxyGoMod(input.ProxyGoMod); err != nil {
			return "", nil, err
		}
		selected.GoModOrigin, selected.GoModSHA256, selected.GoModSum = input.ProxyGoMod.Protocol, input.ProxyGoMod.SHA256, input.ProxyGoMod.GoModSum
	}
	expectedMod := input.Sources["go.mod"]
	if input.ProxyGoMod != nil {
		expectedMod = input.ProxyGoMod.SHA256
	}
	if hash, err := FileSHA256(pkg.Module.GoMod); err != nil || hash != expectedMod || expectedMod == "" {
		return "", nil, fmt.Errorf("actual module metadata differs from the immutable original origin")
	}
	resolvedCache, err := sourcepath.Resolve(cache)
	if err != nil {
		return "", nil, err
	}
	archive, err := sourcepath.Resolve(pkg.Export)
	relative, relErr := filepath.Rel(resolvedCache, archive)
	if err != nil || relErr != nil || !filepath.IsAbs(pkg.Export) || !filepath.IsLocal(relative) {
		return "", nil, fmt.Errorf("actual original export is absent or outside its observed owned cache")
	}
	return archive, selected, nil
}

func recheckInstrumentationOriginalSources(input *ConsumerInput) error {
	if input == nil || !filepath.IsAbs(input.SourceRoot) || len(input.Sources) == 0 || len(input.Sources) > 65536 || len(input.Directories) == 0 {
		return fmt.Errorf("missing bounded original source inventory")
	}
	root, err := sourcepath.Resolve(input.SourceRoot)
	if err != nil {
		return err
	}
	for directory, names := range input.Directories {
		if directory != "." && !validInstrumentationSourcePath(directory) {
			return fmt.Errorf("original directory escapes its source root")
		}
		physical := filepath.Join(root, filepath.FromSlash(directory))
		resolved, err := sourcepath.Resolve(physical)
		if err != nil || resolved != physical {
			return fmt.Errorf("original directory is absent or redirected: %s", directory)
		}
		entries, err := os.ReadDir(physical)
		if err != nil || len(entries) != len(names) {
			return fmt.Errorf("original directory inventory changed: %s", directory)
		}
		for index, entry := range entries {
			if entry.Name() != names[index] || entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
				return fmt.Errorf("original directory member changed or is not regular: %s", entry.Name())
			}
			if !entry.IsDir() && input.Sources[path.Join(directory, entry.Name())] == "" {
				return fmt.Errorf("original resource lacks a full byte identity: %s", entry.Name())
			}
		}
	}
	for file, expected := range input.Sources {
		if !validInstrumentationSourcePath(file) || !discoverySHA256Pattern.MatchString(expected) {
			return fmt.Errorf("invalid original source byte identity")
		}
		physical, err := CPPRegularSource(root, file)
		if err != nil {
			return err
		}
		if hash, err := FileSHA256(physical); err != nil || hash != expected {
			return fmt.Errorf("original source bytes changed: %s", file)
		}
	}
	return nil
}

func captureInstrumentationInvocationConfig(directory string) (map[string]string, error) {
	return CaptureInstrumentationInvocationConfig(directory)
}

// CaptureInstrumentationInvocationConfig snapshots only an existing owned
// caller's module configuration. It never edits metadata, chooses versions or
// supplies source authentication. Recheck it after every consumer stage.
func CaptureInstrumentationInvocationConfig(directory string) (map[string]string, error) {
	config := make(map[string]string)
	for _, name := range []string{"go.mod", "go.sum"} {
		file := filepath.Join(directory, name)
		info, err := os.Lstat(file)
		if os.IsNotExist(err) && name == "go.sum" {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return nil, fmt.Errorf("owned invocation configuration is missing, nonregular or over-bound: %s", name)
		}
		config[name], err = FileSHA256(file)
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}
