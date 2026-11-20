package gotoolprofile

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const instrumentationExportModule = "example.invalid/instrumentation-export"

// InstrumentationExportObservation is a current-Go, no-import marker export
// and asmdecl observation. It proves real compilation and a defined assembly
// symbol under the same mode, not linking, sanitizer execution, CC/SDK
// availability, or compilation of any external candidate. Original exporters
// still need their independently bound package/dependency/source observations.
type InstrumentationExportObservation struct {
	Protocol      string                           `json:"protocol"`
	Early         *InstrumentationEarlyObservation `json:"early"`
	BuildPlan     *InstrumentationBuildPlan        `json:"build_plan"`
	Routing       *InstrumentationExportRouting    `json:"routing"`
	Selection     *InstrumentationExportSelection  `json:"selection"`
	FixtureSHA256 map[string]string                `json:"fixture_sha256"`
	ExportArgs    []string                         `json:"export_args"`
	VetArgs       []string                         `json:"vet_args"`
	ArchiveSHA256 string                           `json:"archive_sha256"`
	NMOutput      string                           `json:"nm_output"`
	NMSHA256      string                           `json:"nm_sha256"`
}

type InstrumentationExportSelection struct {
	ImportPath        string   `json:"import_path"`
	GoFiles           []string `json:"go_files"`
	SFiles            []string `json:"s_files"`
	IgnoredGoFiles    []string `json:"ignored_go_files"`
	IgnoredOtherFiles []string `json:"ignored_other_files"`
}

func CaptureInstrumentationExportObservation(ctx context.Context, binary, ownedDir string, env []string, target string, mode InstrumentationMode, cgo string, overrides map[string]string, run Runner) (*InstrumentationExportObservation, error) {
	if ctx == nil || ctx.Err() != nil || run == nil {
		return nil, fmt.Errorf("export observation requires a live context and bounded runner")
	}
	if !filepath.IsAbs(ownedDir) {
		return nil, fmt.Errorf("export observation requires an absolute owned directory")
	}
	ownedDir, err := sourcepath.Resolve(ownedDir)
	if err != nil {
		return nil, err
	}
	env = replaceEnv(env, map[string]string{"GOENV": "off"})
	entries, err := os.ReadDir(ownedDir)
	if err != nil || len(entries) != 0 {
		return nil, fmt.Errorf("export observation requires an existing empty owned directory")
	}
	earlyDir, markerDir := filepath.Join(ownedDir, "early"), filepath.Join(ownedDir, "export")
	for _, dir := range []string{earlyDir, markerDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
	}
	early, err := CaptureInstrumentationEarlyObservation(ctx, binary, earlyDir, env, target, mode, cgo, overrides, run)
	if err != nil {
		return nil, err
	}
	minor, _ := goMinor(early.SourceRules.GoVersion)
	if early.Status != InstrumentationEarlyRuleAccepted || minor != 27 {
		return nil, fmt.Errorf("marker export routing requires an eligible current Go 1.27 mode; early rejection is not export proof")
	}
	plan, err := DeriveInstrumentationBuildPlan(early.SourceRules, target, mode)
	if err != nil {
		return nil, err
	}
	replacements := copyInstrumentationHashes(early.Environment)
	delete(replacements, "GOVERSION")
	replacements["GOTOOLCHAIN"], replacements["GOWORK"], replacements["GOFLAGS"], replacements["GOPACKAGESDRIVER"] = "local", "off", "", "off"
	modeEnv := replaceEnv(env, replacements)
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, markerDir, modeEnv, run)
	if err != nil {
		return nil, err
	}
	if err := recheckInstrumentationExportEnvironment(actual, commandContext, early); err != nil {
		return nil, err
	}
	before, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil || !instrumentationExportToolsMatch(before, early.ModeTools) {
		return nil, fmt.Errorf("mode tool state changed before actual export: %v", err)
	}
	environment, err := captureInstrumentationExportEnvironment(actual["GOROOT"], actual["GOVERSION"])
	if err != nil {
		return nil, err
	}
	if environment.SourceSHA256["src/cmd/go/internal/work/init.go"] != early.SourceRules.SourceSHA256["src/cmd/go/internal/work/init.go"] {
		return nil, fmt.Errorf("marker changed-environment source differs from its actual early build plan")
	}
	files := instrumentationExportFixture()
	for name, data := range files {
		file, err := os.OpenFile(filepath.Join(markerDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(data)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, fmt.Errorf("write owned export marker: %v (close: %v)", writeErr, closeErr)
		}
	}
	proof := &InstrumentationExportObservation{
		Protocol: "actual_go_instrumentation_marker_export_v2", Early: early, BuildPlan: plan,
		FixtureSHA256: instrumentationExportFixtureHashes(files),
		ExportArgs:    instrumentationExportArgs(mode), VetArgs: instrumentationVetArgs(mode),
	}
	stdout, stderr, commandErr := run(ctx, markerDir, modeEnv, binary, proof.ExportArgs...)
	if commandErr != nil {
		return nil, fmt.Errorf("eligible same-mode actual Go export failed (not source N/A): %w", commandErr)
	}
	archive, selection, err := decodeInstrumentationExport(stdout, markerDir, actual["GOCACHE"], mode)
	if err != nil {
		return nil, err
	}
	proof.Selection = selection
	proof.ArchiveSHA256, err = FileSHA256(archive)
	if err != nil {
		return nil, fmt.Errorf("actual export archive is absent: %w", err)
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(actual["GOOS"], actual["GOARCH"], actual)
	if err != nil {
		return nil, err
	}
	proof.Routing, err = captureInstrumentationExportRouting(stderr, actual["GOROOT"], markerDir, archive, early.ModeTools, plan, defines, environment, actual)
	if err != nil {
		return nil, err
	}
	stdout, stderr, commandErr = run(ctx, markerDir, modeEnv, binary, "tool", "nm", archive)
	if commandErr != nil || len(stderr) != 0 {
		return nil, fmt.Errorf("actual exported assembly nm failed or emitted unregistered diagnostics: %v", commandErr)
	}
	proof.NMOutput = instrumentationExportNMOutput(string(stdout), archive, markerDir)
	proof.NMSHA256 = bytesSHA256([]byte(proof.NMOutput))
	stdout, stderr, commandErr = run(ctx, markerDir, modeEnv, binary, proof.VetArgs...)
	if commandErr != nil || len(stdout) != 0 || len(stderr) != 0 {
		return nil, fmt.Errorf("actual same-mode asmdecl failed or emitted unregistered diagnostics: %v", commandErr)
	}
	if err := recheckInstrumentationExportInputs(ctx, binary, markerDir, modeEnv, actual, commandContext, early, files, archive, proof.ArchiveSHA256, before, run); err != nil {
		return nil, err
	}
	if err := recheckInstrumentationExportEnvironmentSources(actual["GOROOT"], actual["GOVERSION"], environment); err != nil {
		return nil, err
	}
	if err := ValidateInstrumentationExportObservation(proof); err != nil {
		return nil, err
	}
	return proof, nil
}

func ValidateInstrumentationExportObservation(proof *InstrumentationExportObservation) error {
	if proof == nil || proof.Protocol != "actual_go_instrumentation_marker_export_v2" {
		return fmt.Errorf("missing actual same-mode marker export protocol")
	}
	if err := ValidateInstrumentationEarlyObservation(proof.Early); err != nil {
		return err
	}
	minor, _ := goMinor(proof.Early.SourceRules.GoVersion)
	if proof.Early.Status != InstrumentationEarlyRuleAccepted || minor != 27 {
		return fmt.Errorf("early support/rejection does not prove a current actual export")
	}
	if err := ValidateInstrumentationBuildPlan(proof.BuildPlan, proof.Early.SourceRules); err != nil {
		return err
	}
	if proof.BuildPlan.Target != proof.Early.Target || proof.BuildPlan.Mode != proof.Early.Mode {
		return fmt.Errorf("export build plan differs from actual mode observation")
	}
	defines, err := plan9asm.GoAssemblerDefinesForEnvironment(proof.Early.Environment["GOOS"], proof.Early.Environment["GOARCH"], proof.Early.Environment)
	if err != nil {
		return err
	}
	if err := validateInstrumentationExportRouting(proof.Routing, proof.BuildPlan, defines, proof.Early.Environment); err != nil {
		return err
	}
	if proof.Routing.EnvironmentSource.SourceSHA256["src/cmd/go/internal/work/init.go"] != proof.Early.SourceRules.SourceSHA256["src/cmd/go/internal/work/init.go"] {
		return fmt.Errorf("marker environment and early build-plan sources differ")
	}
	if !reflect.DeepEqual(proof.Selection, instrumentationExpectedExportSelection(proof.Early.Mode)) ||
		!reflect.DeepEqual(proof.FixtureSHA256, instrumentationExportFixtureHashes(instrumentationExportFixture())) ||
		!reflect.DeepEqual(proof.ExportArgs, instrumentationExportArgs(proof.Early.Mode)) ||
		!reflect.DeepEqual(proof.VetArgs, instrumentationVetArgs(proof.Early.Mode)) ||
		!discoverySHA256Pattern.MatchString(proof.ArchiveSHA256) {
		return fmt.Errorf("export lacks its complete same-mode selected/excluded sources, archive or actual commands")
	}
	if len(proof.NMOutput) > commandOutputLimit || proof.NMSHA256 != bytesSHA256([]byte(proof.NMOutput)) {
		return fmt.Errorf("exported assembly symbol observation changed or exceeded its bound")
	}
	return validateInstrumentationExportNM(proof.NMOutput, proof.Early.Mode)
}

func instrumentationExportFixture() map[string][]byte {
	files := map[string][]byte{
		"go.mod":  []byte("module " + instrumentationExportModule + "\n\ngo 1.20\n"),
		"base.go": []byte("package markers\n\nfunc marker()\n"),
	}
	for _, mode := range []string{"race", "msan", "asan"} {
		files["mode_"+mode+".go"] = []byte("//go:build " + mode + "\n\npackage markers\n\nconst Mode = \"" + mode + "\"\n")
		files["mode_"+mode+".s"] = []byte("//go:build " + mode + "\n\n#include \"textflag.h\"\n\nTEXT ·marker(SB), NOSPLIT, $0-0\n\tRET\n")
	}
	return files
}

func instrumentationExportFixtureHashes(files map[string][]byte) map[string]string {
	hashes := make(map[string]string)
	for name, contents := range files {
		hashes[name] = bytesSHA256(contents)
	}
	return hashes
}

func instrumentationExportArgs(mode InstrumentationMode) []string {
	return []string{"list", "-a", "-x", "-export", "-json", "-p=1", "-mod=readonly", "-" + string(mode), "."}
}

func instrumentationVetArgs(mode InstrumentationMode) []string {
	return []string{"vet", "-" + string(mode), "-asmdecl", "-p=1", "-mod=readonly", "."}
}

func instrumentationExpectedExportSelection(mode InstrumentationMode) *InstrumentationExportSelection {
	selected := &InstrumentationExportSelection{
		ImportPath: instrumentationExportModule, GoFiles: []string{"base.go", "mode_" + string(mode) + ".go"},
		SFiles: []string{"mode_" + string(mode) + ".s"},
	}
	for _, candidate := range []string{"asan", "msan", "race"} {
		if candidate != string(mode) {
			selected.IgnoredGoFiles = append(selected.IgnoredGoFiles, "mode_"+candidate+".go")
			selected.IgnoredOtherFiles = append(selected.IgnoredOtherFiles, "mode_"+candidate+".s")
		}
	}
	return selected
}

func decodeInstrumentationExport(data []byte, directory, cache string, mode InstrumentationMode) (string, *InstrumentationExportSelection, error) {
	if len(data) == 0 || len(data) > commandOutputLimit {
		return "", nil, fmt.Errorf("missing or over-bound actual marker export JSON")
	}
	var pkg struct {
		Dir, ImportPath, Name, Export, BuildID                               string
		GoFiles, SFiles, IgnoredGoFiles, IgnoredOtherFiles                   []string
		CgoFiles, CFiles, CXXFiles, FFiles, SwigFiles, SwigCXXFiles, Imports []string
		Incomplete                                                           bool
		Error                                                                json.RawMessage
		DepsErrors                                                           []json.RawMessage
		Module                                                               *struct {
			Path, Version, Dir, GoMod, GoVersion string
			Main                                 bool
			Replace                              json.RawMessage
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&pkg); err != nil {
		return "", nil, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return "", nil, fmt.Errorf("actual marker export contains multiple packages or trailing output")
	}
	selection := &InstrumentationExportSelection{pkg.ImportPath, pkg.GoFiles, pkg.SFiles, pkg.IgnoredGoFiles, pkg.IgnoredOtherFiles}
	if pkg.Dir != directory || pkg.Name != "markers" || pkg.BuildID == "" || pkg.Incomplete || len(pkg.Error) != 0 || len(pkg.DepsErrors) != 0 ||
		len(pkg.CgoFiles)+len(pkg.CFiles)+len(pkg.CXXFiles)+len(pkg.FFiles)+len(pkg.SwigFiles)+len(pkg.SwigCXXFiles)+len(pkg.Imports) != 0 ||
		pkg.Module == nil || !pkg.Module.Main || pkg.Module.Path != instrumentationExportModule || pkg.Module.Version != "" ||
		pkg.Module.Dir != directory || pkg.Module.GoMod != filepath.Join(directory, "go.mod") || pkg.Module.GoVersion != "1.20" || len(pkg.Module.Replace) != 0 ||
		!reflect.DeepEqual(selection, instrumentationExpectedExportSelection(mode)) {
		return "", nil, fmt.Errorf("actual export selected incomplete, foreign or mismatched original marker sources")
	}
	resolvedCache, err := sourcepath.Resolve(cache)
	if err != nil {
		return "", nil, err
	}
	resolved, err := sourcepath.Resolve(pkg.Export)
	relative, relErr := filepath.Rel(resolvedCache, resolved)
	if err != nil || relErr != nil || !filepath.IsAbs(pkg.Export) || !filepath.IsLocal(relative) {
		return "", nil, fmt.Errorf("actual export archive is absent or outside the observed cache")
	}
	return pkg.Export, selection, nil
}

func instrumentationExportNMOutput(output, archive, directory string) string {
	// nm prints the invoked archive path verbatim, but original Go object
	// source symbols follow objabi.AbsFile's slash convention on Windows.
	// Replace only these exact observed roots, not arbitrary whitespace or
	// unknown symbol names. The complete output grammar remains strict.
	return strings.NewReplacer(
		archive, "@export", filepath.ToSlash(archive), "@export",
		directory, "@marker", filepath.ToSlash(directory), "@marker",
	).Replace(output)
}

func validateInstrumentationExportNM(output string, mode InstrumentationMode) error {
	if !strings.HasSuffix(output, "\n") || strings.ContainsAny(output, "\x00\r") {
		return fmt.Errorf("actual export nm output is incomplete or malformed")
	}
	defined := 0
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		object, body, ok := strings.Cut(line, ":\t")
		if !ok || object != "@export(_go_.o)" && object != "@export(mode_"+string(mode)+".o)" {
			return fmt.Errorf("actual nm output contains an unrelated object or diagnostic")
		}
		fields := strings.Fields(body)
		if len(fields) == 1 && fields[0] == "U" || len(fields) == 2 && fields[0] == "U" {
			continue
		}
		if len(fields) != 3 || len(fields[1]) != 1 || !strings.Contains("TtRrDdBb?", fields[1]) {
			return fmt.Errorf("actual nm output has an unknown symbol grammar")
		}
		if _, err := strconv.ParseUint(fields[0], 16, 64); err != nil {
			return fmt.Errorf("actual nm output has an invalid symbol address")
		}
		if object == "@export(mode_"+string(mode)+".o)" && fields[1] == "T" && fields[2] == instrumentationExportModule+".marker" {
			defined++
		}
	}
	if defined != 1 {
		return fmt.Errorf("actual selected assembly does not define exactly one required marker symbol")
	}
	return nil
}

func instrumentationExportToolsMatch(actual *discoveryFeatureToolState, bound *InstrumentationToolState) bool {
	return bound != nil && equalDiscoveryFeatureToolStates(actual, &discoveryFeatureToolState{
		directory: bound.Directory, digests: bound.BinarySHA256, origins: bound.BinaryOrigins,
		routing: bound.RoutingSHA256, dispatcher: bound.DispatcherSHA256,
	})
}

func recheckInstrumentationExportEnvironment(actual, commandContext map[string]string, early *InstrumentationEarlyObservation) error {
	portable := copyInstrumentationHashes(actual)
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOCACHE"} {
		delete(portable, key)
	}
	if !reflect.DeepEqual(portable, early.Environment) || !reflect.DeepEqual(commandContext, early.CommandContext) {
		return fmt.Errorf("actual export environment differs from its independently captured mode")
	}
	return nil
}

func recheckInstrumentationExportInputs(ctx context.Context, binary, directory string, env []string, actual, commandContext map[string]string, early *InstrumentationEarlyObservation, files map[string][]byte, archive, archiveSHA string, before *discoveryFeatureToolState, run Runner) error {
	after, afterContext, err := instrumentationObserverEnvironment(ctx, binary, directory, env, run)
	if err != nil || !reflect.DeepEqual(actual, after) || !reflect.DeepEqual(commandContext, afterContext) {
		return fmt.Errorf("actual instrumentation environment changed during export")
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(sources, early.SourceRules) {
		return fmt.Errorf("actual instrumentation source changed during export")
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual, run)
	if err != nil {
		return fmt.Errorf("actual mode compiler/assembler/nm/vet routing reobservation failed during export: %w", err)
	}
	if !equalDiscoveryFeatureToolStates(before, tools) {
		difference, err := instrumentationExportToolDifference(before, tools)
		if err != nil {
			return fmt.Errorf("actual mode compiler/assembler/nm/vet routing changed during export; summarize bound states: %w", err)
		}
		return fmt.Errorf("actual mode compiler/assembler/nm/vet routing changed during export: %s", difference)
	}
	if hash, err := FileSHA256(binary); err != nil || hash != early.BaselineFeatures.DriverSHA256 {
		return fmt.Errorf("actual driver changed during export")
	}
	for name, before := range early.BaselineFeatures.ToolSourceSHA256 {
		if hash, err := FileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(name))); err != nil || hash != before {
			return fmt.Errorf("actual CPU/experiment source changed during export: %s", name)
		}
	}
	if hash, err := FileSHA256(archive); err != nil || hash != archiveSHA {
		return fmt.Errorf("actual export archive changed during nm/asmdecl")
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(files) {
		return fmt.Errorf("actual export marker inventory changed during compilation")
	}
	for name, data := range files {
		if hash, err := FileSHA256(filepath.Join(directory, name)); err != nil || hash != bytesSHA256(data) {
			return fmt.Errorf("actual export marker source changed during compilation: %s", name)
		}
	}
	return nil
}
