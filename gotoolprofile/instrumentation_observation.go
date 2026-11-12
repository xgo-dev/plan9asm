package gotoolprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

const instrumentationEarlyObservationProtocol = "actual_go_instrumentation_early_observation_v2"

// InstrumentationEarlyObservation proves only stock Go's early target rule
// and finite marker selection under one real mode. It is deliberately not an
// export, compiler, sanitizer-runtime or original-source exclusion proof.
// BaselineFeatures supplies CPU/experiment provenance only: its CGO=0 marker
// selection never impersonates this mode's separately observed environment.
type InstrumentationEarlyObservation struct {
	Protocol              string                      `json:"protocol"`
	Target                string                      `json:"target"`
	Mode                  InstrumentationMode         `json:"mode"`
	CGOEnabled            string                      `json:"cgo_enabled"`
	BuildFlags            []string                    `json:"build_flags"`
	BaselineFeatures      *Observation                `json:"baseline_cpu_features"`
	ModeTools             *InstrumentationToolState   `json:"mode_tools"`
	SourceRules           *InstrumentationSourceProof `json:"source_rules"`
	Environment           map[string]string           `json:"environment"`
	CommandContext        map[string]string           `json:"command_context"`
	EnvironmentSHA256     string                      `json:"environment_sha256"`
	ContextSHA256         string                      `json:"context_sha256"`
	CommandArgs           []string                    `json:"command_args"`
	ExitCode              int                         `json:"exit_code"`
	DriverSelectionSHA256 string                      `json:"driver_selection_sha256"`
	Stderr                string                      `json:"stderr"`
	Status                InstrumentationEarlyStatus  `json:"status"`
	MarkerSelection       map[string]bool             `json:"marker_selection"`
	MarkerSourceSHA256    string                      `json:"marker_source_sha256"`
}

type InstrumentationToolState struct {
	Directory        string            `json:"directory"`
	BinarySHA256     map[string]string `json:"binary_sha256"`
	BinaryOrigins    map[string]string `json:"binary_origins"`
	RoutingSHA256    string            `json:"routing_sha256"`
	DispatcherSHA256 string            `json:"dispatcher_sha256"`
}

func InstrumentationEarlyProfileID(observed *InstrumentationEarlyObservation) string {
	if observed == nil {
		return ""
	}
	data, _ := json.Marshal(observed)
	return bytesSHA256(data)
}

func CaptureInstrumentationEarlyObservation(ctx context.Context, binary, ownedDir string, env []string, target string, mode InstrumentationMode, cgo string, overrides map[string]string, run Runner) (*InstrumentationEarlyObservation, error) {
	if ctx == nil || ctx.Err() != nil || run == nil {
		return nil, fmt.Errorf("instrumentation observer requires a live context and bounded runner")
	}
	flags, err := InstrumentationBuildFlags(mode)
	if err != nil {
		return nil, err
	}
	if cgo != "0" && cgo != "1" {
		return nil, fmt.Errorf("instrumentation observer requires explicit CGO=0 or CGO=1")
	}
	// An actual mode observation owns its configuration. Do not silently
	// read a private user go/env file, even when every CPU override is empty.
	env = replaceEnv(env, map[string]string{"GOENV": "off"})
	if !filepath.IsAbs(binary) || !filepath.IsAbs(ownedDir) {
		return nil, fmt.Errorf("instrumentation driver and owned directory must be absolute")
	}
	ownedDir, err = sourcepath.Resolve(ownedDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(ownedDir)
	if err != nil || len(entries) != 0 {
		return nil, fmt.Errorf("instrumentation observer directory must exist and be empty")
	}
	baselineDir, markerDir := filepath.Join(ownedDir, "baseline"), filepath.Join(ownedDir, "mode")
	for _, dir := range []string{baselineDir, markerDir} {
		if err := os.Mkdir(dir, 0700); err != nil {
			return nil, err
		}
	}
	baseline, err := Capture(ctx, binary, baselineDir, env, target, overrides, run)
	if err != nil {
		return nil, err
	}
	if err := Validate(baseline); err != nil {
		return nil, err
	}
	replacements := copyInstrumentationHashes(baseline.Environment)
	delete(replacements, "GOVERSION")
	replacements["CGO_ENABLED"], replacements["GOTOOLCHAIN"] = cgo, "local"
	replacements["GOWORK"], replacements["GOFLAGS"], replacements["GOPACKAGESDRIVER"] = "off", "", "off"
	modeEnv := replaceEnv(env, replacements)
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, markerDir, modeEnv, run)
	if err != nil {
		return nil, err
	}
	beforeTools, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil {
		return nil, err
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil {
		return nil, err
	}
	rules, err := ReplayInstrumentationSourceProof(sources)
	if err != nil {
		return nil, err
	}
	tags := instrumentationObserverTags(baseline)
	files := MarkerFiles(tags)
	for name, contents := range files {
		file, err := os.OpenFile(filepath.Join(markerDir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.Write(contents)
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return nil, fmt.Errorf("write instrumentation marker: %v (close: %v)", writeErr, closeErr)
		}
	}
	args := append([]string{"list", "-find", "-json", "-mod=readonly"}, flags...)
	args = append(args, ".")
	stdout, stderr, commandErr := run(ctx, markerDir, modeEnv, binary, args...)
	status, err := ClassifyInstrumentationEarlyResult(rules, target, mode, stdout, stderr, commandErr)
	if err != nil {
		return nil, err
	}
	observed := &InstrumentationEarlyObservation{
		Protocol: instrumentationEarlyObservationProtocol, Target: target, Mode: mode,
		CGOEnabled: cgo, BuildFlags: flags, BaselineFeatures: baseline, SourceRules: sources,
		ModeTools: &InstrumentationToolState{
			Directory: beforeTools.directory, BinarySHA256: beforeTools.digests, BinaryOrigins: beforeTools.origins,
			RoutingSHA256: beforeTools.routing, DispatcherSHA256: beforeTools.dispatcher,
		},
		CommandContext: commandContext, CommandArgs: args,
		Stderr: string(stderr), Status: status, MarkerSourceSHA256: MarkerSHA256(files),
	}
	if status == InstrumentationEarlyRuleAccepted {
		observed.MarkerSelection, err = DecodeMarkers(stdout, markerDir, tags)
		if err != nil {
			return nil, err
		}
		// Keep the complete decoded marker selection, not the private
		// package Dir embedded in raw JSON. Reobservers own different
		// marker directories but must produce this same portable identity.
		observed.DriverSelectionSHA256 = instrumentationObjectSHA(observed.MarkerSelection)
	} else {
		observed.ExitCode = 2
		observed.DriverSelectionSHA256 = bytesSHA256(nil)
	}
	after, afterContext, err := instrumentationObserverEnvironment(ctx, binary, markerDir, modeEnv, run)
	if err != nil || !reflect.DeepEqual(actual, after) || !reflect.DeepEqual(commandContext, afterContext) {
		return nil, fmt.Errorf("actual mode environment or command context changed during observation")
	}
	afterSources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(sources, afterSources) {
		return nil, fmt.Errorf("instrumentation source rules changed during observation")
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil || !equalDiscoveryFeatureToolStates(beforeTools, tools) {
		return nil, fmt.Errorf("actual driver subtool identity changed during instrumentation observation")
	}
	if hash, err := FileSHA256(binary); err != nil || hash != baseline.DriverSHA256 {
		return nil, fmt.Errorf("actual driver changed during instrumentation observation")
	}
	for name, before := range baseline.ToolSourceSHA256 {
		if hash, err := FileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(name))); err != nil || hash != before {
			return nil, fmt.Errorf("actual CPU/experiment source changed during instrumentation observation: %s", name)
		}
	}
	entries, err = os.ReadDir(markerDir)
	if err != nil || len(entries) != len(files) {
		return nil, fmt.Errorf("instrumentation marker inventory changed during observation")
	}
	for name, contents := range files {
		if hash, err := FileSHA256(filepath.Join(markerDir, name)); err != nil || hash != bytesSHA256(contents) {
			return nil, fmt.Errorf("instrumentation marker source changed during observation")
		}
	}
	observed.Environment = copyInstrumentationHashes(actual)
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOCACHE"} {
		delete(observed.Environment, key)
	}
	observed.EnvironmentSHA256 = instrumentationObjectSHA(observed.Environment)
	observed.ContextSHA256 = instrumentationObjectSHA(commandContext)
	if err := ValidateInstrumentationEarlyObservation(observed); err != nil {
		return nil, err
	}
	return observed, nil
}

func instrumentationObserverEnvironment(ctx context.Context, binary, dir string, env []string, run Runner) (map[string]string, map[string]string, error) {
	keys := append(append([]string(nil), discoveryFeatureEnvKeys...), "CC", "CXX", "GOFLAGS", "GODEBUG", "GOENV")
	args := append([]string{"env", "-json"}, keys...)
	stdout, stderr, err := run(ctx, dir, env, binary, args...)
	if err != nil || len(stderr) != 0 {
		return nil, nil, fmt.Errorf("actual instrumentation environment query failed or emitted unregistered diagnostics: %v", err)
	}
	var actual map[string]string
	if err := json.Unmarshal(stdout, &actual); err != nil || len(actual) != len(keys) {
		return nil, nil, fmt.Errorf("incomplete actual instrumentation environment query")
	}
	commandContext := make(map[string]string)
	for _, key := range []string{"CC", "CXX", "GOFLAGS", "GODEBUG", "GOENV"} {
		value, present := actual[key]
		if !present {
			return nil, nil, fmt.Errorf("missing actual instrumentation command context %s", key)
		}
		commandContext[key] = value
		delete(actual, key)
	}
	return actual, commandContext, nil
}

func ValidateInstrumentationEarlyObservation(observed *InstrumentationEarlyObservation) error {
	if observed == nil || observed.Protocol != instrumentationEarlyObservationProtocol {
		return fmt.Errorf("missing actual instrumentation early-observation protocol")
	}
	if err := Validate(observed.BaselineFeatures); err != nil {
		return err
	}
	base := observed.BaselineFeatures
	if err := validateInstrumentationModeTools(observed.ModeTools, base); err != nil {
		return err
	}
	rules, err := ReplayInstrumentationSourceProof(observed.SourceRules)
	if err != nil {
		return err
	}
	flags, err := InstrumentationBuildFlags(observed.Mode)
	if err != nil || !reflect.DeepEqual(flags, observed.BuildFlags) || observed.Target != base.Target ||
		observed.SourceRules.GoVersion != base.GoVersion || observed.SourceRules.SourceSHA256["VERSION"] != base.ToolSourceSHA256["VERSION"] {
		return fmt.Errorf("mode/source/actual driver identity differs from the complete CPU foundation")
	}
	if observed.CGOEnabled != "0" && observed.CGOEnabled != "1" || len(observed.Environment) != len(base.Environment) {
		return fmt.Errorf("incomplete or unobserved instrumentation environment")
	}
	for key, wanted := range base.Environment {
		if key == "CGO_ENABLED" {
			wanted = observed.CGOEnabled
		}
		if actual, present := observed.Environment[key]; !present || actual != wanted {
			return fmt.Errorf("mode observer differs from its CPU foundation: %s", key)
		}
	}
	// Stock Go reports an empty configuration filename for explicit GOENV=off.
	if len(observed.CommandContext) != 5 || observed.CommandContext["GOFLAGS"] != "" || observed.CommandContext["GOENV"] != "" {
		return fmt.Errorf("missing or arbitrary instrumentation command context")
	}
	for _, key := range []string{"CC", "CXX", "GOFLAGS", "GODEBUG", "GOENV"} {
		if _, present := observed.CommandContext[key]; !present {
			return fmt.Errorf("missing actual instrumentation command context %s", key)
		}
	}
	if observed.EnvironmentSHA256 != instrumentationObjectSHA(observed.Environment) || observed.ContextSHA256 != instrumentationObjectSHA(observed.CommandContext) {
		return fmt.Errorf("mode environment/context no longer matches its captured digest")
	}
	wantedArgs := append([]string{"list", "-find", "-json", "-mod=readonly"}, flags...)
	wantedArgs = append(wantedArgs, ".")
	tags := instrumentationObserverTags(base)
	if !reflect.DeepEqual(observed.CommandArgs, wantedArgs) || observed.MarkerSourceSHA256 != MarkerSHA256(MarkerFiles(tags)) ||
		!discoverySHA256Pattern.MatchString(observed.DriverSelectionSHA256) {
		return fmt.Errorf("missing exact instrumentation early invocation or complete marker inputs")
	}
	supported, err := rules.TargetSupported(observed.Target, observed.Mode)
	if err != nil {
		return err
	}
	if !supported {
		wantedStderr := fmt.Sprintf("-%s is not supported on %s\n", observed.Mode, observed.Target)
		if observed.Status != InstrumentationOfficialTargetUnsupported || observed.ExitCode != 2 || observed.Stderr != wantedStderr ||
			observed.DriverSelectionSHA256 != bytesSHA256(nil) || len(observed.MarkerSelection) != 0 {
			return fmt.Errorf("unsupported rule requires one exact complete actual Exit2 observation")
		}
		return nil
	}
	if observed.Status != InstrumentationEarlyRuleAccepted || observed.ExitCode != 0 || observed.Stderr != "" || len(observed.MarkerSelection) != len(tags) {
		return fmt.Errorf("eligible early mode observation is incomplete or has unregistered diagnostics")
	}
	if observed.DriverSelectionSHA256 != instrumentationObjectSHA(observed.MarkerSelection) {
		return fmt.Errorf("actual complete marker selection changed after observation")
	}
	if required, err := rules.RequiresCGO(observed.Target, observed.Mode); err != nil || required && observed.CGOEnabled != "1" {
		return fmt.Errorf("eligible early mode is missing the source-required CGO prerequisite")
	}
	for _, tag := range tags {
		wanted, isBuiltin := base.MarkerSelection[tag]
		if !isBuiltin {
			wanted = tag == string(observed.Mode)
		}
		if actual, present := observed.MarkerSelection[tag]; !present || actual != wanted {
			return fmt.Errorf("actual mode marker selection contradicts the requested mode or CPU/experiment: %s", tag)
		}
	}
	return nil
}

func instrumentationObserverTags(baseline *Observation) []string {
	tags := []string{"race", "msan", "asan"}
	for tag := range baseline.MarkerSelection {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	return tags
}

func validateInstrumentationModeTools(tools *InstrumentationToolState, baseline *Observation) error {
	if tools == nil || tools.Directory != baseline.ToolDirectory || tools.DispatcherSHA256 != baseline.ToolDispatcherSHA256 ||
		!discoverySHA256Pattern.MatchString(tools.RoutingSHA256) {
		return fmt.Errorf("missing independently observed mode tool routing/dispatcher identity")
	}
	copy := *baseline
	// Reuse only the common tool-origin/digest grammar. This temporary value
	// is never returned as a CGO=0 observation of the mode's builtin tools.
	copy.ToolBinarySHA256, copy.ToolBinaryOrigins = tools.BinarySHA256, tools.BinaryOrigins
	copy.ToolRoutingSHA256, copy.ToolDispatcherSHA256 = tools.RoutingSHA256, tools.DispatcherSHA256
	if err := Validate(&copy); err != nil {
		return err
	}
	for _, name := range discoveryFeatureSubtools {
		origin := tools.BinaryOrigins[name]
		if origin != baseline.ToolBinaryOrigins[name] ||
			strings.HasPrefix(origin, "goroot/") && tools.BinarySHA256[name] != baseline.ToolBinarySHA256[name] {
			return fmt.Errorf("mode observer used different installed Go %s tools", name)
		}
	}
	return nil
}

func instrumentationObjectSHA(value any) string {
	data, _ := json.Marshal(value)
	return bytesSHA256(data)
}
