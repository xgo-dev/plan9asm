package gotoolprofile

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

const InstrumentationTargetExclusionProtocol = "actual_go_instrumentation_tagged_target_exclusion_v1"

// InstrumentationTargetExclusion is a distinct, zero-object mode-scope witness.
// Early retains its unchanged v1 command. CommandArgs records the additional
// actual command with this source requirement's exact canonical custom tags.
// Neither observation is an original-package export or LLVM object proof.
type InstrumentationTargetExclusion struct {
	Protocol     string                           `json:"protocol"`
	Early        *InstrumentationEarlyObservation `json:"early"`
	CustomTags   []string                         `json:"custom_tags,omitempty"`
	CommandArgs  []string                         `json:"command_args"`
	ExitCode     int                              `json:"exit_code"`
	StdoutSHA256 string                           `json:"stdout_sha256"`
	Stderr       string                           `json:"stderr"`
}

func CaptureInstrumentationScopeObservation(ctx context.Context, binary, ownedDir string, env []string, target string, mode InstrumentationMode, cgo string, overrides map[string]string, tags []string, run Runner) (*InstrumentationEarlyObservation, *InstrumentationTargetExclusion, error) {
	early, err := CaptureInstrumentationEarlyObservation(ctx, binary, ownedDir, env, target, mode, cgo, overrides, run)
	if err != nil {
		return nil, nil, err
	}
	if err := validateInstrumentationScopeTags(tags, early); err != nil {
		return nil, nil, err
	}
	if early.Status == InstrumentationEarlyRuleAccepted {
		return early, nil, nil
	}
	dir := filepath.Join(ownedDir, "mode")
	replacements := copyInstrumentationHashes(early.BaselineFeatures.Environment)
	replacements["GOENV"] = "off"
	delete(replacements, "GOVERSION")
	replacements["CGO_ENABLED"], replacements["GOTOOLCHAIN"] = cgo, "local"
	replacements["GOWORK"], replacements["GOFLAGS"], replacements["GOPACKAGESDRIVER"] = "off", "", "off"
	modeEnv := replaceEnv(env, replacements)
	if err := recheckInstrumentationTargetExclusion(ctx, binary, dir, modeEnv, early, run); err != nil {
		return nil, nil, err
	}
	args := instrumentationTargetExclusionArgs(early.BuildFlags, tags)
	stdout, stderr, commandErr := run(ctx, dir, modeEnv, binary, args...)
	rules, err := ReplayInstrumentationSourceProof(early.SourceRules)
	if err != nil {
		return nil, nil, err
	}
	status, err := ClassifyInstrumentationEarlyResult(rules, target, mode, stdout, stderr, commandErr)
	if err != nil || status != InstrumentationOfficialTargetUnsupported {
		return nil, nil, fmt.Errorf("tagged instrumentation target rule is not the exact registered refusal: %v", err)
	}
	if err := recheckInstrumentationTargetExclusion(ctx, binary, dir, modeEnv, early, run); err != nil {
		return nil, nil, err
	}
	proof := &InstrumentationTargetExclusion{
		Protocol: InstrumentationTargetExclusionProtocol, Early: early,
		CustomTags: append([]string(nil), tags...), CommandArgs: args,
		ExitCode: 2, StdoutSHA256: bytesSHA256(stdout), Stderr: string(stderr),
	}
	if err := ValidateInstrumentationTargetExclusion(proof, tags); err != nil {
		return nil, nil, err
	}
	return early, proof, nil
}

func instrumentationTargetExclusionArgs(flags, tags []string) []string {
	args := append([]string{"list", "-find", "-json", "-mod=readonly"}, flags...)
	if len(tags) != 0 {
		args = append(args, "-tags="+strings.Join(tags, ","))
	}
	return append(args, ".")
}

func validateInstrumentationScopeTags(tags []string, early *InstrumentationEarlyObservation) error {
	if early == nil || early.BaselineFeatures == nil {
		return fmt.Errorf("mode scope tags lack the actual builtin foundation")
	}
	copy := *early
	copy.MarkerSelection = early.BaselineFeatures.MarkerSelection
	return validateInstrumentationCustomTags(tags, &copy)
}

func ValidateInstrumentationTargetExclusion(proof *InstrumentationTargetExclusion, tags []string) error {
	if proof == nil || proof.Protocol != InstrumentationTargetExclusionProtocol {
		return fmt.Errorf("missing tagged official target-exclusion protocol")
	}
	if err := ValidateInstrumentationEarlyObservation(proof.Early); err != nil {
		return err
	}
	if err := validateInstrumentationScopeTags(tags, proof.Early); err != nil {
		return err
	}
	if proof.Early.Status != InstrumentationOfficialTargetUnsupported ||
		!equalDiscoveryStrings(tags, proof.CustomTags) ||
		!reflect.DeepEqual(proof.CommandArgs, instrumentationTargetExclusionArgs(proof.Early.BuildFlags, tags)) ||
		proof.ExitCode != 2 || proof.StdoutSHA256 != bytesSHA256(nil) || proof.Stderr != proof.Early.Stderr {
		return fmt.Errorf("official target exclusion lacks the exact tagged Exit2/empty-output/unique diagnostic")
	}
	return nil
}

func recheckInstrumentationTargetExclusion(ctx context.Context, binary, dir string, env []string, early *InstrumentationEarlyObservation, run Runner) error {
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, dir, env, run)
	if err != nil || !reflect.DeepEqual(commandContext, early.CommandContext) {
		return fmt.Errorf("tagged target-rule command context changed: %v", err)
	}
	portable := copyInstrumentationHashes(actual)
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOCACHE"} {
		delete(portable, key)
	}
	if !reflect.DeepEqual(portable, early.Environment) {
		return fmt.Errorf("tagged target-rule actual mode environment changed")
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(sources, early.SourceRules) {
		return fmt.Errorf("tagged target-rule complete source registration changed: %v", err)
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, env, actual, run)
	if err != nil {
		return err
	}
	state := &InstrumentationToolState{Directory: tools.directory, BinarySHA256: tools.digests,
		BinaryOrigins: tools.origins, RoutingSHA256: tools.routing, DispatcherSHA256: tools.dispatcher}
	if !reflect.DeepEqual(state, early.ModeTools) {
		return fmt.Errorf("tagged target-rule actual subtool routing/bytes changed")
	}
	if digest, err := FileSHA256(binary); err != nil || digest != early.BaselineFeatures.DriverSHA256 {
		return fmt.Errorf("tagged target-rule actual Go driver changed: %v", err)
	}
	for name, before := range early.BaselineFeatures.ToolSourceSHA256 {
		if digest, err := FileSHA256(filepath.Join(actual["GOROOT"], filepath.FromSlash(name))); err != nil || digest != before {
			return fmt.Errorf("tagged target-rule builtin source changed: %s: %v", name, err)
		}
	}
	files := MarkerFiles(instrumentationObserverTags(early.BaselineFeatures))
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != len(files) {
		return fmt.Errorf("tagged target-rule marker inventory changed: %v", err)
	}
	for name, content := range files {
		file := filepath.Join(dir, name)
		info, err := os.Lstat(file)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("tagged target-rule marker is not a regular original source: %s", name)
		}
		if digest, err := FileSHA256(file); err != nil || digest != bytesSHA256(content) {
			return fmt.Errorf("tagged target-rule marker source changed: %s: %v", name, err)
		}
	}
	return nil
}
