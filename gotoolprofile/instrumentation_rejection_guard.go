package gotoolprofile

import (
	"context"
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// Private to one actual bounded rejection invocation. It never memoizes a
// successful source/tool check or supplies permissions to another consumer.
type instrumentationRejectionGuard struct {
	binary, directory string
	sourceRoot        string
	env               []string
	input             *ConsumerInput
	marker            *InstrumentationExportObservation
	run               Runner
	configs           map[string]string
	actual            map[string]string
	commandContext    map[string]string
	tools             *discoveryFeatureToolState
}

func newInstrumentationRejectionGuard(ctx context.Context, binary, directory string, env []string, input *ConsumerInput, marker *InstrumentationExportObservation, run Runner) (*instrumentationRejectionGuard, error) {
	directory, err := sourcepath.Resolve(directory)
	if err != nil {
		return nil, err
	}
	if err := recheckInstrumentationOriginalSources(input); err != nil {
		return nil, err
	}
	sourceRoot, err := sourcepath.Resolve(input.SourceRoot)
	if err != nil {
		return nil, err
	}
	configs, err := captureInstrumentationInvocationConfig(directory)
	if err != nil {
		return nil, err
	}
	replacements := copyInstrumentationHashes(marker.Early.Environment)
	delete(replacements, "GOVERSION")
	replacements["GOTOOLCHAIN"], replacements["GOWORK"] = "local", "off"
	replacements["GOFLAGS"], replacements["GOPACKAGESDRIVER"], replacements["GOENV"] = "", "off", "off"
	modeEnv := replaceEnv(env, replacements)
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, directory, modeEnv, run)
	if err != nil {
		return nil, err
	}
	if err := recheckInstrumentationExportEnvironment(actual, commandContext, marker.Early); err != nil {
		return nil, err
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, modeEnv, actual, run)
	if err != nil || !instrumentationExportToolsMatch(tools, marker.Early.ModeTools) {
		return nil, fmt.Errorf("rejected-source actual tool routing differs from its mode observation: %v", err)
	}
	guard := &instrumentationRejectionGuard{
		binary: binary, directory: directory, sourceRoot: sourceRoot, env: modeEnv, input: input, marker: marker, run: run,
		configs: configs, actual: actual, commandContext: commandContext, tools: tools,
	}
	if err := guard.verify(ctx); err != nil {
		return nil, err
	}
	return guard, nil
}

func (guard *instrumentationRejectionGuard) verify(ctx context.Context) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	sourceRoot, err := sourcepath.Resolve(guard.input.SourceRoot)
	if err != nil || sourceRoot != guard.sourceRoot {
		return fmt.Errorf("rejected-source original physical root changed")
	}
	if err := recheckInstrumentationOriginalSources(guard.input); err != nil {
		return err
	}
	configs, err := captureInstrumentationInvocationConfig(guard.directory)
	if err != nil || !reflect.DeepEqual(configs, guard.configs) {
		return fmt.Errorf("rejected-source invocation configuration changed: %v", err)
	}
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, guard.binary, guard.directory, guard.env, guard.run)
	if err != nil || !reflect.DeepEqual(actual, guard.actual) || !reflect.DeepEqual(commandContext, guard.commandContext) {
		return fmt.Errorf("rejected-source actual environment/configuration changed: %v", err)
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, guard.binary, guard.env, actual, guard.run)
	if err != nil || !equalDiscoveryFeatureToolStates(guard.tools, tools) {
		return fmt.Errorf("rejected-source actual compiler/assembler/tool routing changed: %v", err)
	}
	if digest, err := FileSHA256(guard.binary); err != nil || digest != guard.marker.Early.BaselineFeatures.DriverSHA256 {
		return fmt.Errorf("rejected-source actual driver changed")
	}
	rules, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil || !reflect.DeepEqual(rules, guard.marker.Early.SourceRules) {
		return fmt.Errorf("rejected-source actual mode source registrations changed: %v", err)
	}
	for _, hashes := range []map[string]string{guard.marker.Early.BaselineFeatures.ToolSourceSHA256, guard.input.ToolSources} {
		for file, wanted := range hashes {
			physical, err := CPPRegularSource(actual["GOROOT"], file)
			if err != nil {
				return err
			}
			if digest, err := FileSHA256(physical); err != nil || digest != wanted {
				return fmt.Errorf("rejected-source actual SDK source changed: %s", file)
			}
		}
	}
	// The original invocation is an existing owned directory; reject a late
	// redirect rather than using a different configuration with equal contents.
	resolved, err := sourcepath.Resolve(guard.directory)
	if err != nil || resolved != filepath.Clean(guard.directory) {
		return fmt.Errorf("rejected-source invocation directory was redirected")
	}
	return nil
}
