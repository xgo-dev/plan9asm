package gotoolprofile

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// This is a deliberately finite, no-import Go 1.27 marker build trace, not a
// parser that treats arbitrary -x stderr as commands. A changed driver trace,
// an additional package/command or any warning fails closed. Original package
// exporters must retain their own dependency/source observations separately.
var instrumentationActionID = regexp.MustCompile(` -buildid ([A-Za-z0-9_-]+)/([A-Za-z0-9_-]+) `)
var instrumentationThreads = regexp.MustCompile(` -c=([0-9]+) `)

type InstrumentationExportRouting struct {
	Protocol            string                            `json:"protocol"`
	CanonicalTrace      string                            `json:"canonical_trace"`
	TraceSHA256         string                            `json:"trace_sha256"`
	CompilerConcurrency int                               `json:"compiler_concurrency"`
	AssemblerDefines    []string                          `json:"assembler_defines"`
	CommandEnvironment  []string                          `json:"command_environment"`
	EnvironmentSource   *InstrumentationExportEnvironment `json:"environment_source"`
}

func captureInstrumentationExportRouting(trace []byte, root, markerDir, archive string, tools *InstrumentationToolState, plan *InstrumentationBuildPlan, defines []string, environment *InstrumentationExportEnvironment, actual map[string]string) (*InstrumentationExportRouting, error) {
	commandEnvironment, err := instrumentationExportCommandEnvironment(environment, actual, plan)
	if err != nil {
		return nil, err
	}
	if len(defines) < 2 {
		return nil, fmt.Errorf("export trace lacks complete actual OS/architecture definitions")
	}
	if len(trace) == 0 || len(trace) > commandOutputLimit || !strings.HasSuffix(string(trace), "\n") || strings.ContainsAny(string(trace), "\x00\r") {
		return nil, fmt.Errorf("missing, malformed or over-bound actual export command trace")
	}
	lines := strings.Split(strings.TrimSuffix(string(trace), "\n"), "\n")
	if !strings.HasPrefix(lines[0], "WORK=") {
		return nil, fmt.Errorf("export trace lacks its actual stock Go work directory")
	}
	paths, err := instrumentationExportPhysicalTracePaths(strings.TrimPrefix(lines[0], "WORK="), root, markerDir, archive, tools)
	if err != nil {
		return nil, err
	}
	observed := string(trace)
	ids := instrumentationActionID.FindAllStringSubmatch(observed, -1)
	if len(ids) != 1 || ids[0][1] != ids[0][2] {
		return nil, fmt.Errorf("actual export compiler trace has missing or inconsistent action identity")
	}
	observed = instrumentationActionID.ReplaceAllString(observed, " -buildid @action/@action ")
	concurrency := 1
	threads := instrumentationThreads.FindAllStringSubmatch(observed, -1)
	if len(threads) > 1 {
		return nil, fmt.Errorf("duplicated export compiler concurrency")
	}
	if len(threads) == 1 {
		var err error
		concurrency, err = strconv.Atoi(threads[0][1])
		if err != nil || concurrency < 2 || concurrency > 256 {
			return nil, fmt.Errorf("invalid actual export compiler concurrency")
		}
	}
	if observed != instrumentationRenderedExportTrace(plan, defines, concurrency, commandEnvironment, paths) {
		return nil, fmt.Errorf("actual export did not execute the exact source-bound host command display/routing")
	}
	canonical := instrumentationExpectedExportTrace(plan, defines, concurrency, commandEnvironment)
	proof := &InstrumentationExportRouting{
		Protocol: "actual_go_instrumentation_marker_export_routing_v2", CanonicalTrace: canonical,
		TraceSHA256: bytesSHA256([]byte(canonical)), CompilerConcurrency: concurrency,
		AssemblerDefines:   append([]string(nil), defines...),
		CommandEnvironment: commandEnvironment, EnvironmentSource: environment,
	}
	if err := validateInstrumentationExportRouting(proof, plan, defines, actual); err != nil {
		return nil, err
	}
	return proof, nil
}

func validateInstrumentationExportRouting(proof *InstrumentationExportRouting, plan *InstrumentationBuildPlan, defines []string, actual map[string]string) error {
	if proof == nil || proof.Protocol != "actual_go_instrumentation_marker_export_routing_v2" || plan == nil ||
		len(defines) < 2 ||
		len(proof.CanonicalTrace) > commandOutputLimit || proof.CompilerConcurrency < 1 || proof.CompilerConcurrency > 256 ||
		!equalDiscoveryStrings(proof.AssemblerDefines, defines) || proof.TraceSHA256 != bytesSHA256([]byte(proof.CanonicalTrace)) {
		return fmt.Errorf("incomplete actual instrumentation export routing evidence")
	}
	environment, err := instrumentationExportCommandEnvironment(proof.EnvironmentSource, actual, plan)
	if err != nil || !equalDiscoveryStrings(proof.CommandEnvironment, environment) {
		return fmt.Errorf("marker export command environment is not bound to its actual SDK/target: %v", err)
	}
	if proof.CanonicalTrace != instrumentationExpectedExportTrace(plan, defines, proof.CompilerConcurrency, environment) {
		return fmt.Errorf("actual export did not execute the complete expected same-mode compiler/assembler routing")
	}
	return nil
}

func instrumentationExpectedExportTrace(plan *InstrumentationBuildPlan, defines []string, concurrency int, environment []string) string {
	mode := string(plan.Mode)
	prefix := instrumentationExportCommandPrefix(environment)
	base := prefix + "@asm -p " + instrumentationExportModule + ` -trimpath "$WORK/b001=>" -I $WORK/b001/ -I @include`
	// asmArgs emits OS/architecture first, then build-mode flags, then
	// architecture-level CPU definitions. Shared AMD64 must not silently
	// normalize a different order into the same observed command.
	for _, define := range defines[:2] {
		base += " -D " + define
	}
	for _, flag := range plan.CodegenFlags {
		base += " " + flag
	}
	for _, define := range defines[2:] {
		base += " -D " + define
	}
	installSuffix := mode
	if plan.InstrumentAdjustedBuildMode == "pie" && len(plan.CodegenFlags) == 1 {
		installSuffix += "_" + strings.TrimPrefix(plan.CodegenFlags[0], "-")
	}
	compile := prefix + `@compile -o $WORK/b001/_pkg_.a -trimpath "$WORK/b001=>" -p ` + instrumentationExportModule +
		" -lang=go1.20 -installsuffix " + installSuffix + " -buildid @action/@action -goversion " + plan.GoVersion +
		" -symabis $WORK/b001/symabis"
	if concurrency > 1 {
		compile += " -c=" + strconv.Itoa(concurrency)
	}
	for _, flag := range plan.CodegenFlags {
		compile += " " + flag
	}
	compile += " -" + mode + " -nolocalimports -importcfg $WORK/b001/importcfg -pack -asmhdr $WORK/b001/go_asm.h ./base.go ./mode_" + mode + ".go"
	return strings.Join([]string{
		"WORK=@work", "mkdir -p $WORK/b001/", "echo -n > $WORK/b001/go_asm.h # internal", "cd @marker",
		base + " -gensymabis -o $WORK/b001/symabis ./mode_" + mode + ".s",
		"echo '# import config' > $WORK/b001/importcfg # internal", compile,
		base + " -o $WORK/b001/mode_" + mode + ".o ./mode_" + mode + ".s",
		"go tool pack r $WORK/b001/_pkg_.a $WORK/b001/mode_" + mode + ".o # internal",
		"go tool buildid -w $WORK/b001/_pkg_.a # internal", "cp $WORK/b001/_pkg_.a @export # internal",
	}, "\n") + "\n"
}
