package gotoolprofile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func instrumentationExportEnvironmentFixture(t *testing.T) *InstrumentationExportEnvironment {
	t.Helper()
	data, err := os.ReadFile("testdata/instrumentation-export-environment-go1.27.1.json")
	if err != nil {
		t.Fatal(err)
	}
	var proof InstrumentationExportEnvironment
	if err := json.Unmarshal(data, &proof); err != nil {
		t.Fatal(err)
	}
	if err := validateInstrumentationExportEnvironment(&proof); err != nil {
		t.Fatal(err)
	}
	return &proof
}

func TestInstrumentationExportRoutingRejectsMissingMixedOrChangedCommands(t *testing.T) {
	plan := &InstrumentationBuildPlan{GoVersion: "go1.27.1", Target: "darwin/arm64", Mode: InstrumentationRace, CodegenFlags: []string{"-shared"}}
	defines := []string{"GOOS_darwin", "GOARCH_arm64"}
	actual := map[string]string{"GOOS": "darwin", "GOARCH": "arm64", "GOARM64": "v8.0"}
	original := &InstrumentationExportRouting{
		Protocol: "actual_go_instrumentation_marker_export_routing_v2", CompilerConcurrency: 2, AssemblerDefines: defines,
		CanonicalTrace:    instrumentationExpectedExportTrace(plan, defines, 2, nil),
		EnvironmentSource: instrumentationExportEnvironmentFixture(t),
	}
	original.TraceSHA256 = bytesSHA256([]byte(original.CanonicalTrace))
	if err := validateInstrumentationExportRouting(original, plan, defines, actual); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstrumentationExportRouting){
		"warning":     func(p *InstrumentationExportRouting) { p.CanonicalTrace += "go: unknown warning\n" },
		"mixed error": func(p *InstrumentationExportRouting) { p.CanonicalTrace += "# failed-package\nmissing SDK\n" },
		"no compiler": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, "@compile", "@fake", 1)
		},
		"wrong compiler": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, "@compile", "/unrelated/compile", 1)
		},
		"ordinary compiler": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, " -race ", " ", 1)
		},
		"mode as tag": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, " -race ", " -tags=race ", 1)
		},
		"two modes": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, " -race ", " -race -asan ", 1)
		},
		"ordinary asm": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.Replace(p.CanonicalTrace, " -shared ", " ", 1)
		},
		"fake mode source": func(p *InstrumentationExportRouting) {
			p.CanonicalTrace = strings.ReplaceAll(p.CanonicalTrace, "mode_race", "mode_asan")
		},
		"duplicate compiler": func(p *InstrumentationExportRouting) { p.CanonicalTrace += p.CanonicalTrace },
		"stale hash":         func(p *InstrumentationExportRouting) { p.TraceSHA256 = strings.Repeat("0", 64) },
		"changed defines":    func(p *InstrumentationExportRouting) { p.AssemblerDefines = append(p.AssemblerDefines, "RACE") },
		"missing protocol":   func(p *InstrumentationExportRouting) { p.Protocol = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := *original
			copy.AssemblerDefines = append([]string(nil), original.AssemblerDefines...)
			mutate(&copy)
			if name != "stale hash" {
				copy.TraceSHA256 = bytesSHA256([]byte(copy.CanonicalTrace))
			}
			if err := validateInstrumentationExportRouting(&copy, plan, defines, actual); err == nil {
				t.Fatal("accepted incomplete or mismatched same-mode export routing")
			}
		})
	}
}
