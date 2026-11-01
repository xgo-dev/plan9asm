package gotoolprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

// This fixture is Go 1.27.1's registered command display on a Windows SDK,
// not an observation that Windows tools or Windows runtime ran on this host.
// runOut quotes backslashes before fmtCmd substitutes both WORK spellings;
// ShowCmd does not replace a quoted absolute source argument with dot.
const instrumentationWindowsExportTrace = `WORK=C:\tmp\go-build1234
mkdir -p $WORK\b001\
echo -n > $WORK\b001\go_asm.h # internal
cd C:\owned task\export
GOAMD64='v2' "C:\\Go SDK\\pkg\\tool\\windows_amd64\\asm.exe" -p example.invalid/instrumentation-export -trimpath "$WORK\\b001=>" -I "$WORK\\b001\\" -I "C:\\Go SDK\\pkg\\include" -D GOOS_linux -D GOARCH_amd64 -D GOAMD64_v2 -gensymabis -o "$WORK\\b001\\symabis" "C:\\owned task\\export\\mode_race.s"
echo '# import config' > $WORK\b001\importcfg # internal
GOAMD64='v2' "C:\\Go SDK\\pkg\\tool\\windows_amd64\\compile.exe" -o "$WORK\\b001\\_pkg_.a" -trimpath "$WORK\\b001=>" -p example.invalid/instrumentation-export -lang=go1.20 -installsuffix race -buildid action/action -goversion go1.27.1 -symabis "$WORK\\b001\\symabis" -c=2 -race -nolocalimports -importcfg "$WORK\\b001\\importcfg" -pack -asmhdr "$WORK\\b001\\go_asm.h" "C:\\owned task\\export\\base.go" "C:\\owned task\\export\\mode_race.go"
GOAMD64='v2' "C:\\Go SDK\\pkg\\tool\\windows_amd64\\asm.exe" -p example.invalid/instrumentation-export -trimpath "$WORK\\b001=>" -I "$WORK\\b001\\" -I "C:\\Go SDK\\pkg\\include" -D GOOS_linux -D GOARCH_amd64 -D GOAMD64_v2 -o "$WORK\\b001\\mode_race.o" "C:\\owned task\\export\\mode_race.s"
go tool pack r "$WORK\\b001\\_pkg_.a" "$WORK\\b001\\mode_race.o" # internal
go tool buildid -w "$WORK\\b001\\_pkg_.a" # internal
cp "$WORK\\b001\\_pkg_.a" "C:\\cache root\\aa\\artifact-d" # internal
`

func instrumentationWindowsTraceInputs() (*InstrumentationToolState, *InstrumentationBuildPlan, []string, map[string]string) {
	tools := &InstrumentationToolState{
		Directory: "pkg/tool/windows_amd64",
		BinaryOrigins: map[string]string{
			"asm": "goroot/pkg/tool/windows_amd64/asm.exe", "compile": "goroot/pkg/tool/windows_amd64/compile.exe",
		},
	}
	plan := &InstrumentationBuildPlan{GoVersion: "go1.27.1", Target: "linux/amd64", Mode: InstrumentationRace}
	defines := []string{"GOOS_linux", "GOARCH_amd64", "GOAMD64_v2"}
	actual := map[string]string{"GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v2"}
	return tools, plan, defines, actual
}

func TestInstrumentationExportRoutingWindowsSourceBoundCommandDisplay(t *testing.T) {
	tools, plan, defines, actual := instrumentationWindowsTraceInputs()
	proof, err := captureInstrumentationExportRouting([]byte(instrumentationWindowsExportTrace), `C:\Go SDK`,
		`C:\owned task\export`, `C:\cache root\aa\artifact-d`, tools, plan, defines,
		instrumentationExportEnvironmentFixture(t), actual)
	if err != nil {
		t.Fatal(err)
	}
	expected := instrumentationExpectedExportTrace(plan, defines, 2, []string{"GOAMD64=v2"})
	if proof.CanonicalTrace != expected {
		t.Fatal("Windows display did not retain the exact portable command/target/mode denominator")
	}
	data, err := json.MarshalIndent(proof, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	var replay InstrumentationExportRouting
	if err := json.Unmarshal(data, &replay); err != nil {
		t.Fatal(err)
	}
	if err := validateInstrumentationExportRouting(&replay, plan, defines, actual); err != nil {
		t.Fatal(err)
	}
}

func TestInstrumentationExportRoutingWindowsDisplayKeepsUnknownOutputFailed(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"unknown tool":              func(trace string) string { return strings.ReplaceAll(trace, "asm.exe", "unknown.exe") },
		"missing host suffix":       func(trace string) string { return strings.ReplaceAll(trace, "compile.exe", "compile") },
		"wrong host root":           func(trace string) string { return strings.ReplaceAll(trace, `C:\\Go SDK`, `D:\\Go SDK`) },
		"wrong host tool directory": func(trace string) string { return strings.ReplaceAll(trace, "windows_amd64", "linux_amd64") },
		"unregistered quoting": func(trace string) string {
			return strings.ReplaceAll(trace, `"C:\\Go SDK\\pkg\\tool\\windows_amd64\\compile.exe"`, `'C:\Go SDK\pkg\tool\windows_amd64\compile.exe'`)
		},
		"quoted unknown operand": func(trace string) string {
			return strings.ReplaceAll(trace, `"C:\\owned task\\export\\base.go"`, `"C:\\owned task\\export\\base.go unexpected"`)
		},
		"prefix mutation":          func(trace string) string { return strings.ReplaceAll(trace, "GOAMD64='v2'", "GOAMD64='v3'") },
		"prefix deletion":          func(trace string) string { return strings.ReplaceAll(trace, "GOAMD64='v2' ", "") },
		"extra warning":            func(trace string) string { return trace + "unknown warning\n" },
		"incorrect WORK escape":    func(trace string) string { return strings.ReplaceAll(trace, `$WORK\\b001`, `$WORK\b001`) },
		"incorrect WORK separator": func(trace string) string { return strings.ReplaceAll(trace, `$WORK\\b001`, `$WORK/b001`) },
		"unquoted cache copy": func(trace string) string {
			return strings.Replace(trace, `cp "$WORK\\b001\\_pkg_.a" "C:\\cache root\\aa\\artifact-d"`,
				`cp $WORK\b001\_pkg_.a C:\cache root\aa\artifact-d`, 1)
		},
		"relative WORK": func(trace string) string {
			return strings.Replace(trace, `WORK=C:\tmp\go-build1234`, `WORK=tmp\go-build1234`, 1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			tools, plan, defines, actual := instrumentationWindowsTraceInputs()
			if _, err := captureInstrumentationExportRouting([]byte(mutate(instrumentationWindowsExportTrace)), `C:\Go SDK`,
				`C:\owned task\export`, `C:\cache root\aa\artifact-d`, tools, plan, defines,
				instrumentationExportEnvironmentFixture(t), actual); err == nil {
				t.Fatal("accepted changed tool/path/operand/CPU display as the observed routing")
			}
		})
	}
}

func TestInstrumentationExportRoutingHostIdentityNotTargetExecutableSuffix(t *testing.T) {
	for _, host := range []string{"darwin_arm64", "linux_amd64", "windows_amd64"} {
		for _, target := range []string{"darwin/amd64", "linux/amd64", "windows/amd64"} {
			t.Run(host+"/"+target, func(t *testing.T) {
				separator, suffix := "/", ""
				root, work, marker, archive := "/sdk", "/tmp/go-build1234", "/owned/export", "/cache/export-d"
				if strings.HasPrefix(host, "windows_") {
					separator, suffix = `\`, ".exe"
					root, work, marker, archive = `C:\sdk`, `C:\tmp\go-build1234`, `C:\owned\export`, `C:\cache\export-d`
				}
				tools := &InstrumentationToolState{Directory: "pkg/tool/" + host, BinaryOrigins: make(map[string]string)}
				for _, name := range []string{"asm", "compile"} {
					tools.BinaryOrigins[name] = "goroot/" + tools.Directory + "/" + name + suffix
				}
				paths, err := instrumentationExportPhysicalTracePaths(work, root, marker, archive, tools)
				if err != nil {
					t.Fatal(err)
				}
				if paths.separator != separator || !strings.HasSuffix(paths.compile, "compile"+suffix) {
					t.Fatal("target OS changed the actual SDK host executable")
				}
				goos, _, _ := strings.Cut(target, "/")
				plan := &InstrumentationBuildPlan{GoVersion: "go1.27.1", Target: target, Mode: InstrumentationRace}
				defines := []string{"GOOS_" + goos, "GOARCH_amd64", "GOAMD64_v1"}
				actual := map[string]string{"GOOS": goos, "GOARCH": "amd64", "GOAMD64": "v1"}
				trace := instrumentationRenderedExportTrace(plan, defines, 1, nil, paths)
				trace = strings.Replace(trace, "@action/@action", "action/action", 1)
				if _, err := captureInstrumentationExportRouting([]byte(trace), root, marker, archive, tools, plan, defines,
					instrumentationExportEnvironmentFixture(t), actual); err != nil {
					t.Fatal(err)
				}
				tools.BinaryOrigins["compile"] += ".exe"
				if _, err := captureInstrumentationExportRouting([]byte(trace), root, marker, archive, tools, plan, defines,
					instrumentationExportEnvironmentFixture(t), actual); err == nil {
					t.Fatal("accepted a different observed host executable origin")
				}
			})
		}
	}
}

func TestInstrumentationExportRoutingWindowsDisplayNeedsBoundWholeSDKSource(t *testing.T) {
	for _, key := range []string{"src/cmd/go/internal/work/shell.go", "src/cmd/go/internal/work/gc.go", "src/cmd/go/internal/work/buildid.go"} {
		t.Run(key, func(t *testing.T) {
			tools, plan, defines, actual := instrumentationWindowsTraceInputs()
			source := instrumentationExportEnvironmentFixture(t)
			source.SourceSHA256[key] = strings.Repeat("0", 64)
			if _, err := captureInstrumentationExportRouting([]byte(instrumentationWindowsExportTrace), `C:\Go SDK`,
				`C:\owned task\export`, `C:\cache root\aa\artifact-d`, tools, plan, defines, source, actual); err == nil {
				t.Fatal("accepted command display without the complete registered SDK source bytes")
			}
		})
	}
}

func TestInstrumentationExportCommandDisplayRequiresCompleteRegisteredDeclarations(t *testing.T) {
	for _, name := range []string{"joinUnambiguously", "fmtCmd", "ShowCmd"} {
		for _, mutation := range []string{"delete", "paired rewrite"} {
			t.Run(name+"/"+mutation, func(t *testing.T) {
				source := instrumentationExportEnvironmentFixture(t)
				key := "src/cmd/go/internal/work/shell.go#" + name
				if mutation == "delete" {
					delete(source.SourceDeclarations, key)
					delete(source.RegistrationSHA256, key)
				} else {
					source.SourceDeclarations[key] = "func " + name + "() {}"
					_, source.RegistrationSHA256[key], _ = instrumentationExportDeclaration("shell.go",
						[]byte("package replay\n"+source.SourceDeclarations[key]), name)
				}
				if err := validateInstrumentationExportEnvironment(source); err == nil {
					t.Fatal("accepted missing or simultaneously rewritten display source and AST identity")
				}
			})
		}
	}
}

func TestInstrumentationExportPhysicalDisplayFailsClosedBeforeRendering(t *testing.T) {
	for _, name := range []string{"missing tools", "missing origins", "unbound directory", "relative root", "relative archive", "relative marker", "empty definitions"} {
		t.Run(name, func(t *testing.T) {
			tools, plan, defines, actual := instrumentationWindowsTraceInputs()
			root, marker, archive := `C:\Go SDK`, `C:\owned task\export`, `C:\cache root\aa\artifact-d`
			switch name {
			case "missing tools":
				tools = nil
			case "missing origins":
				tools.BinaryOrigins = nil
			case "unbound directory":
				tools.Directory = "pkg/tool/windows_amd64/foreign"
			case "relative root":
				root = `Go SDK`
			case "relative archive":
				archive = `C:artifact-d`
			case "relative marker":
				marker = `\owned task\export`
			case "empty definitions":
				defines = nil
			}
			if _, err := captureInstrumentationExportRouting([]byte(instrumentationWindowsExportTrace), root, marker, archive,
				tools, plan, defines, instrumentationExportEnvironmentFixture(t), actual); err == nil {
				t.Fatal("accepted missing or relative actual source/tool/target routing")
			}
		})
	}
}
