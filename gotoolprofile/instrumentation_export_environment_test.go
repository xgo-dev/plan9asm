package gotoolprofile

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestInstrumentationExportEnvironmentCompleteSourcesAndDefaults(t *testing.T) {
	original := instrumentationExportEnvironmentFixture(t)
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstrumentationExportEnvironment){
		"legacy protocol": func(p *InstrumentationExportEnvironment) {
			p.Protocol = "actual_go_instrumentation_marker_export_routing_v1"
		},
		"future SDK":     func(p *InstrumentationExportEnvironment) { p.GoVersion = "go1.27.4" },
		"missing source": func(p *InstrumentationExportEnvironment) { delete(p.SourceSHA256, "src/cmd/go/internal/cfg/cfg.go") },
		"changed complete source": func(p *InstrumentationExportEnvironment) {
			p.SourceSHA256["src/cmd/go/internal/work/shell.go"] = strings.Repeat("0", 64)
		},
		"extra source": func(p *InstrumentationExportEnvironment) { p.SourceSHA256["unregistered.go"] = strings.Repeat("0", 64) },
		"missing declaration": func(p *InstrumentationExportEnvironment) {
			delete(p.SourceDeclarations, "src/cmd/go/internal/work/init.go#makeCfgChangedEnv")
		},
		"rewritten declaration and AST": func(p *InstrumentationExportEnvironment) {
			key := "src/cmd/go/internal/cfg/cfg.go#EnvOrAndChanged"
			p.SourceDeclarations[key] = strings.Replace(p.SourceDeclarations[key], "val != def", "val == def", 1)
			_, p.RegistrationSHA256[key], _ = instrumentationExportDeclaration("cfg.go", []byte("package replay\n"+p.SourceDeclarations[key]), "EnvOrAndChanged")
		},
		"additional projected declaration": func(p *InstrumentationExportEnvironment) {
			key := "src/cmd/go/internal/cfg/cfg.go#EnvOrAndChanged"
			p.SourceDeclarations[key] += "\nfunc unregistered() {}\n"
		},
		"missing registration": func(p *InstrumentationExportEnvironment) {
			delete(p.RegistrationSHA256, "src/cmd/go/internal/work/gc.go#gc")
		},
		"missing bootstrap": func(p *InstrumentationExportEnvironment) { p.BootstrapText = "" },
		"changed bootstrap digest": func(p *InstrumentationExportEnvironment) {
			p.SourceSHA256[instrumentationBootstrapSource] = strings.Repeat("0", 64)
		},
		"rewritten CPU default and digest": func(p *InstrumentationExportEnvironment) {
			p.BootstrapText = strings.Replace(p.BootstrapText, "`v1`", "`v2`", 1)
			p.SourceSHA256[instrumentationBootstrapSource] = bytesSHA256([]byte(p.BootstrapText))
		},
		"rewritten ARM default and digest": func(p *InstrumentationExportEnvironment) {
			p.BootstrapText = strings.Replace(p.BootstrapText, "`v8.0`", "`v8.1`", 1)
			p.SourceSHA256[instrumentationBootstrapSource] = bytesSHA256([]byte(p.BootstrapText))
		},
		"changed SDK env digest":  func(p *InstrumentationExportEnvironment) { p.GoEnvText += "GOAMD64=v2\n" },
		"invented absent SDK env": func(p *InstrumentationExportEnvironment) { p.GoEnvPresent = false },
	} {
		t.Run(name, func(t *testing.T) {
			var proof InstrumentationExportEnvironment
			if err := json.Unmarshal(encoded, &proof); err != nil {
				t.Fatal(err)
			}
			mutate(&proof)
			if err := validateInstrumentationExportEnvironment(&proof); err == nil {
				t.Fatal("accepted missing, fabricated or changed driver source/default evidence")
			}
		})
	}
}

func TestInstrumentationExportCommandEnvironmentSDKFileSemantics(t *testing.T) {
	for _, input := range []struct {
		name, arch, value, sdk string
		absent                 bool
		want                   []string
	}{
		{"AMD64 default", "amd64", "v1", "", false, nil},
		{"AMD64 v2", "amd64", "v2", "", false, []string{"GOAMD64=v2"}},
		{"AMD64 v3", "amd64", "v3", "", false, []string{"GOAMD64=v3"}},
		{"AMD64 v4", "amd64", "v4", "", false, []string{"GOAMD64=v4"}},
		{"ARM64 default", "arm64", "v8.0", "", false, nil},
		{"ARM64 v8.1", "arm64", "v8.1", "", false, []string{"GOARM64=v8.1"}},
		{"ARM64 v9.0", "arm64", "v9.0", "", false, []string{"GOARM64=v9.0"}},
		{"absent file", "amd64", "v2", "", true, []string{"GOAMD64=v2"}},
		{"SDK CPU override", "amd64", "v2", "GOAMD64=v2\n", false, nil},
		{"SDK not runtime default", "amd64", "v1", "GOAMD64=v2\n", false, []string{"GOAMD64=v1"}},
		{"present empty SDK key", "amd64", "v1", "GOAMD64=\n", false, []string{"GOAMD64=v1"}},
		{"last duplicate wins", "amd64", "v3", "GOAMD64=v2\nGOAMD64=v3\n", false, nil},
		{"last empty duplicate wins", "amd64", "v1", "GOAMD64=v1\nGOAMD64=\n", false, []string{"GOAMD64=v1"}},
		{"no trimming", "amd64", "v1", "GOAMD64=v1 \n", false, []string{"GOAMD64=v1"}},
		{"retain CR", "amd64", "v1", "GOAMD64=v1\r\n", false, []string{"GOAMD64=v1"}},
		{"ignore lowercase", "amd64", "v1", "goamd64=v4\n", false, nil},
		{"ignore leading space", "amd64", "v1", " GOAMD64=v4\n", false, nil},
		{"ignore comment", "amd64", "v1", "#GOAMD64=v4\n", false, nil},
		{"other arch key", "amd64", "v1", "GOARM64=v8.1\n", false, nil},
		{"ARM64 SDK override", "arm64", "v8.1", "GOARM64=v8.1", false, nil},
	} {
		t.Run(input.name, func(t *testing.T) {
			proof := instrumentationExportEnvironmentFixture(t)
			proof.GoEnvPresent, proof.GoEnvText = !input.absent, input.sdk
			if input.absent {
				delete(proof.SourceSHA256, "go.env")
			} else {
				proof.SourceSHA256["go.env"] = bytesSHA256([]byte(input.sdk))
			}
			key := "GOAMD64"
			if input.arch == "arm64" {
				key = "GOARM64"
			}
			plan := &InstrumentationBuildPlan{Target: "darwin/" + input.arch, GoVersion: "go1.27.1"}
			actual := map[string]string{"GOOS": "darwin", "GOARCH": input.arch, key: input.value}
			got, err := instrumentationExportCommandEnvironment(proof, actual, plan)
			if err != nil || !reflect.DeepEqual(got, input.want) {
				t.Fatalf("actual SDK changed-env model: %v %v, want %v", got, err, input.want)
			}
			for name, mutate := range map[string]func(map[string]string){
				"missing target": func(m map[string]string) { delete(m, "GOARCH") },
				"wrong target":   func(m map[string]string) { m["GOOS"] = "linux" },
				"missing CPU":    func(m map[string]string) { delete(m, key) },
				"empty CPU":      func(m map[string]string) { m[key] = "" },
				"malformed CPU":  func(m map[string]string) { m[key] += "\n" },
			} {
				t.Run(name, func(t *testing.T) {
					changed := copyInstrumentationHashes(actual)
					mutate(changed)
					if _, err := instrumentationExportCommandEnvironment(proof, changed, plan); err == nil {
						t.Fatal("accepted changed or incomplete actual target environment")
					}
				})
			}
		})
	}
}

func TestInstrumentationExportRoutingCPUEnvironmentCannotBeNormalizedAway(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			key, value := "GOAMD64", "v2"
			if arch == "arm64" {
				key, value = "GOARM64", "v8.1"
			}
			environment := []string{key + "=" + value}
			prefix := instrumentationExportCommandPrefix(environment)
			actual := map[string]string{"GOOS": "darwin", "GOARCH": arch, key: value}
			plan := &InstrumentationBuildPlan{GoVersion: "go1.27.1", Target: "darwin/" + arch, Mode: InstrumentationRace, CodegenFlags: []string{"-shared"}}
			defines := []string{"GOOS_darwin", "GOARCH_" + arch}
			original := &InstrumentationExportRouting{
				Protocol: "actual_go_instrumentation_marker_export_routing_v2", CompilerConcurrency: 2,
				AssemblerDefines: defines, CommandEnvironment: environment,
				EnvironmentSource: instrumentationExportEnvironmentFixture(t),
				CanonicalTrace:    instrumentationExpectedExportTrace(plan, defines, 2, environment),
			}
			original.TraceSHA256 = bytesSHA256([]byte(original.CanonicalTrace))
			if err := validateInstrumentationExportRouting(original, plan, defines, actual); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*InstrumentationExportRouting){
				"dropped prefix": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.ReplaceAll(p.CanonicalTrace, prefix, "")
				},
				"only one command": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.Replace(p.CanonicalTrace, prefix, "", 1)
				},
				"changed CPU": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.ReplaceAll(p.CanonicalTrace, value, "bogus")
				},
				"wrong quotes": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.ReplaceAll(p.CanonicalTrace, prefix, key+"="+value+" ")
				},
				"duplicate prefix": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.Replace(p.CanonicalTrace, prefix, prefix+prefix, 1)
				},
				"unrelated env": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.Replace(p.CanonicalTrace, prefix, "GODEBUG='unknown' "+prefix, 1)
				},
				"wrong arch key": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.ReplaceAll(p.CanonicalTrace, key, "GO386")
				},
				"invented GOOS mismatch": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.Replace(p.CanonicalTrace, prefix, "GOOS='darwin' "+prefix, 1)
				},
				"env on internal pack": func(p *InstrumentationExportRouting) {
					p.CanonicalTrace = strings.Replace(p.CanonicalTrace, "go tool pack", prefix+"go tool pack", 1)
				},
				"changed recorded env": func(p *InstrumentationExportRouting) { p.CommandEnvironment = []string{key + "=bogus"} },
				"missing source":       func(p *InstrumentationExportRouting) { p.EnvironmentSource = nil },
				"legacy protocol": func(p *InstrumentationExportRouting) {
					p.Protocol = "actual_go_instrumentation_marker_export_routing_v1"
				},
			} {
				t.Run(name, func(t *testing.T) {
					copy := *original
					copy.CommandEnvironment = append([]string(nil), original.CommandEnvironment...)
					mutate(&copy)
					copy.TraceSHA256 = bytesSHA256([]byte(copy.CanonicalTrace))
					if err := validateInstrumentationExportRouting(&copy, plan, defines, actual); err == nil {
						t.Fatal("normalized away a changed actual CPU command route")
					}
				})
			}
		})
	}
	if got := instrumentationExportCommandPrefix([]string{"KEY=value'quoted"}); got != "KEY=\"value'quoted\" " {
		t.Fatalf("registered shell quote rule changed: %q", got)
	}
}
