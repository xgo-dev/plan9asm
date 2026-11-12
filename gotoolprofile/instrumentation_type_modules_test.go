package gotoolprofile

import (
	"encoding/json"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// Portable shape tests use first-party original ZIP bytes and a synthetic
// export digest. They never claim an actual external-module authentication.
func instrumentationForeignPortableFixture(t *testing.T) *InstrumentationConsumerInput {
	t.Helper()
	resource, _, _ := testDependencyModuleFixture(t)
	const dependencyPath = "example.invalid/boundary/loader/internal/layout"
	root := "package replay\nimport alias \"" + dependencyPath + "\"\nfunc Probe(value alias.Float) alias.Float\n"
	foreign := "package layout\ntype Float = float32\n"
	input := &InstrumentationConsumerInput{
		Original: &ConsumerInput{Module: "example.invalid/replay", Sources: map[string]string{"replay.go": bytesSHA256([]byte(root))}},
		Plan:     &InstrumentationOriginalPackagePlan{Target: "linux/amd64", PackageName: "replay", PackagePath: "example.invalid/replay", GoFiles: []string{"replay.go"}},
		Sources:  &InstrumentationOriginalSourceInventory{Contents: map[string]string{"replay.go": root}},
		Observation: &InstrumentationExportObservation{Early: &InstrumentationEarlyObservation{
			Mode: InstrumentationRace, CGOEnabled: "0", Environment: map[string]string{"GOOS": "linux", "GOARCH": "amd64"},
			BaselineFeatures: &Observation{GoVersion: runtime.Version()},
			SourceRules:      &InstrumentationSourceProof{GoVersion: runtime.Version()},
		}},
	}
	input.TypeSources = &InstrumentationTypeSourceProof{
		Protocol: InstrumentationTypeSourcesProtocol, InputSHA256: instrumentationTypeSourceInputSHA(input),
		RootImportMap: map[string]string{dependencyPath: dependencyPath}, SourceModules: []TestModuleSource{resource},
		Dependencies: []InstrumentationTypeSourcePackage{{Name: "layout", SourceRootID: resource.ID(), SFiles: []string{},
			Contents: map[string]string{"internal/layout/type.go": foreign},
			Dependency: InstrumentationDependencyExport{ImportMap: map[string]string{}, Source: ImportExport{
				ImportPath: dependencyPath, PackagePath: dependencyPath, ModulePath: resource.SourceModule, Version: resource.SourceVersion,
				SourceModule: resource.SourceModule, SourceVersion: resource.SourceVersion, SourceRole: "module",
				ExportSHA256: strings.Repeat("1", 64), GoSHA256: map[string]string{"internal/layout/type.go": bytesSHA256([]byte(foreign))},
			}},
		}},
	}
	return input
}

func TestInstrumentationForeignTypeResourcesPortableClosure(t *testing.T) {
	input := instrumentationForeignPortableFixture(t)
	if err := ValidateInstrumentationTypeSources(input, input.TypeSources); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	var roundtrip InstrumentationConsumerInput
	if err := json.Unmarshal(encoded, &roundtrip); err != nil {
		t.Fatal(err)
	}
	if err := ValidateInstrumentationTypeSources(&roundtrip, roundtrip.TypeSources); err != nil {
		t.Fatal(err)
	}
	if roundtrip.TypeSources.Dependencies[0].SFiles == nil {
		t.Fatal("explicit empty selected assembly was lost in JSON")
	}
	for name, mutate := range map[string]func(*InstrumentationConsumerInput){
		"missing modules":          func(p *InstrumentationConsumerInput) { p.TypeSources.SourceModules = nil },
		"missing source reference": func(p *InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].SourceRootID = "" },
		"old protocol": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Protocol = "actual_go_instrumentation_type_sources_v1"
		},
		"foreign main role": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.SourceRole = "main"
		},
		"different declared version": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.Version = "v1.0.1"
		},
		"ordinary source role": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.ModulePath = p.Original.Module
		},
		"source-only assembly deleted": func(p *InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].SFiles = nil },
		"source rules deleted":         func(p *InstrumentationConsumerInput) { p.Observation.Early.SourceRules = nil },
		"selected source deleted": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.GoSHA256 = map[string]string{}
		},
		"directory removed": func(p *InstrumentationConsumerInput) { delete(p.TypeSources.SourceModules[0].Directories, "internal") },
		"header removed": func(p *InstrumentationConsumerInput) {
			delete(p.TypeSources.SourceModules[0].Headers, "internal/layout/type.go")
		},
		"source byte hash": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.GoSHA256["internal/layout/type.go"] = strings.Repeat("0", 64)
		},
		"different profile selection": func(p *InstrumentationConsumerInput) {
			p.Observation.Early.Environment["GOARCH"] = "arm64"
			p.TypeSources.Dependencies[0].SFiles = []string{"internal/layout/probe_amd64.s"}
		},
		"test source pretending ordinary": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.GoSHA256["internal/layout/extra_test.go"] = strings.Repeat("0", 64)
		},
		"unconsumed module": func(p *InstrumentationConsumerInput) {
			extra := cloneTestModuleSource(t, p.TypeSources.SourceModules[0])
			extra.SourceModule = "example.invalid/unused"
			p.TypeSources.SourceModules = append(p.TypeSources.SourceModules, extra)
			SortTestModuleSources(p.TypeSources.SourceModules)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationConsumerInput
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			// Rebinding the input digest cannot turn a changed selection or role
			// into a missing-resource fallback.
			changed.TypeSources.InputSHA256 = instrumentationTypeSourceInputSHA(&changed)
			if err := ValidateInstrumentationTypeSources(&changed, changed.TypeSources); err == nil {
				t.Fatal("accepted incomplete/changed foreign source-only closure")
			}
		})
	}
	if input.Original.TestDependencies != nil || input.Original.TestDependencySourceProtocol != "" {
		t.Fatal("type resources borrowed a test-source role")
	}
}

func TestInstrumentationForeignTypeResourcesSharedBudget(t *testing.T) {
	input := instrumentationForeignPortableFixture(t)
	resource := cloneTestModuleSource(t, input.TypeSources.SourceModules[0])
	for file := range resource.Headers {
		resource.Headers[file] = strings.Repeat(" ", 3<<20)
	}
	if err := validateInstrumentationTypeModuleResources([]TestModuleSource{resource}); err != nil {
		t.Fatal(err)
	}
	other := cloneTestModuleSource(t, resource)
	other.SourceModule = "example.invalid/other"
	third := cloneTestModuleSource(t, resource)
	third.SourceModule = "example.invalid/third"
	resources := []TestModuleSource{resource, other, third}
	SortTestModuleSources(resources)
	if err := validateInstrumentationTypeModuleResources(resources); err == nil {
		t.Fatal("each module received a fresh text-byte budget")
	}
	if !reflect.DeepEqual(input.TypeSources.SourceModules[0].Headers, instrumentationForeignPortableFixture(t).TypeSources.SourceModules[0].Headers) {
		t.Fatal("budget validation mutated original resources")
	}
}
