package gotoolprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func instrumentationOriginalFixture(t *testing.T, early *InstrumentationEarlyObservation) *ConsumerInput {
	t.Helper()
	files := instrumentationExportFixture()
	input := &ConsumerInput{
		Protocol: ConsumerProtocol, ID: ProfileID(early.BaselineFeatures), Observed: early.BaselineFeatures,
		Module: instrumentationExportModule, SourceRoot: t.TempDir(), Sources: make(map[string]string),
		Headers: make(map[string]string), Directories: make(map[string][]string),
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(input.SourceRoot, name), data, 0600); err != nil {
			t.Fatal(err)
		}
		input.Sources[name] = bytesSHA256(data)
		input.Headers[name] = string(data)
		input.Directories["."] = append(input.Directories["."], name)
	}
	sort.Strings(input.Directories["."])
	input.AsmFiles = []string{"mode_asan.s", "mode_msan.s", "mode_race.s"}
	return input
}

func TestInstrumentationOriginalPlanKeepsFullModeDenominator(t *testing.T) {
	early := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	input := instrumentationOriginalFixture(t, early)
	sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.GoFiles, []string{"base.go", "mode_race.go"}) ||
		!reflect.DeepEqual(plan.SFiles, []string{"mode_race.s"}) || len(plan.Decisions) != 7 ||
		plan.Decisions[6].File != "mode_race.s" || !plan.Decisions[6].ModeRequired ||
		plan.Status != "consumer_pending" || !reflect.DeepEqual(plan.BuildFlags, []string{"-race"}) {
		t.Fatalf("incomplete mode/ordinary pairing denominator: %+v", plan)
	}
	if err := ValidateInstrumentationOriginalPackagePlan(input, sources, early, ".", nil, plan); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*InstrumentationOriginalPackagePlan){
		"delete excluded": func(p *InstrumentationOriginalPackagePlan) { p.Decisions = p.Decisions[1:] },
		"ordinary flags":  func(p *InstrumentationOriginalPackagePlan) { p.BuildFlags = nil },
		"other mode":      func(p *InstrumentationOriginalPackagePlan) { p.Mode = InstrumentationMSan },
		"unpaired go":     func(p *InstrumentationOriginalPackagePlan) { p.GoFiles = nil },
		"claim pass":      func(p *InstrumentationOriginalPackagePlan) { p.Status = "passed" },
		"changed scope":   func(p *InstrumentationOriginalPackagePlan) { p.CustomTags = []string{"changed"} },
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationOriginalPackagePlan
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if err := ValidateInstrumentationOriginalPackagePlan(input, sources, early, ".", nil, &changed); err == nil {
				t.Fatal("accepted missing, changed or promoted original scope")
			}
		})
	}
	for _, tags := range [][]string{{"race"}, {"cgo"}, {"go1.27"}, {"amd64.v1"}, {"x", "x"}, {"x || y"}} {
		if _, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", tags); err == nil {
			t.Fatalf("accepted custom flags impersonating mode/builtin or malformed tags: %v", tags)
		}
	}
	delete(input.Headers, "mode_msan.s")
	if _, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil); err == nil {
		t.Fatal("accepted an uncaptured excluded source")
	}
}

func TestInstrumentationOriginalPlanPreservesOldInputFields(t *testing.T) {
	early := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	input := instrumentationOriginalFixture(t, early)
	sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, sources, early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	input.TestDependencySourceProtocol = TestDependencyProtocol
	if err := ValidateInstrumentationOriginalPackagePlan(input, sources, early, ".", nil, plan); err == nil {
		t.Fatal("old protocol/source-field mutation escaped complete input binding")
	}
}
