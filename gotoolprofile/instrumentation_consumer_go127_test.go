//go:build go1.27

package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestInstrumentationConsumerPackageContextCannotBecomeOrdinary(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "darwin/arm64", InstrumentationRace, "0", nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	input := instrumentationOriginalFixture(t, marker.Early)
	sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstrumentationOriginalPackage(input, sources, marker.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	wrapped, err := NewInstrumentationConsumerInput(input, sources, marker, plan)
	if err != nil {
		t.Fatal(err)
	}
	exported, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(), input, sources, marker, plan, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	pkg := exported.Package
	root, stderr, err := RunBounded(ctx, input.SourceRoot, os.Environ(), binary, "env", "GOROOT")
	if err != nil || len(stderr) != 0 {
		t.Fatalf("actual compiler root: %v; %s", err, stderr)
	}
	pkg.Macros, err = CaptureInstrumentationAssemblerMacros(strings.TrimSpace(string(root)), wrapped, pkg.PackagePath)
	if err != nil {
		t.Fatal(err)
	}
	proof := &InstrumentationPackageSelectionProof{
		Protocol: InstrumentationPackageSelectionProtocol, ModeProfileID: wrapped.ID,
		InputSHA256: InstrumentationConsumerInputSHA256(wrapped), Packages: []PackageProof{pkg},
		Status: "consumer_pending",
	}
	if err := ValidateInstrumentationPackageSelection(wrapped, ".", nil, proof); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePackageSelection(input, proof.Packages, nil); err == nil {
		t.Fatal("mode-selected assembly passed the ordinary package reader")
	}
	if wrapped.ID == input.ID || !reflect.DeepEqual(wrapped.Plan.BuildFlags, []string{"-race"}) {
		t.Fatal("mode source context was reduced to its ordinary CPU foundation")
	}
	data, err := json.Marshal(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstrumentationConsumerInput(strings.NewReader(string(data)), ".", nil); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{string(data) + "{}", strings.Replace(string(data), "\"protocol\":", "\"unknown\":true,\"protocol\":", 1)} {
		if _, err := DecodeInstrumentationConsumerInput(strings.NewReader(invalid), ".", nil); err == nil {
			t.Fatal("mode wrapper accepted unknown fields or trailing JSON")
		}
	}
	for name, mutate := range map[string]func(*InstrumentationConsumerInput){
		"missing protocol":       func(p *InstrumentationConsumerInput) { p.Protocol = "" },
		"ordinary protocol":      func(p *InstrumentationConsumerInput) { p.Protocol = ConsumerProtocol },
		"ordinary ID":            func(p *InstrumentationConsumerInput) { p.ID = p.Original.ID },
		"missing mode":           func(p *InstrumentationConsumerInput) { p.Observation = nil },
		"early only":             func(p *InstrumentationConsumerInput) { p.Observation.Routing = nil },
		"missing ignored source": func(p *InstrumentationConsumerInput) { delete(p.Sources.Contents, "mode_msan.s") },
		"changed original protocol": func(p *InstrumentationConsumerInput) {
			p.Original.TestDependencySourceProtocol = TestDependencyProtocol
		},
		"CGO substitution":       func(p *InstrumentationConsumerInput) { p.Observation.Early.CGOEnabled = "1" },
		"mode as tag":            func(p *InstrumentationConsumerInput) { p.Plan.CustomTags = []string{"race"} },
		"missing selected scope": func(p *InstrumentationConsumerInput) { p.Plan.SFiles = nil },
	} {
		t.Run(name, func(t *testing.T) {
			var p InstrumentationConsumerInput
			if err := json.Unmarshal(data, &p); err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			if err := ValidateInstrumentationConsumerInput(&p, ".", nil); err == nil {
				t.Fatal("accepted changed or downgraded mode context")
			}
		})
	}
	selection, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeInstrumentationPackageSelection(strings.NewReader(string(selection)), wrapped, ".", nil); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{string(selection) + "{}", strings.Replace(string(selection), "\"protocol\":", "\"unknown\":true,\"protocol\":", 1)} {
		if _, err := DecodeInstrumentationPackageSelection(strings.NewReader(invalid), wrapped, ".", nil); err == nil {
			t.Fatal("mode package reader accepted unknown fields or trailing JSON")
		}
	}
	if _, err := DecodeInstrumentationPackageSelection(strings.NewReader(string(selection)), wrapped, ".", []string{"foreign"}); err == nil {
		t.Fatal("mode package reader accepted a foreign independently requested tag scope")
	}
	for name, mutate := range map[string]func(*InstrumentationPackageSelectionProof){
		"ordinary protocol":     func(p *InstrumentationPackageSelectionProof) { p.Protocol = ConsumerProtocol },
		"ordinary ID":           func(p *InstrumentationPackageSelectionProof) { p.ModeProfileID = input.ID },
		"missing input binding": func(p *InstrumentationPackageSelectionProof) { p.InputSHA256 = "" },
		"ordinary macros": func(p *InstrumentationPackageSelectionProof) {
			p.Packages[0].Macros.FeatureID = input.ID
			p.Packages[0].Macros.Protocol = "go_source_assembler_macros_v1"
		},
		"wrong Go":          func(p *InstrumentationPackageSelectionProof) { p.Packages[0].GoFiles = []string{"base.go"} },
		"wrong compiled Go": func(p *InstrumentationPackageSelectionProof) { p.Packages[0].CompiledGoFiles = []string{"base.go"} },
		"missing ASM":       func(p *InstrumentationPackageSelectionProof) { p.Packages[0].SFiles = nil },
		"missing package":   func(p *InstrumentationPackageSelectionProof) { p.Packages = nil },
		"claim pass":        func(p *InstrumentationPackageSelectionProof) { p.Status = "passed" },
	} {
		t.Run(name, func(t *testing.T) {
			var p InstrumentationPackageSelectionProof
			if err := json.Unmarshal(selection, &p); err != nil {
				t.Fatal(err)
			}
			mutate(&p)
			if err := ValidateInstrumentationPackageSelection(wrapped, ".", nil, &p); err == nil {
				t.Fatal("accepted changed or downgraded actual package context")
			}
		})
	}
}

func TestInstrumentationConsumerActualExclusiveModeSourceContexts(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []struct {
		target string
		mode   InstrumentationMode
		cgo    string
	}{
		{"darwin/arm64", InstrumentationRace, "1"},
		{"linux/arm64", InstrumentationMSan, "1"},
		{"linux/arm64", InstrumentationASan, "1"},
	} {
		t.Run(config.target+"/"+string(config.mode), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			marker, err := CaptureInstrumentationExportObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), config.target, config.mode, config.cgo, nil, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			input := instrumentationOriginalFixture(t, marker.Early)
			sources, err := CaptureInstrumentationOriginalSourceInventory(input, ".")
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanInstrumentationOriginalPackage(input, sources, marker.Early, ".", nil)
			if err != nil {
				t.Fatal(err)
			}
			wrapped, err := NewInstrumentationConsumerInput(input, sources, marker, plan)
			if err != nil {
				t.Fatal(err)
			}
			exported, err := CaptureInstrumentationOriginalExport(ctx, binary, input.SourceRoot, os.Environ(), input, sources, marker, plan, RunBounded)
			if err != nil {
				t.Fatal(err)
			}
			pkg := exported.Package
			root, stderr, err := RunBounded(ctx, input.SourceRoot, os.Environ(), binary, "env", "GOROOT")
			if err != nil || len(stderr) != 0 {
				t.Fatalf("actual compiler root: %v; %s", err, stderr)
			}
			pkg.Macros, err = CaptureInstrumentationAssemblerMacros(strings.TrimSpace(string(root)), wrapped, pkg.PackagePath)
			if err != nil {
				t.Fatal(err)
			}
			proof := &InstrumentationPackageSelectionProof{
				Protocol: InstrumentationPackageSelectionProtocol, ModeProfileID: wrapped.ID,
				InputSHA256: InstrumentationConsumerInputSHA256(wrapped), Packages: []PackageProof{pkg}, Status: "consumer_pending",
			}
			if err := ValidateInstrumentationPackageSelection(wrapped, ".", nil, proof); err != nil {
				t.Fatal(err)
			}
			if proof.Status != "consumer_pending" || wrapped.Observation.Early.Environment["CGO_ENABLED"] != config.cgo ||
				wrapped.ID == input.ID || pkg.Macros.Protocol == "go_source_assembler_macros_v1" {
				t.Fatal("mode package context lost its independently observed CGO/mode role")
			}
		})
	}
}
