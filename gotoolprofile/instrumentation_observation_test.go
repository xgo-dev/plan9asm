package gotoolprofile

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func instrumentationFixtureEnvironment(base []string, early *InstrumentationEarlyObservation) []string {
	observed := copyInstrumentationHashes(early.Environment)
	for key, value := range early.CommandContext {
		observed[key] = value
	}
	// `go env GOENV` reports an empty value for the observer's explicit off
	// policy. Do not restore a user's environment file for fixture commands.
	observed["GOENV"] = "off"
	return replaceEnv(base, observed)
}

func captureActualInstrumentationEarly(t *testing.T, target string, mode InstrumentationMode, cgo string) *InstrumentationEarlyObservation {
	t.Helper()
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	proof, err := CaptureInstrumentationEarlyObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), target, mode, cgo, nil, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func TestInstrumentationEarlyObservationActualDriverAndPortableReplay(t *testing.T) {
	for _, input := range []struct {
		target string
		mode   InstrumentationMode
		status InstrumentationEarlyStatus
	}{
		{"darwin/arm64", InstrumentationRace, InstrumentationEarlyRuleAccepted},
		{"linux/386", InstrumentationRace, InstrumentationOfficialTargetUnsupported},
		{"js/wasm", InstrumentationASan, InstrumentationOfficialTargetUnsupported},
	} {
		t.Run(input.target+"/"+string(input.mode), func(t *testing.T) {
			proof := captureActualInstrumentationEarly(t, input.target, input.mode, "0")
			if proof.Status != input.status {
				t.Fatalf("unexpected early-rule status %s", proof.Status)
			}
			data, err := json.Marshal(proof)
			if err != nil {
				t.Fatal(err)
			}
			var restored InstrumentationEarlyObservation
			if err := json.Unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := ValidateInstrumentationEarlyObservation(&restored); err != nil {
				t.Fatal(err)
			}
			if InstrumentationEarlyProfileID(&restored) != InstrumentationEarlyProfileID(proof) {
				t.Fatal("source/driver/environment/mode evidence changed on roundtrip")
			}
		})
	}
	withoutCGO := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	newDirectory := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	if InstrumentationEarlyProfileID(withoutCGO) != InstrumentationEarlyProfileID(newDirectory) {
		t.Fatal("private marker directory polluted portable source/driver/environment identity")
	}
	withCGO := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "1")
	if withCGO.BaselineFeatures.Environment["CGO_ENABLED"] != "0" || withCGO.Environment["CGO_ENABLED"] != "1" ||
		InstrumentationEarlyProfileID(withCGO) == InstrumentationEarlyProfileID(withoutCGO) {
		t.Fatal("CGO=0 CPU foundation impersonated the independently observed CGO=1 mode")
	}
}

func TestInstrumentationEarlyObservationRejectsDowngradeAndChangedModeEnvironment(t *testing.T) {
	original := captureActualInstrumentationEarly(t, "darwin/arm64", InstrumentationRace, "0")
	for name, mutate := range map[string]func(*InstrumentationEarlyObservation){
		"missing protocol":       func(p *InstrumentationEarlyObservation) { p.Protocol = "" },
		"downgrade":              func(p *InstrumentationEarlyObservation) { p.Protocol = "go_driver_builtin_features_v2" },
		"missing baseline":       func(p *InstrumentationEarlyObservation) { p.BaselineFeatures = nil },
		"missing mode tools":     func(p *InstrumentationEarlyObservation) { p.ModeTools = nil },
		"changed installed tool": func(p *InstrumentationEarlyObservation) { p.ModeTools.BinarySHA256["asm"] = strings.Repeat("0", 64) },
		"missing source":         func(p *InstrumentationEarlyObservation) { p.SourceRules = nil },
		"different mode":         func(p *InstrumentationEarlyObservation) { p.Mode = InstrumentationASan },
		"fake success":           func(p *InstrumentationEarlyObservation) { p.Status = "exported" },
		"extra flags":            func(p *InstrumentationEarlyObservation) { p.BuildFlags = append(p.BuildFlags, "-asan") },
		"CGO source mismatch":    func(p *InstrumentationEarlyObservation) { p.Environment["CGO_ENABLED"] = "1" },
		"CPU source mismatch":    func(p *InstrumentationEarlyObservation) { p.Environment["GOARM64"] = "v8.4" },
		"unknown stderr":         func(p *InstrumentationEarlyObservation) { p.Stderr = "unknown warning\n" },
		"missing marker":         func(p *InstrumentationEarlyObservation) { delete(p.MarkerSelection, "msan") },
		"fake mode marker":       func(p *InstrumentationEarlyObservation) { p.MarkerSelection["race"] = false },
		"missing context":        func(p *InstrumentationEarlyObservation) { delete(p.CommandContext, "CC") },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var modified InstrumentationEarlyObservation
			if err := json.Unmarshal(data, &modified); err != nil {
				t.Fatal(err)
			}
			mutate(&modified)
			if err := ValidateInstrumentationEarlyObservation(&modified); err == nil {
				t.Fatal("accepted changed, incomplete or downgraded early observation")
			}
		})
	}
}

func TestInstrumentationEarlyObservationDoesNotTurnPrerequisitesIntoTargetExclusions(t *testing.T) {
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, mode := range []InstrumentationMode{InstrumentationRace, InstrumentationMSan} {
		if _, err := CaptureInstrumentationEarlyObservation(ctx, binary, instrumentationMarkerDirectory(t), os.Environ(), "linux/amd64", mode, "0", nil, RunBounded); err == nil {
			t.Fatal("missing CGO became an unsupported target or early accepted observation")
		}
	}
	if InstrumentationEarlyProfileID(nil) != "" {
		t.Fatal("nil early observation received an identity")
	}
	env := replaceEnv(os.Environ(), map[string]string{"GODEBUG": "cpu.plan9asm_unregistered=off"})
	if _, err := CaptureInstrumentationEarlyObservation(ctx, binary, instrumentationMarkerDirectory(t), env, "darwin/arm64", InstrumentationRace, "0", nil, RunBounded); err == nil {
		t.Fatal("actual unknown driver warning became a complete mode observation")
	}
}

func TestInstrumentationEarlyObservationUnsupportedNeedsExactCompleteWitness(t *testing.T) {
	original := captureActualInstrumentationEarly(t, "linux/386", InstrumentationRace, "0")
	for name, mutate := range map[string]func(*InstrumentationEarlyObservation){
		"wrong exit":          func(p *InstrumentationEarlyObservation) { p.ExitCode = 1 },
		"unknown diagnostics": func(p *InstrumentationEarlyObservation) { p.Stderr += "unknown warning\n" },
		"wrong target":        func(p *InstrumentationEarlyObservation) { p.Target = "linux/arm" },
		"nonempty stdout": func(p *InstrumentationEarlyObservation) {
			p.DriverSelectionSHA256 = bytesSHA256([]byte("unknown output"))
		},
		"invented markers": func(p *InstrumentationEarlyObservation) { p.MarkerSelection = map[string]bool{"race": true} },
		"missing source":   func(p *InstrumentationEarlyObservation) { delete(p.SourceRules.SourceText, "VERSION") },
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			var proof InstrumentationEarlyObservation
			if err := json.Unmarshal(data, &proof); err != nil {
				t.Fatal(err)
			}
			mutate(&proof)
			if err := ValidateInstrumentationEarlyObservation(&proof); err == nil {
				t.Fatal("accepted incomplete or changed exact unsupported-target observation")
			}
		})
	}
	if !strings.Contains(original.Stderr, "-race is not supported on linux/386") {
		t.Fatal("original actual unsupported diagnostic was not retained")
	}
}
