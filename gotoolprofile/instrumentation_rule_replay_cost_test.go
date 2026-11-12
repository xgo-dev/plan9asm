package gotoolprofile

import (
	"reflect"
	"runtime"
	"testing"
)

func TestInstrumentationRuleReplayRepeatedOriginalDoesNotReparseSDK(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	var last *InstrumentationSourceRules
	var replayError error
	allocations := testing.AllocsPerRun(5, func() {
		last, replayError = ReplayInstrumentationSourceProof(proof)
	})
	if replayError != nil || last == nil {
		t.Fatalf("complete original replay failed: %v", replayError)
	}
	// Rechecking all original bytes and returning independent rule maps is
	// required. Rebuilding complete SDK ASTs for every repeated scope is not.
	// This deliberately generous allocation bound distinguishes those paths
	// without depending on clock speed, host load, or LLVM execution.
	t.Logf("unchanged original rule replay allocations=%.0f", allocations)
	if allocations > 128 {
		t.Fatalf("repeated original source replay reparses SDK rules: %.0f allocations, want <=128", allocations)
	}
}

func TestInstrumentationRuleReplayReturnedMapsAndRootsRemainIndependent(t *testing.T) {
	proof := actualInstrumentationSourceProof(t)
	first, err := ReplayInstrumentationSourceProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	wantSources := first.SourceHashes()
	wantRegistration := first.RegistrationHashes()
	wantTargets := make(map[InstrumentationMode]map[string]bool)
	for mode, targets := range first.targets {
		wantTargets[mode] = make(map[string]bool)
		for target, supported := range targets {
			wantTargets[mode][target] = supported
		}
	}
	first.root = t.TempDir()
	first.version = "go1.99.0"
	first.sources["VERSION"] = "changed"
	first.registration["instrumentInit"] = "changed"
	for _, targets := range first.targets {
		for target := range targets {
			delete(targets, target)
		}
		targets["unregistered/target"] = true
	}

	again, err := ReplayInstrumentationSourceProof(proof)
	if err != nil {
		t.Fatal(err)
	}
	if again.root != "" || again.version != proof.GoVersion ||
		!reflect.DeepEqual(again.sources, wantSources) ||
		!reflect.DeepEqual(again.registration, wantRegistration) ||
		!reflect.DeepEqual(again.targets, wantTargets) {
		t.Fatal("one replay mutated another replay or acquired a physical root")
	}
	if err := again.Recheck(); err == nil {
		t.Fatal("portable repeated replay acquired physical source authority")
	}
}

func BenchmarkInstrumentationSourceProofRepeatedReplay(b *testing.B) {
	proof, err := CaptureInstrumentationSourceProof(runtime.GOROOT(), runtime.Version())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ReplayInstrumentationSourceProof(proof); err != nil {
			b.Fatal(err)
		}
	}
}
