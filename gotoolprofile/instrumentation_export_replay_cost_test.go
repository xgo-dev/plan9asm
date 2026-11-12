package gotoolprofile

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestInstrumentationExportDeclarationsRepeatedOriginalDoesNotReparse(t *testing.T) {
	proof := instrumentationExportEnvironmentFixture(t)
	var replayError error
	allocations := testing.AllocsPerRun(3, func() {
		for key, original := range proof.SourceDeclarations {
			name, target, _ := strings.Cut(key, "#")
			_, _, replayError = instrumentationExportDeclaration(name, []byte("package replay\n"+original+"\n"), target)
			if replayError != nil {
				return
			}
		}
	})
	if replayError != nil {
		t.Fatal(replayError)
	}
	// All complete original declarations and their registered digests still
	// participate. Repeating pure parsing/formatting for each mode scope does
	// not add source authority and should not dominate the object checks.
	t.Logf("unchanged original declaration replay allocations=%.0f", allocations)
	if allocations > 256 {
		t.Fatalf("repeated original declarations rebuild SDK ASTs: %.0f allocations, want <=256", allocations)
	}
}

func TestInstrumentationExportEnvironmentRepeatedOriginalKeepsValidationBounded(t *testing.T) {
	proof := instrumentationExportEnvironmentFixture(t)
	var replayError error
	allocations := testing.AllocsPerRun(3, func() {
		replayError = validateInstrumentationExportEnvironment(proof)
	})
	if replayError != nil {
		t.Fatal(replayError)
	}
	t.Logf("unchanged original environment validation allocations=%.0f", allocations)
	if allocations > 1024 {
		t.Fatalf("repeated environment validation rebuilds driver ASTs: %.0f allocations, want <=1024", allocations)
	}
}

func BenchmarkInstrumentationExportEnvironmentRepeatedValidation(b *testing.B) {
	data, err := os.ReadFile("testdata/instrumentation-export-environment-go1.27.1.json")
	if err != nil {
		b.Fatal(err)
	}
	var proof InstrumentationExportEnvironment
	if err := json.Unmarshal(data, &proof); err != nil {
		b.Fatal(err)
	}
	if err := validateInstrumentationExportEnvironment(&proof); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := validateInstrumentationExportEnvironment(&proof); err != nil {
			b.Fatal(err)
		}
	}
}
