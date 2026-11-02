package plan9asm

import (
	"os"
	"strings"
	"testing"
)

func TestX86PackedConversionRequiredNativeOwners(t *testing.T) {
	// The complete policy binds all 17 unconditional owners to the explicit
	// native tag. Ordinary conversion counterparts retain the default CI selector.
	TestX86PackedConversionCompleteNativeRuntimeOwnership(t)
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") {
		t.Fatal("ordinary conversion runtime counterparts not selected by CI", err)
	}
}
