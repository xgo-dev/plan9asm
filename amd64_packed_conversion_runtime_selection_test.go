package plan9asm

import (
	"os"
	"strings"
	"testing"
)

func TestX86PackedConversionRequiredNativeOwners(t *testing.T) {
	// The complete policy retains native-only build selection and binds all17
	// unconditional owner calls. Keep the full go-ci counterpart check here.
	TestX86PackedConversionCompleteNativeRuntimeOwnership(t)
	workflow, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil || !strings.Contains(string(workflow), "-ci-selector '^(TestCrossLinuxRuntimeMatrix|") {
		t.Fatal("required native runtime roots not selected by CI", err)
	}
}
