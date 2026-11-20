package main

import "testing"

func TestExtractSupportedOpsARM64RandomRegisterCarriers(t *testing.T) {
	supported, err := extractSupportedOps("../..", "arm64")
	if err != nil {
		t.Fatal(err)
	}
	// RNDR/RNDRRS are system-register operands, not independent mnemonics.
	for _, operation := range []string{"MRS", "MOVD", "WORD"} {
		if _, present := supported[operation]; !present {
			t.Errorf("RNG source carrier lost supported-op extraction: %s", operation)
		}
	}
}
