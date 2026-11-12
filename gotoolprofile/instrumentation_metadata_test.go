package gotoolprofile

import (
	"strings"
	"testing"
)

func TestInstrumentationMetadataAndObjectReadersRequireIndependentContexts(t *testing.T) {
	for _, input := range []*InstrumentationConsumerInput{nil, {}, {Plan: &InstrumentationOriginalPackagePlan{}}} {
		if _, err := InstrumentationHeaderCompilerFlags(input); err == nil {
			t.Fatal("missing actual mode context supplied compiler flags")
		}
		if _, err := InstrumentationPackageLoadFlags(input); err == nil {
			t.Fatal("missing actual mode context supplied package flags")
		}
		if _, err := DecodeInstrumentationMetadata(strings.NewReader(`{}`), input, ".", nil); err == nil {
			t.Fatal("unbound metadata acquired a mode/source role")
		}
		if _, err := DecodeInstrumentationConsumption(strings.NewReader(`{}`), input, nil, nil, ".", nil); err == nil {
			t.Fatal("unbound objects acquired mode/source/LLVM evidence")
		}
	}
}
