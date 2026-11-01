package gotoolprofile

import (
	"strings"
	"testing"
)

func TestInstrumentationInvocationReadersNeedIndependentModeSourcePhaseAndTools(t *testing.T) {
	for _, input := range []*InstrumentationConsumerInput{nil, {}, {Plan: &InstrumentationOriginalPackagePlan{}}} {
		for _, phase := range []InstrumentationInvocationPhase{InstrumentationMetadataQuery, InstrumentationObjectCompile, "passed", ""} {
			if _, err := NewInstrumentationInvocation(input, phase, nil, nil, nil); err == nil {
				t.Fatal("missing original mode context acquired a CLI result")
			}
			if err := ValidateInstrumentationInvocation(input, phase, nil, nil, &InstrumentationInvocationProof{}); err == nil {
				t.Fatal("missing mode/phase/tool prerequisites validated")
			}
			for _, contents := range []string{"", "{}", `{"protocol":"actual_go_cpu_profile_consumer_v1"}`,
				`{"protocol":"actual_go_instrumentation_cli_invocation_v1","phase":"passed"}`,
				`{"protocol":"actual_go_instrumentation_cli_invocation_v1","unknown":true}`, "{}\n{}"} {
				if _, err := DecodeInstrumentationInvocation(strings.NewReader(contents), input, phase, nil, nil); err == nil {
					t.Fatal("ordinary, missing, unknown or trailing mode invocation accepted")
				}
			}
		}
	}
	if _, err := DecodeInstrumentationInvocation(nil, nil, InstrumentationObjectCompile, nil, nil); err == nil {
		t.Fatal("nil mode reader accepted")
	}
}
