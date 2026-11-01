package gotoolprofile

import (
	"strings"
	"testing"
)

// These malformed-context cases run in the root's historical Go matrix too.
// Current-Go actual exports belong in the separately versioned oracle file.
func TestInstrumentationConsumerRequiresCompleteSeparateProtocol(t *testing.T) {
	if _, err := NewInstrumentationConsumerInput(nil, nil, nil, nil); err == nil {
		t.Fatal("missing original/mode inputs became a consumer context")
	}
	if err := ValidateInstrumentationConsumerInput(nil, ".", nil); err == nil {
		t.Fatal("missing context validated")
	}
	for _, reader := range []string{"", "{}", `{"protocol":"actual_go_cpu_profile_v2"}`} {
		if _, err := DecodeInstrumentationConsumerInput(strings.NewReader(reader), ".", nil); err == nil {
			t.Fatal("absent/ordinary context became instrumentation evidence")
		}
	}
	if _, err := DecodeInstrumentationConsumerInput(nil, ".", nil); err == nil {
		t.Fatal("nil context reader accepted")
	}
	if _, err := DecodeInstrumentationPackageSelection(strings.NewReader("{}"), nil, ".", nil); err == nil {
		t.Fatal("unbound package selection accepted")
	}
	if _, err := CaptureInstrumentationAssemblerMacros("", nil, ""); err == nil {
		t.Fatal("missing mode macros acquired a source role")
	}
}
