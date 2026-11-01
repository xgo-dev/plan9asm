package gotoolprofile

import (
	"fmt"
	"strings"
	"testing"
)

func TestModeledWASMFeaturesMatchVersionedRegistration(t *testing.T) {
	for minor := 20; minor <= 27; minor++ {
		for _, setting := range []string{"", "satconv", "signext", "satconv,signext", "signext,satconv"} {
			t.Run(fmt.Sprintf("go1.%d/%s", minor, setting), func(t *testing.T) {
				var expected []string
				for _, feature := range []string{"satconv", "signext"} {
					if minor >= 26 || strings.Contains(setting, feature) {
						expected = append(expected, "wasm."+feature)
					}
				}
				actual := discoveryModeledCPUFeatures(nil, "wasm", setting, minor)
				if !equalDiscoveryStrings(actual, expected) {
					t.Fatalf("GOWASM=%q: got %q, want %q", setting, actual, expected)
				}
			})
		}
	}
}
