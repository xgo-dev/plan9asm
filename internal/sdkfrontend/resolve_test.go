package sdkfrontend

import "testing"

func TestSDKResolverPreservesNativeNamespaceAndLogicalABISelectors(t *testing.T) {
	for source, want := range map[string]string{
		"·Value":                     "arbitrary/sdk.Value",
		"·Value<ABI0>":               "arbitrary/sdk.Value",
		"·Value<ABIInternal>":        "arbitrary/sdk.Value",
		"runtime·Value<ABIInternal>": "runtime.Value",
		"internal∕cpu·X86":           "internal/cpu.X86",
		"·literal<>":                 "arbitrary/sdk.literal<>",
		"·literal$local":             "arbitrary/sdk.literal$local",
		"·Value<ABIUnknown>":         "arbitrary/sdk.Value<ABIUnknown>",
	} {
		if actual := Resolve("arbitrary/sdk", source); actual != want {
			t.Fatalf("Resolve(%q) = %q, want %q", source, actual, want)
		}
	}
}
