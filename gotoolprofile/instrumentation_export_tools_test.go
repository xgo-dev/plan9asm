package gotoolprofile

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These guards observe the actual selected SDK environment, registered source
// and executable routes. The injected failures below are deliberately unknown
// command failures, never original-Go ABI rejection or object evidence.
func instrumentationExportRecheckFixture(t *testing.T) (context.Context, string, string, map[string]string, map[string]string, *InstrumentationEarlyObservation, *discoveryFeatureToolState) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	actual, commandContext, err := instrumentationObserverEnvironment(ctx, binary, directory, os.Environ(), RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	sources, err := CaptureInstrumentationSourceProof(actual["GOROOT"], actual["GOVERSION"])
	if err != nil {
		t.Fatal(err)
	}
	tools, err := captureDiscoveryFeatureSubtools(ctx, binary, os.Environ(), actual, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual %s registered SDK sources and complete tool routes observed", actual["GOVERSION"])
	return ctx, binary, directory, actual, commandContext, &InstrumentationEarlyObservation{SourceRules: sources}, tools
}

func TestInstrumentationExportRecheckRetainsUnknownSubtoolCause(t *testing.T) {
	ctx, binary, directory, actual, commandContext, early, before := instrumentationExportRecheckFixture(t)
	for _, tool := range []string{"nm", "vet"} {
		for _, cause := range []error{errors.New("fixture-bound unknown tool refusal"), context.DeadlineExceeded} {
			t.Run(tool+"/"+cause.Error(), func(t *testing.T) {
				seen := 0
				run := func(ctx context.Context, dir string, env []string, driver string, args ...string) ([]byte, []byte, error) {
					if reflect.DeepEqual(args, []string{"tool", "-n", tool}) {
						seen++
						return nil, nil, cause
					}
					return RunBounded(ctx, dir, env, driver, args...)
				}
				err := recheckInstrumentationExportInputs(ctx, binary, directory, os.Environ(), actual, commandContext, early, nil, "", "", before, run)
				if err == nil || seen != 1 || !errors.Is(err, cause) || !strings.Contains(err.Error(), tool) {
					t.Fatalf("actual SDK routing guard lost its bound unknown %s cause: seen=%d error=%v", tool, seen, err)
				}
			})
		}
	}
}

func TestInstrumentationExportRecheckDescribesRoutingFieldsWithoutPaths(t *testing.T) {
	ctx, binary, directory, actual, commandContext, early, observed := instrumentationExportRecheckFixture(t)
	const secret = "/private/fixture-routing-identity"
	for _, scenario := range []struct {
		name   string
		field  string
		mutate func(*discoveryFeatureToolState)
	}{
		{"directory", "directory", func(p *discoveryFeatureToolState) { p.directory = secret }},
		{"routing", "routing_sha256", func(p *discoveryFeatureToolState) { p.routing = strings.Repeat("0", 64) }},
		{"dispatcher", "dispatcher_sha256", func(p *discoveryFeatureToolState) { p.dispatcher = strings.Repeat("0", 64) }},
		{"binary", "binary_sha256[nm]", func(p *discoveryFeatureToolState) { p.digests["nm"] = strings.Repeat("0", 64) }},
		{"origin", "binary_origins[compile]", func(p *discoveryFeatureToolState) { p.origins["compile"] = secret }},
		{"extra_key", "binary_sha256", func(p *discoveryFeatureToolState) { p.digests[secret] = strings.Repeat("0", 64) }},
		{"nil_map", "binary_sha256", func(p *discoveryFeatureToolState) { p.digests = nil }},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			before := *observed
			before.digests = copyInstrumentationHashes(observed.digests)
			before.origins = copyInstrumentationHashes(observed.origins)
			scenario.mutate(&before)
			err := recheckInstrumentationExportInputs(ctx, binary, directory, os.Environ(), actual, commandContext, early, nil, "", "", &before, RunBounded)
			if err == nil || !strings.Contains(err.Error(), scenario.field) || !strings.Contains(err.Error(), "before_sha256=") || !strings.Contains(err.Error(), "after_sha256=") {
				t.Fatalf("exact tool mismatch lacks a bounded field/digest diagnosis: %v", err)
			}
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), actual["GOROOT"]) || strings.Contains(err.Error(), actual["GOCACHE"]) {
				t.Fatal("tool difference diagnostic leaked a physical route")
			}
		})
	}
}

func TestInstrumentationExportToolDifferenceRetainsExactIdentityWithoutPaths(t *testing.T) {
	const secret = "/private/fixture-routing-identity"
	states := []*discoveryFeatureToolState{
		nil,
		{},
		{digests: map[string]string{}},
		{digests: map[string]string{"nm": ""}},
		{digests: map[string]string{secret: ""}},
		{origins: map[string]string{}},
		{origins: map[string]string{"nm": ""}},
		{directory: secret},
		{routing: secret},
		{dispatcher: secret},
	}

	for i, before := range states {
		for j, after := range states {
			beforeSHA, err := instrumentationExportToolStateSHA(before)
			if err != nil {
				t.Fatal(err)
			}
			afterSHA, err := instrumentationExportToolStateSHA(after)
			if err != nil {
				t.Fatal(err)
			}
			if (beforeSHA == afterSHA) != (i == j) {
				t.Fatalf("diagnostic identity discarded distinct state %d/%d", i, j)
			}

			difference, err := instrumentationExportToolDifference(before, after)
			if err != nil || strings.Contains(difference, secret) || len(difference) > 600 {
				t.Fatalf("unbounded or path-bearing state difference %d/%d: %q, %v", i, j, difference, err)
			}
		}
	}

	before := &discoveryFeatureToolState{digests: map[string]string{"asm": "a", "vet": "b"}}
	after := &discoveryFeatureToolState{digests: map[string]string{"vet": "b", "asm": "a"}}
	beforeSHA, err := instrumentationExportToolStateSHA(before)
	if err != nil {
		t.Fatal(err)
	}
	afterSHA, err := instrumentationExportToolStateSHA(after)
	if err != nil || beforeSHA != afterSHA {
		t.Fatal("map insertion order changed the diagnostic digest")
	}
}
