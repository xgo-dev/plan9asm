//go:build go1.27

package gostaticstorage

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestGoStaticStorageRepeatedLiveSelectionPreservesOriginalCompilerPrior(t *testing.T) {
	directory, binary, _ := fixture(t)
	// Existing physical-input, report, lifetime and unknown-field guard roots
	// cover those boundaries separately. This narrow witness uses only actual
	// stock-Go commands and archives, never a wrapper or simulated compiler.
	observation, report := captured(t, request(t, directory, binary, "linux/amd64"))
	if !reflect.DeepEqual(report.CommandArguments, selectionArguments()) || ValidateReport(report) != nil {
		t.Fatal("actual original forced-build compiler prior is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for index := 0; index < 3; index++ {
		if err := observation.Verify(ctx); err != nil {
			t.Fatal("unchanged actual source/export selection must remain valid", err)
		}
		if !reflect.DeepEqual(observation.report, report) {
			t.Fatal("live verification rewrote original compiler arguments, outputs or source evidence")
		}
	}
	// All captured file bytes still match. A live command must nevertheless
	// observe a different compiler profile instead of reusing an earlier
	// selection/result. No SDK or shared tool file is changed by this test.
	originalEnvironment := append([]string(nil), observation.request.Environment...)
	changed := false
	for index, pair := range observation.request.Environment {
		if pair == "GOAMD64=v1" {
			observation.request.Environment[index], changed = "GOAMD64=v2", true
		}
	}
	if !changed {
		t.Fatal("actual command-environment mutation did not apply")
	}
	if err := observation.Verify(ctx); !errors.Is(err, ErrContext) {
		t.Fatal("live selection accepted another actual compiler profile", err)
	}
	observation.request.Environment = originalEnvironment
	if err := observation.Verify(ctx); !errors.Is(err, ErrContext) {
		t.Fatal("restoring the actual environment revived a revoked observation", err)
	}
}
