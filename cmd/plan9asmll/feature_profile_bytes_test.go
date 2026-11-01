package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
)

func TestFeatureConsumerCompleteJSONBeyondLegacyByteLimit(t *testing.T) {
	input, directory := featureConsumerFixture(t)
	t.Chdir(directory)
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	// Leading JSON whitespace changes no source, profile, closure or role.
	// The complete input, not a truncated prefix, must reach all normal guards.
	data = append(bytes.Repeat([]byte(" "), 4<<20), data...)
	filename := filepath.Join(t.TempDir(), "complete-profile.json")
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	consumer, err := loadFeatureConsumer(ctx, filename, t.TempDir(), "linux/amd64", input.Module, nil)
	if err != nil {
		t.Fatalf("complete source-bound JSON beyond the old transport limit: %v", err)
	}
	if !reflect.DeepEqual(consumer.Input, input) {
		t.Fatal("transport changed the complete input or its source roles")
	}
	for name, change := range map[string]func(*featureInput){
		"module identity": func(input *featureInput) { input.Module = "example.invalid/other" },
		"source identity": func(input *featureInput) { input.Sources["probe_amd64.s"] = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			var changed featureInput
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			encoded, err := gotoolprofile.MarshalConsumerInput(&changed)
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(bytes.Repeat([]byte(" "), 4<<20), encoded...)
			if err := os.WriteFile(filename, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := loadFeatureConsumer(ctx, filename, t.TempDir(), "linux/amd64", input.Module, nil); err == nil {
				t.Fatal("larger transport bypassed an unchanged source/profile guard")
			}
		})
	}
}

func TestFeatureConsumerCLICompleteJSONProducesObjectProof(t *testing.T) {
	input, directory := featureConsumerFixture(t)
	filename := writeFeatureInput(t, input)
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	data = append(bytes.Repeat([]byte(" "), 4<<20), data...)
	if err := os.WriteFile(filename, data, 0600); err != nil {
		t.Fatal(err)
	}
	output, report := t.TempDir(), filepath.Join(t.TempDir(), "report.json")
	args := []string{"-goos=linux", "-goarch=amd64", "-patterns=.", "-module-path=" + input.Module,
		"-asm-files=probe_amd64.s", "-feature-profile=" + filename, "-feature-timeout=1m",
		"-compile", "-keep-obj", "-out=" + output, "-report=" + report}
	encoded, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	env := append(os.Environ(), "PLAN9ASM_CPUCLI_ARGS="+string(encoded))
	_, stderr, err := gotoolprofile.RunBounded(ctx, directory, env, os.Args[0], "-test.run=^TestFeatureConsumerCLIChild$")
	if err != nil {
		t.Fatalf("actual complete-profile CLI object stage: %v\n%s", err, stderr)
	}
	data, err = os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	var result runReport
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if result.Success != 1 || result.Failed != 0 || result.FeatureSelection == nil {
		t.Fatal("CLI did not produce its original object/source-consumption proof")
	}
	if err := gotoolprofile.ValidateSelection(input, result.FeatureSelection, nil, true); err != nil {
		t.Fatalf("independent same-profile object proof readback: %v", err)
	}
}

func TestFeatureConsumerCLIOverflowIsExplicitBeforeIdentity(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "oversized-profile.json")
	if err := os.WriteFile(filename, bytes.Repeat([]byte(" "), gotoolprofile.ConsumerInputJSONLimit+1), 0600); err != nil {
		t.Fatal(err)
	}
	consumer, err := loadFeatureConsumer(context.Background(), filename, t.TempDir(), "linux/amd64", "example.invalid/x", nil)
	if consumer != nil || err == nil || !strings.Contains(err.Error(), "byte bound") || strings.Contains(err.Error(), "EOF") {
		t.Fatalf("oversized profile did not report the real bounded transport failure: %v", err)
	}
}
