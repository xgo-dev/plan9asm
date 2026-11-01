//go:build go1.27

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationObjectsLargeOriginalAssemblyRetainsCPPBytes(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	const assembly = "probe_arm64.s"
	// Large generated files are legitimate source. Comment padding keeps this
	// resource-bound regression cheap without inventing instruction coverage.
	source := input.Sources.Contents[assembly] + strings.Repeat("// generated source padding\n", 120000)
	if len(source) <= 2<<20 || len(source) >= 8<<20 {
		t.Fatalf("fixture lost its large-source boundary: %d bytes", len(source))
	}
	if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, assembly), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Sources[assembly] = featureBytesSHA256([]byte(source))
	inventory, err := gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input.Original, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input.Original, inventory, input.Observation.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	input, err = gotoolprofile.NewInstrumentationConsumerInput(input.Original, inventory, input.Observation, plan)
	if err != nil {
		t.Fatal(err)
	}
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Files) != 1 || proof.Files[0].InputContents["module/"+assembly] != source || proof.Files[0].Output.Object == "" {
		t.Fatal("large original source lost its whole-byte CPP or actual LLVM object witness")
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gotoolprofile.DecodeInstrumentationConsumption(bytes.NewReader(data), input, producer.Metadata, tools, ".", nil); err != nil {
		t.Fatal(err)
	}
	proof.Files[0].InputContents["module/"+assembly] += "// changed\n"
	if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err == nil {
		t.Fatal("large-source allowance erased independent original CPP byte binding")
	}
}
