//go:build go1.27

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationObjectsRequireIndependentModeMetadataAndActualLLVM(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	output := instrumentationObjectFixtureOutput(t, input)
	proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), output)
	if err != nil {
		t.Fatal(err)
	}
	if proof.Status != "llvm_objects_only" || len(proof.Files) != 1 || proof.Files[0].Output.Object == "" {
		t.Fatalf("mode proof did not retain its actual object/nonruntime scope: %#v", proof)
	}
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gotoolprofile.DecodeInstrumentationConsumption(strings.NewReader(string(data)), input, producer.Metadata, tools, ".", nil); err != nil {
		t.Fatal(err)
	}
	recordInstrumentationObjectFixture(t, output, input, producer.Metadata, tools, proof)
	var ordinary gotoolprofile.SelectionProof
	if err := json.Unmarshal(data, &ordinary); err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateSelection(input.Original, &ordinary, nil, true); err == nil {
		t.Fatal("mode object proof was accepted by an ordinary translation reader")
	}
	for name, mutate := range map[string]func(*gotoolprofile.InstrumentationConsumptionProof){
		"old artifact consumer": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			p.Protocol = "actual_go_instrumentation_llvm_objects_v1"
		},
		"deleted artifact role": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Artifacts = nil },
		"paired role downgrade": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			p.Protocol = "actual_go_instrumentation_llvm_objects_v1"
			p.Files[0].Artifacts = nil
		},
		"source artifact role":      func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Artifacts.IR.Role = "module_source" },
		"changed artifact bytes":    func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Artifacts.IR.Bytes = 0 },
		"foreign target triple":     func(p *gotoolprofile.InstrumentationConsumptionProof) { p.LLVM.Triple = "aarch64-unknown-linux-gnu" },
		"ordinary protocol":         func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Protocol = gotoolprofile.ConsumerProtocol },
		"ordinary ID":               func(p *gotoolprofile.InstrumentationConsumptionProof) { p.ModeProfileID = input.Original.ID },
		"missing mode and metadata": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.ModeProfileID = ""; p.Metadata = nil },
		"missing metadata binding":  func(p *gotoolprofile.InstrumentationConsumptionProof) { p.MetadataSHA256 = "" },
		"missing sibling":           func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files = nil },
		"missing original CPP": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			delete(p.Files[0].CPP.Inputs, "module/probe_arm64.s")
		},
		"missing generated CPP": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			delete(p.Files[0].CPP.Inputs, "generated/"+input.Plan.PackagePath+"/go_asm.h")
		},
		"changed typed source":       func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].TypedSource += "\n" },
		"missing actual declaration": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Declarations = nil },
		"unknown declaration":        func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Declarations[0].Symbol += "Unknown" },
		"changed declaration": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			p.Files[0].Declarations[0].DeclarationSHA256 = strings.Repeat("0", 64)
		},
		"changed typed layout": func(p *gotoolprofile.InstrumentationConsumptionProof) {
			p.Files[0].Declarations[0].Layout = json.RawMessage(`{"Name":"example.invalid/modeheader.Probe","Ret":"i8"}`)
		},
		"missing object":       func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Output.Object = "" },
		"changed output scope": func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Files[0].Output.File = "unknown.s" },
		"changed LLVM":         func(p *gotoolprofile.InstrumentationConsumptionProof) { p.LLVM.SHA256 = strings.Repeat("0", 64) },
		"claim runtime":        func(p *gotoolprofile.InstrumentationConsumptionProof) { p.Status = "passed" },
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.InstrumentationConsumptionProof
			if err := json.Unmarshal(data, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, &changed); err == nil {
				t.Fatal("mode consumer accepted deletion/relabel or missing actual evidence")
			}
		})
	}
}

func TestInstrumentationObjectsActualModeAndCGOFamily(t *testing.T) {
	for _, config := range []struct {
		target string
		mode   gotoolprofile.InstrumentationMode
		cgo    string
	}{
		{"darwin/arm64", gotoolprofile.InstrumentationRace, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationMSan, "1"},
		{"linux/arm64", gotoolprofile.InstrumentationASan, "1"},
	} {
		t.Run(config.target+"/"+string(config.mode), func(t *testing.T) {
			input, ctx := instrumentationMetadataFixture(t, config.target, config.mode, config.cgo)
			producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
			if err != nil {
				t.Fatal(err)
			}
			output := instrumentationObjectFixtureOutput(t, input)
			proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), output)
			if err != nil {
				t.Fatal(err)
			}
			if len(proof.Files) != 1 || !strings.Contains(proof.Files[0].TypedSource, "$41") ||
				proof.ModeProfileID != input.ID || proof.Metadata.Selection.Packages[0].Macros.FeatureID != input.ID {
				t.Fatal("actual mode/header/layout was not consumed by the same selected original assembly")
			}
			if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err != nil {
				t.Fatal(err)
			}
			recordInstrumentationObjectFixture(t, output, input, producer.Metadata, tools, proof)
		})
	}
}

// Optional ignored artifacts retain the actual inputs, object and independently
// read producer/consumer proofs. This does not change test or proof semantics.
func instrumentationObjectFixtureOutput(t *testing.T, input *gotoolprofile.InstrumentationConsumerInput) string {
	t.Helper()
	root := os.Getenv("PLAN9ASM_INSTRUMENTATION_ARTIFACT_DIR")
	if root == "" {
		return t.TempDir()
	}
	if !filepath.IsAbs(root) {
		t.Fatal("instrumentation artifact root must be an explicit absolute owned directory")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	early := input.Observation.Early
	prefix := strings.ReplaceAll(early.Target, "/", "-") + "-" + string(early.Mode) + "-cgo" + early.CGOEnabled + "-"
	output, err := os.MkdirTemp(root, prefix)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("retained mode object fixture: %s", output)
	return output
}

func recordInstrumentationObjectFixture(t *testing.T, output string, input *gotoolprofile.InstrumentationConsumerInput, producer *gotoolprofile.InstrumentationMetadataProof, tools *gotoolprofile.InstrumentationLLVMTool, proof *gotoolprofile.InstrumentationConsumptionProof) {
	t.Helper()
	for name, value := range map[string]any{"input.json": input, "producer.json": producer, "llvm.json": tools, "consumption.json": proof} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(output, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
