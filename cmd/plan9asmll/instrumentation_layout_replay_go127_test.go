//go:build go1.27

package main

import (
	"encoding/json"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm"
	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationObjectsPairedLayoutChangesRequireOriginalGoTypes(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	producerJSON, err := json.Marshal(producer.Metadata)
	if err != nil {
		t.Fatal(err)
	}
	proofJSON, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*plan9asm.FuncSig){
		"return type": func(sig *plan9asm.FuncSig) {
			sig.Ret, sig.Frame.Results[0].Type = plan9asm.I8, plan9asm.I8
		},
		"paired GoType and return": func(sig *plan9asm.FuncSig) {
			sig.Ret, sig.Frame.Results[0].Type = plan9asm.I8, plan9asm.I8
		},
		"result name":      func(sig *plan9asm.FuncSig) { sig.Frame.Results[0].Name = "invented" },
		"FP result offset": func(sig *plan9asm.FuncSig) { sig.Frame.Results[0].Offset += 8 },
		"invented parameter": func(sig *plan9asm.FuncSig) {
			sig.Args = []plan9asm.LLVMType{plan9asm.I8}
			sig.Frame.Params = []plan9asm.FrameSlot{{Type: plan9asm.I8, Index: 0, Field: -1}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changedProducer gotoolprofile.InstrumentationMetadataProof
			var changedProof gotoolprofile.InstrumentationConsumptionProof
			if err := json.Unmarshal(producerJSON, &changedProducer); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(proofJSON, &changedProof); err != nil {
				t.Fatal(err)
			}
			var layout plan9asm.FuncSig
			if err := json.Unmarshal(changedProducer.Declarations[0].Layout, &layout); err != nil {
				t.Fatal(err)
			}
			change(&layout)
			data, err := json.Marshal(layout)
			if err != nil {
				t.Fatal(err)
			}
			changedProducer.Declarations[0].Layout = data
			changedProof.Metadata.Declarations[0].Layout = data
			changedProof.Files[0].Declarations[0].Layout = data
			if name == "paired GoType and return" {
				changedProducer.Declarations[0].GoType = "func() uint8"
				changedProof.Metadata.Declarations[0].GoType = "func() uint8"
				changedProof.Files[0].Declarations[0].GoType = "func() uint8"
			}
			changedProof.MetadataSHA256 = gotoolprofile.InstrumentationMetadataSHA256(&changedProducer)
			if err := gotoolprofile.ValidateInstrumentationConsumption(input, &changedProducer, tools, ".", nil, &changedProof); err == nil {
				t.Fatal("paired metadata/source-layout forgery bypassed independent original Go type replay")
			}
		})
	}
}

func TestInstrumentationObjectsActualClosedAliasAndConstantSignature(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	input = replaceInstrumentationReplaySignature(t, input,
		"type Element uint16\ntype Alias = Element\nconst Count = 3\nfunc Probe(values [Count]Alias) uint64",
		strings.Replace(strings.Replace(input.Sources.Contents["probe_arm64.s"], "$0-8", "$0-16", 1), "ret+0(FP)", "ret+8(FP)", 1))
	producer, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), packages.Load)
	if err != nil {
		t.Fatal(err)
	}
	proof, tools, err := consumeInstrumentationAssembly(ctx, input, producer.Metadata, input.Original.SourceRoot, os.Environ(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err != nil {
		t.Fatal(err)
	}
}

func TestInstrumentationZeroSizedParameterOriginalGoAcceptedButConsumerUnclosed(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	input = replaceInstrumentationReplaySignature(t, input, "func Probe(values [0]byte) uint64", input.Sources.Contents["probe_arm64.s"])
	var actual *packages.Package
	load := func(config *packages.Config, patterns ...string) ([]*packages.Package, error) {
		loaded, err := packages.Load(config, patterns...)
		if err == nil && len(loaded) == 1 && len(loaded[0].Errors) == 0 && loaded[0].Types != nil {
			actual = loaded[0]
		}
		return loaded, err
	}
	_, err := captureInstrumentationMetadata(ctx, input, input.Original.SourceRoot, os.Environ(), t.TempDir(), load)
	if err == nil || !strings.Contains(err.Error(), "two-builder zero-sized parameter difference") {
		t.Fatalf("actual Go zero-sized declaration became source-invalid or claimed consumer proof: %v", err)
	}
	if actual == nil || actual.ExportFile == "" {
		t.Fatal("missing original stock-Go compiled/exported declaration")
	}
	if _, err := gotoolprofile.FileSHA256(actual.ExportFile); err != nil {
		t.Fatal(err)
	}
	derived, _, found, err := tryDeclSig(actual.Types.Scope(), "·Probe", input.Plan.PackagePath+".Probe", nil, "arm64", actual.TypesSizes, false)
	if err != nil || !found || len(derived.Args) != 0 || len(derived.Frame.Params) != 0 {
		t.Fatalf("actual CLI ABI0 builder did not omit the zero-sized parameter: %#v: %v", derived, err)
	}
	root, err := plan9asm.DeriveGoFuncABI0Signature(derived.Name, actual.Types.Scope().Lookup("Probe").(*types.Func), "arm64", actual.TypesSizes)
	if err != nil || len(root.Args) != 1 || len(root.Frame.Params) != 0 {
		t.Fatalf("root builder's unchanged zero-sized parameter difference disappeared: %#v: %v", root, err)
	}
	t.Logf("actual unchanged root Args=%v, CLI Args=%v", root.Args, derived.Args)
	t.Log("original same-mode Go export/asmdecl accepted; known root/CLI zero-sized parameter agreement remains consumer F")
}

func replaceInstrumentationReplaySignature(t *testing.T, input *gotoolprofile.InstrumentationConsumerInput, declaration, assembly string) *gotoolprofile.InstrumentationConsumerInput {
	t.Helper()
	source := strings.Replace(input.Sources.Contents["mode.go"], "func Probe() uint64", declaration, 1)
	for name, text := range map[string]string{"mode.go": source, "probe_arm64.s": assembly} {
		if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		input.Original.Sources[name] = featureBytesSHA256([]byte(text))
		input.Original.Headers[name] = text
	}
	sources, err := gotoolprofile.CaptureInstrumentationOriginalSourceInventory(input.Original, ".")
	if err != nil {
		t.Fatal(err)
	}
	plan, err := gotoolprofile.PlanInstrumentationOriginalPackage(input.Original, sources, input.Observation.Early, ".", nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := gotoolprofile.NewInstrumentationConsumerInput(input.Original, sources, input.Observation, plan)
	if err != nil {
		t.Fatal(err)
	}
	return result
}
