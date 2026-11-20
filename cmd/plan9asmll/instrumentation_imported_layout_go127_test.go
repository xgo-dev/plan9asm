//go:build go1.27

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestInstrumentationImportedSDKDeclarationActualObjects(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	input = replaceInstrumentationReplaySignature(t, input,
		"func Probe(values [bits.UintSize / 8]byte) syscall.Errno",
		strings.Replace(strings.Replace(input.Sources.Contents["probe_arm64.s"], "$0-8", "$0-16", 1), "ret+0(FP)", "ret+8(FP)", 1))
	source := strings.Replace(input.Sources.Contents["mode.go"], "import \"example.invalid/modeheader/dep\"",
		"import (\"example.invalid/modeheader/dep\"; \"math/bits\"; \"syscall\")", 1)
	if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, "mode.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Sources["mode.go"], input.Original.Headers["mode.go"] = featureBytesSHA256([]byte(source)), source
	replanInstrumentationMetadataFixture(t, input)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	input.TypeSources, err = gotoolprofile.CaptureInstrumentationTypeSources(ctx, binary, input.Original.SourceRoot,
		featureEnvironment(os.Environ(), input.Observation.Early.Environment), input, gotoolprofile.RunBounded)
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
	data, err := json.Marshal(proof)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gotoolprofile.DecodeInstrumentationConsumption(strings.NewReader(string(data)), input, producer.Metadata, tools, ".", nil); err != nil {
		t.Fatal(err)
	}
	t.Log("actual same-mode SDK constant/type, stock Go header/export/asmdecl and independent LLVM22 object/readback; no external execution")
}

func TestInstrumentationImportedSameModuleDeclarationActualObjects(t *testing.T) {
	input, ctx := instrumentationMetadataFixture(t, "darwin/arm64", gotoolprofile.InstrumentationRace, "0")
	input = replaceInstrumentationReplaySignature(t, input, "func Probe(values dep.Buffer) uint64",
		strings.Replace(strings.Replace(input.Sources.Contents["probe_arm64.s"], "$0-8", "$0-16", 1), "ret+0(FP)", "ret+8(FP)", 1))
	const name = "dep/layout.go"
	source := input.Original.Headers[name] + `
type Element uint16
type Alias = Element
const (
	_ = iota
	Count
	_ = iota
	Length
)
type Buffer [Length]Alias
`
	if err := os.WriteFile(filepath.Join(input.Original.SourceRoot, name), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	input.Original.Headers[name], input.Original.Sources[name] = source, featureBytesSHA256([]byte(source))
	replanInstrumentationMetadataFixture(t, input)
	binary, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	input.TypeSources, err = gotoolprofile.CaptureInstrumentationTypeSources(ctx, binary, input.Original.SourceRoot,
		featureEnvironment(os.Environ(), input.Observation.Early.Environment), input, gotoolprofile.RunBounded)
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
	if err := gotoolprofile.ValidateInstrumentationConsumption(input, producer.Metadata, tools, ".", nil, proof); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*gotoolprofile.InstrumentationConsumerInput){
		"missing original bytes": func(p *gotoolprofile.InstrumentationConsumerInput) { p.TypeSources.Dependencies[0].Contents = nil },
		"changed original bytes": func(p *gotoolprofile.InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Contents["dep/layout.go"] += "\nconst Changed=1\n"
		},
		"paired selector deletion": func(p *gotoolprofile.InstrumentationConsumerInput) { p.TypeSources = nil },
		"forged actual export": func(p *gotoolprofile.InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.Source.ExportSHA256 = strings.Repeat("0", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed gotoolprofile.InstrumentationConsumerInput
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			// Portable readers also fail if both metadata records are unchanged.
			if change(&changed); gotoolprofile.ValidateInstrumentationConsumption(&changed, producer.Metadata, tools, ".", nil, proof) == nil {
				t.Fatal("changed original source input was accepted as object evidence")
			}
			if changed.TypeSources != nil && !reflect.DeepEqual(changed.TypeSources, input.TypeSources) {
				actual, err := gotoolprofile.CaptureInstrumentationTypeSources(ctx, binary, input.Original.SourceRoot,
					featureEnvironment(os.Environ(), input.Observation.Early.Environment), &changed, gotoolprofile.RunBounded)
				if err == nil && reflect.DeepEqual(actual, changed.TypeSources) {
					t.Fatal("actual original source/export capture trusted a forged portable input")
				}
			}
		})
	}
}
