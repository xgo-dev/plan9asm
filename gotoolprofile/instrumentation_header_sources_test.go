package gotoolprofile

import (
	"encoding/json"
	"strings"
	"testing"
)

func instrumentationHeaderReplayFixture(t *testing.T, arch string) (*InstrumentationConsumerInput, *InstrumentationNativeHeaderSourceProof) {
	t.Helper()
	input, _, _ := instrumentationImportedReplayFixture(t, arch)
	const metadata = "module example.invalid/replay\n\ngo 1.20\n"
	text := input.Sources.Contents["replay.go"] + "\ntype Tail struct { Value byte; End [0]byte }\n"
	input.Sources.Contents["replay.go"] = text
	input.Original.Sources["replay.go"] = bytesSHA256([]byte(text))
	input.Original.Sources["go.mod"] = bytesSHA256([]byte(metadata))
	input.TypeSources.InputSHA256 = instrumentationTypeSourceInputSHA(input)
	return input, &InstrumentationNativeHeaderSourceProof{
		Protocol: InstrumentationNativeHeaderSourcesProtocol,
		Types:    input.TypeSources, GoMods: map[string]string{"original": metadata},
	}
}

func TestInstrumentationNativeHeaderPropertiesRetainImportedConstantsAndGCTail(t *testing.T) {
	for _, arch := range []string{"386", "amd64", "arm", "arm64", "wasm"} {
		t.Run(arch, func(t *testing.T) {
			input, proof := instrumentationHeaderReplayFixture(t, arch)
			definitions, language, err := ReplayInstrumentationNativeGeneratedHeader(input, proof)
			if err != nil {
				t.Fatal(err)
			}
			rowSize := "16"
			if arch == "386" || arch == "arm" {
				rowSize = "12"
			}
			for name, expected := range map[string]string{
				"const_Size": "1", "Alias__size": rowSize,
				"Alias_First": "0", "Alias_Payload": "2", "Alias_Last": "8",
				"Tail__size": "2", "Tail_Value": "0", "Tail_End": "1",
			} {
				if definitions[name] != expected {
					t.Fatalf("native property %s=%q, want %q", name, definitions[name], expected)
				}
			}
			if language != "go1.20" {
				t.Fatalf("original module language changed: %s", language)
			}
		})
	}
}

func TestInstrumentationNativeHeaderPropertiesRejectLostLanguageAndSourceClosure(t *testing.T) {
	input, proof := instrumentationHeaderReplayFixture(t, "arm64")
	encoded, err := json.Marshal(struct {
		Input *InstrumentationConsumerInput
		Proof *InstrumentationNativeHeaderSourceProof
	}{input, proof})
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*InstrumentationConsumerInput, *InstrumentationNativeHeaderSourceProof){
		"role deletion":   func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) { p.Types = nil },
		"downgrade":       func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) { p.Protocol = "v0" },
		"module deletion": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) { p.GoMods = nil },
		"language": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) {
			p.GoMods["original"] = strings.Replace(p.GoMods["original"], "1.20", "1.21", 1)
		},
		"extra module": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) {
			p.GoMods["extra"] = p.GoMods["original"]
		},
		"missing imported bytes": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) {
			p.Types.Dependencies[0].Contents = nil
		},
		"changed imported bytes": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) {
			p.Types.Dependencies[0].Contents["dep/types.go"] += "\n"
		},
		"paired imported bytes": func(_ *InstrumentationConsumerInput, p *InstrumentationNativeHeaderSourceProof) {
			dependency := &p.Types.Dependencies[0]
			dependency.Contents["dep/types.go"] += "\n"
			dependency.Dependency.Source.GoSHA256["dep/types.go"] = bytesSHA256([]byte(dependency.Contents["dep/types.go"]))
		},
		"input mode/target": func(p *InstrumentationConsumerInput, _ *InstrumentationNativeHeaderSourceProof) {
			p.Plan.Target = "linux/386"
		},
		"root bytes": func(p *InstrumentationConsumerInput, _ *InstrumentationNativeHeaderSourceProof) {
			p.Sources.Contents["replay.go"] += "\n"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed struct {
				Input *InstrumentationConsumerInput
				Proof *InstrumentationNativeHeaderSourceProof
			}
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(changed.Input, changed.Proof)
			if _, _, err := ReplayInstrumentationNativeGeneratedHeader(changed.Input, changed.Proof); err == nil {
				t.Fatal("changed query inputs acquired native header planning authority")
			}
		})
	}
}

func TestInstrumentationNativeHeaderPropertiesBoundImportedStringExpansionBeforeTypes(t *testing.T) {
	input, proof := instrumentationHeaderReplayFixture(t, "arm64")
	dependency := &proof.Types.Dependencies[0]
	dependency.Contents["dep/types.go"] += "\nconst Seed = \"abcdefghijklmnop\"\n"
	dependency.Dependency.Source.GoSHA256["dep/types.go"] = bytesSHA256([]byte(dependency.Contents["dep/types.go"]))
	input.Original.Sources["dep/types.go"] = dependency.Dependency.Source.GoSHA256["dep/types.go"]
	text := input.Sources.Contents["replay.go"] + "\nconst S0 = renamed.Seed\n"
	for _, pair := range [][2]string{{"S1", "S0"}, {"S2", "S1"}, {"S3", "S2"}, {"S4", "S3"}, {"S5", "S4"}, {"S6", "S5"}, {"S7", "S6"}, {"S8", "S7"}, {"S9", "S8"}, {"S10", "S9"}, {"S11", "S10"}, {"S12", "S11"}, {"S13", "S12"}, {"S14", "S13"}, {"S15", "S14"}, {"S16", "S15"}, {"S17", "S16"}, {"S18", "S17"}, {"S19", "S18"}, {"S20", "S19"}} {
		text += "const " + pair[0] + " = " + pair[1] + " + " + pair[1] + "\n"
	}
	input.Sources.Contents["replay.go"] = text
	input.Original.Sources["replay.go"] = bytesSHA256([]byte(text))
	proof.Types.InputSHA256 = instrumentationTypeSourceInputSHA(input)
	_, _, err := ReplayInstrumentationNativeGeneratedHeader(input, proof)
	if !NativeHeaderSourceDomainUnsupported(err) {
		t.Fatalf("imported lazy string expansion was not bounded before typecheck: %v", err)
	}
}

func TestInstrumentationNativeHeaderPropertiesKeepUnknownLanguageConservative(t *testing.T) {
	for _, language := range []string{"", "go 1.19\n", "go 1.28\n"} {
		t.Run(strings.TrimSpace(language), func(t *testing.T) {
			input, proof := instrumentationHeaderReplayFixture(t, "arm64")
			text := "module example.invalid/replay\n" + language
			proof.GoMods["original"] = text
			input.Original.Sources["go.mod"] = bytesSHA256([]byte(text))
			proof.Types.InputSHA256 = instrumentationTypeSourceInputSHA(input)
			if _, _, err := ReplayInstrumentationNativeGeneratedHeader(input, proof); !NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("unregistered module language did not retain its precise unsupported query role: %v", err)
			}
			proof.GoMods["original"] += "changed"
			if _, _, err := ReplayInstrumentationNativeGeneratedHeader(input, proof); err == nil || NativeHeaderSourceDomainUnsupported(err) {
				t.Fatalf("source corruption was swallowed by an unsupported query domain: %v", err)
			}
		})
	}
}
