package gotoolprofile

import (
	"encoding/json"
	"testing"
)

func TestInstrumentationOriginalTypeImportMapCannotInventUnusedSourceEdges(t *testing.T) {
	input, _, _ := instrumentationImportedReplayFixture(t, "arm64")
	encoded, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstrumentationConsumerInput){
		"extra root spelling": func(p *InstrumentationConsumerInput) {
			p.TypeSources.RootImportMap["forged/unselected"] = "example.invalid/replay/dep"
		},
		"absolute root spelling": func(p *InstrumentationConsumerInput) {
			p.TypeSources.RootImportMap["/private/forged/import"] = "example.invalid/replay/dep"
		},
		"extra dependency self edge": func(p *InstrumentationConsumerInput) {
			p.TypeSources.Dependencies[0].Dependency.ImportMap["example.invalid/replay/dep"] = "example.invalid/replay/dep"
		},
		"same graph root spelling replacement": func(p *InstrumentationConsumerInput) {
			delete(p.TypeSources.RootImportMap, "example.invalid/replay/dep")
			p.TypeSources.RootImportMap["forged/replacement"] = "example.invalid/replay/dep"
		},
	} {
		t.Run(name, func(t *testing.T) {
			var changed InstrumentationConsumerInput
			if err := json.Unmarshal(encoded, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			// The complete dependency graph and exports remain internally
			// consistent. Only the independent original Go import bytes
			// establish that these observed spellings were really selected.
			if err := ValidateInstrumentationTypeSources(&changed, changed.TypeSources); err == nil {
				t.Fatal("original type source accepted an unused/replaced import spelling")
			}
		})
	}
}

func TestInstrumentationOriginalTypeImportMapUsesAllSelectedFileImports(t *testing.T) {
	input, pkg, declaration := instrumentationImportedReplayFixture(t, "arm64")
	// These imports are not needed by Probe's type, but still belong to the
	// actual selected source graph. Aliases, blank imports and duplicated
	// spellings across different files must not shrink that graph.
	const extra = `package replay
import (
	_ "example.invalid/replay/dep"
	different "example.invalid/replay/dep"
)
var _ = different.Count
`
	input.Plan.GoFiles = append(input.Plan.GoFiles, "extra.go")
	input.Sources.Contents["extra.go"] = extra
	input.Original.Sources["extra.go"] = bytesSHA256([]byte(extra))
	input.TypeSources.InputSHA256 = instrumentationTypeSourceInputSHA(input)
	if err := ValidateInstrumentationTypeSources(input, input.TypeSources); err != nil {
		t.Fatal(err)
	}
	if err := replayInstrumentationDeclarationLayouts(input, pkg, []InstrumentationDeclarationProof{declaration}); err != nil {
		t.Fatal(err)
	}
	for _, missing := range []string{"extra.go", "replay.go"} {
		t.Run("missing original "+missing, func(t *testing.T) {
			copy := *input
			sources := *input.Sources
			copy.Sources = &sources
			sources.Contents = make(map[string]string)
			for name, contents := range input.Sources.Contents {
				if name != missing {
					sources.Contents[name] = contents
				}
			}
			proof := *input.TypeSources
			copy.TypeSources = &proof
			proof.InputSHA256 = instrumentationTypeSourceInputSHA(&copy)
			if err := ValidateInstrumentationTypeSources(&copy, &proof); err == nil {
				t.Fatal("missing selected original source could authorize the same import map")
			}
		})
	}
}
