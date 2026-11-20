package plan9asm

import (
	"reflect"
	"strings"
	"testing"
)

func TestInspectAssemblyCPPDriverDefinitionsPreserveOrderedTokens(t *testing.T) {
	inputs := []string{"DEFAULT", "EMPTY=", "EMIT=x·first", "EMIT=x∕second /* comment */ << 2\n"}
	got, err := InspectAssemblyCPPDriverDefinitions(inputs)
	if err != nil || len(got) != len(inputs) {
		t.Fatalf("driver definitions lost: %+v %v", got, err)
	}
	for index, definition := range got {
		if definition.Text != inputs[index] || definition.Definition.Function || definition.Definition.Parameters != nil {
			t.Fatal("exact ordered text or object-macro identity changed")
		}
	}
	if got[0].Definition.Replacement[0].Text != "1" || got[1].Definition.Replacement == nil ||
		len(got[1].Definition.Replacement) != 0 || got[2].Definition.Name != got[3].Definition.Name {
		t.Fatal("default, explicit empty or legal duplicate overwrite identity changed")
	}
	tokens := got[3].Definition.Replacement
	if len(tokens) != 4 || tokens[0].Text != "x∕second" || tokens[0].RecordedValue != "x/second" ||
		tokens[1].Text != "<<" || tokens[3].Kind != "newline" || tokens[0].Start != 0 {
		t.Fatalf("shared Go scanner/recording projection changed: %+v", tokens)
	}
	if got[2].Definition.Replacement[0].RecordedValue != "x.first" {
		t.Fatal("predefine canonical recording was not preserved")
	}
	inputs[0] = "MUTATED"
	got[3].Definition.Replacement[0].Text = "mutated"
	got[2].Definition.Name = "mutated"
	again, err := InspectAssemblyCPPDriverDefinitions([]string{"DEFAULT", "EMPTY=", "EMIT=x·first", "EMIT=x∕second /* comment */ << 2\n"})
	if err != nil || again[0].Text != "DEFAULT" || again[2].Definition.Name != "EMIT" ||
		again[3].Definition.Replacement[0].Text != "x∕second" {
		t.Fatal("query retained caller-owned mutable slices")
	}
	empty, err := InspectAssemblyCPPDriverDefinitions(nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatal("empty required driver definition set disappeared")
	}
}

func TestInspectAssemblyCPPDriverDefinitionsBoundsAndLexicalFailures(t *testing.T) {
	cases := map[string][]string{
		"count":      make([]string, 4097),
		"bytes":      {"BODY=" + strings.Repeat("x", 1<<20)},
		"empty name": {""},
		"assignment": {"=x"},
		"function":   {"F(x)=x"},
		"nonliteral": {"NAME /* key is not literal */=1"},
		"quote":      {"BODY=\"unterminated"},
	}
	for name, inputs := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := InspectAssemblyCPPDriverDefinitions(inputs)
			if got != nil || err == nil {
				t.Fatalf("unbounded/unclosed driver input accepted: %+v %v", got, err)
			}
		})
	}
	got, err := InspectAssemblyCPPDriverDefinitions([]string{"FLAGS=1=2", "FLAGS=", "FLAGS"})
	if err != nil || !reflect.DeepEqual([]string{got[0].Text, got[1].Text, got[2].Text}, []string{"FLAGS=1=2", "FLAGS=", "FLAGS"}) {
		t.Fatalf("query confused first '=' or ordered overwrite semantics: %+v %v", got, err)
	}
	boundary := "A=" + strings.Repeat(" ", (1<<20)-2)
	got, err = InspectAssemblyCPPDriverDefinitions([]string{boundary})
	if err != nil || len(got) != 1 || got[0].Text != boundary || len(got[0].Definition.Replacement) != 0 {
		t.Fatalf("exact byte-bound control failed: count=%d err=%v", len(got), err)
	}
	duplicates := make([]string, 4096)
	for index := range duplicates {
		duplicates[index] = "A=1"
	}
	got, err = InspectAssemblyCPPDriverDefinitions(duplicates)
	if err != nil || len(got) != len(duplicates) {
		t.Fatalf("legal ordered duplicates at the count bound failed: count=%d err=%v", len(got), err)
	}
}
