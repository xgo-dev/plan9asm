package gotoolprofile

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestInstrumentationExportNMObservedSourceSpellings(t *testing.T) {
	root := t.TempDir()
	archive := filepath.Join(root, "cache with spaces", "export.a")
	directory := filepath.Join(root, "source with spaces")
	for _, source := range []string{directory, filepath.ToSlash(directory)} {
		output := archive + "(_go_.o):\t 42 ? gofile.." + source + "/base.go\n" +
			archive + "(mode_race.o):\t 80 T " + instrumentationExportModule + ".marker\n"
		normalized := instrumentationExportNMOutput(output, archive, directory)
		if !strings.Contains(normalized, "gofile..@marker/base.go\n") {
			t.Fatalf("captured source spelling was not normalized: %q", normalized)
		}
		if err := validateInstrumentationExportNM(normalized, InstrumentationRace); err != nil {
			t.Fatalf("actual source spelling broke complete nm grammar: %v", err)
		}
		foreign := strings.ReplaceAll(output, source, filepath.Join(root, "unobserved source"))
		if err := validateInstrumentationExportNM(instrumentationExportNMOutput(foreign, archive, directory), InstrumentationRace); err == nil {
			t.Fatal("unknown source symbol text was erased into the observed marker")
		}
	}
}

func TestInstrumentationExportNMUndefinedSymbolGrammarIsComplete(t *testing.T) {
	defined := "@export(mode_race.o):\t 42 T " + instrumentationExportModule + ".marker\n"
	for _, undefined := range []string{"U", "U unresolved.symbol"} {
		output := "@export(mode_race.o):\t " + undefined + "\n" + defined
		if err := validateInstrumentationExportNM(output, InstrumentationRace); err != nil {
			t.Fatalf("rejected actual Go nm undefined grammar %q: %v", undefined, err)
		}
	}
	for _, body := range []string{
		"U missing unexpected warning", "U missing error", "U two symbols", "U missing\twarning",
		"U missing -toolchain-error", "missing U", "warning", "", "42 U missing",
	} {
		t.Run(strings.ReplaceAll(body, "\t", "_"), func(t *testing.T) {
			output := "@export(mode_race.o):\t " + body + "\n" + defined
			if err := validateInstrumentationExportNM(output, InstrumentationRace); err == nil {
				t.Fatalf("accepted unknown nm undefined-symbol text %q", body)
			}
		})
	}
}
