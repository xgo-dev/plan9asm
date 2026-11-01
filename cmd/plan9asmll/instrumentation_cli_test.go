package main

import (
	"context"
	"flag"
	"testing"
)

func TestInstrumentationCLIExplicitDefaultOrEmptyFlagCannotEraseModeEntry(t *testing.T) {
	for _, args := range [][]string{
		nil, {"-instrumentation-package-dir=."}, {"-instrumentation-profile="}, {"-instrumentation-metadata="},
	} {
		flags := flag.NewFlagSet("mode", flag.ContinueOnError)
		flags.String("instrumentation-package-dir", ".", "")
		flags.String("instrumentation-profile", "", "")
		flags.String("instrumentation-metadata", "", "")
		if err := flags.Parse(args); err != nil {
			t.Fatal(err)
		}
		if requestedInstrumentationCLI(flags) != (len(args) != 0) {
			t.Fatalf("explicit mode entry was erased, or ordinary entry changed: %v", args)
		}
	}
}

func TestInstrumentationCLIOptionsCannotDowngradeToOrdinaryOrPartialOutput(t *testing.T) {
	base := instrumentationCLIOptions{
		Profile: "input.json", Directory: ".", Metadata: "metadata.json", Output: "objects",
		Targets: []targetSpec{{Goos: "linux", Goarch: "amd64"}}, Patterns: []string{"example.invalid/mode"},
		Module: "example.invalid/mode", AsmFiles: []string{"probe_amd64.s"},
		Compile: true, KeepObject: true, OptLevel: 0, StrictLoad: true,
	}
	if err := validateInstrumentationCLIOptions(base); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*instrumentationCLIOptions){
		"missing context":              func(o *instrumentationCLIOptions) { o.Profile = "" },
		"ordinary pairing":             func(o *instrumentationCLIOptions) { o.OrdinaryProfile = "ordinary.json" },
		"missing metadata":             func(o *instrumentationCLIOptions) { o.Metadata = "" },
		"no compiler":                  func(o *instrumentationCLIOptions) { o.Compile = false },
		"discard physical object":      func(o *instrumentationCLIOptions) { o.KeepObject = false },
		"different compiler selection": func(o *instrumentationCLIOptions) { o.LLC = "other-llc" },
		"different optimization":       func(o *instrumentationCLIOptions) { o.OptLevel = 2 },
		"target erased":                func(o *instrumentationCLIOptions) { o.Targets = nil },
		"matrix":                       func(o *instrumentationCLIOptions) { o.AllTargets = true },
		"explicit matrix alias":        func(o *instrumentationCLIOptions) { o.ExplicitTargets = true },
		"package union":                func(o *instrumentationCLIOptions) { o.Patterns = append(o.Patterns, "std") },
		"module erased":                func(o *instrumentationCLIOptions) { o.Module = "" },
		"scope erased":                 func(o *instrumentationCLIOptions) { o.AsmFiles = nil },
		"output erased":                func(o *instrumentationCLIOptions) { o.Output = "" },
		"list":                         func(o *instrumentationCLIOptions) { o.ListOnly = true },
		"signature query":              func(o *instrumentationCLIOptions) { o.SignatureQuery = true },
		"partial":                      func(o *instrumentationCLIOptions) { o.Limit = 1 },
		"non-strict loader":            func(o *instrumentationCLIOptions) { o.StrictLoad = false },
		"partial failures":             func(o *instrumentationCLIOptions) { o.KeepGoing = true },
		"changed IR policy":            func(o *instrumentationCLIOptions) { o.Annotate = true },
		"query/object conflation":      func(o *instrumentationCLIOptions) { o.MetadataOnly = true },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			change(&changed)
			if err := validateInstrumentationCLIOptions(changed); err == nil {
				t.Fatal("incomplete/mixed mode request was accepted")
			}
		})
	}
	query := base
	query.MetadataOnly, query.Compile, query.KeepObject, query.Metadata = true, false, false, ""
	if err := validateInstrumentationCLIOptions(query); err != nil {
		t.Fatal(err)
	}
	if _, err := runInstrumentationCLI(nil, base); err == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runInstrumentationCLI(ctx, base); err == nil {
		t.Fatal("cancelled context accepted")
	}
}
