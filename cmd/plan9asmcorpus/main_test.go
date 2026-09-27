package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDiscoveryTargets(t *testing.T) {
	got, err := parseDiscoveryTargets("linux/amd64, windows/arm64")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"linux/amd64", "windows/arm64"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseDiscoveryTargets() = %#v, want %#v", got, want)
	}
	for _, value := range []string{"linux/amd64,linux/amd64", "linux/amd64,", "linux/riscv64"} {
		if _, err := parseDiscoveryTargets(value); err == nil {
			t.Errorf("parseDiscoveryTargets(%q) succeeded, want error", value)
		}
	}
}

func TestRepositoryManifestTracksReportedAssemblyFailures(t *testing.T) {
	manifest, err := loadManifest(filepath.Join("..", "..", "testdata", "corpus", "reported-libraries.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"coder-websocket":    "https://github.com/xgo-dev/llgo/issues/2464",
		"klauspost-compress": "https://github.com/xgo-dev/llgo/issues/2552",
		"go-hex":             "https://github.com/xgo-dev/llgo/issues/2576",
	}
	got := make(map[string]string, len(want))
	for _, library := range manifest.Libraries {
		if library.Origin == originLLGoIssue {
			got[library.ID] = strings.Join(library.Issues, ",")
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reported library issues = %#v, want %#v", got, want)
	}
	wantTargets := []string{
		"darwin/amd64",
		"darwin/arm64",
		"linux/386",
		"linux/amd64",
		"linux/arm",
		"linux/arm64",
		"windows/386",
		"windows/amd64",
		"windows/arm64",
		"js/wasm",
		"wasip1/wasm",
	}
	if !reflect.DeepEqual(manifest.Targets, wantTargets) {
		t.Fatalf("reported library targets = %#v, want %#v", manifest.Targets, wantTargets)
	}
}

func TestRepositoryManifestTracksEcosystemDiscoveries(t *testing.T) {
	manifest, err := loadManifest(filepath.Join("..", "..", "testdata", "corpus", "reported-libraries.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"aead-siphash":          true,
		"anacrolix-mmsg":        true,
		"btcsuite-fastsha256":   true,
		"cespare-xxhash-v1":     true,
		"cespare-xxhash-v2":     true,
		"chain-txvm":            true,
		"dchest-siphash":        true,
		"dgryski-go-bits":       true,
		"dgryski-go-marvin32":   true,
		"golang-snappy":         true,
		"klauspost-cpuid-v1":    true,
		"klauspost-cpuid-v2":    true,
		"klauspost-crc32":       true,
		"klauspost-reedsolomon": true,
		"modern-go-gls":         true,
		"minio-highwayhash":     true,
		"pierrec-lz4-v4":        true,
		"phuslu-log":            true,
		"roaring-bitmap":        true,
		"stevvooe-resumable":    true,
		"tmthrgd-go-bitwise":    true,
		"tmthrgd-go-popcount":   true,
		"x-net":                 true,
		"x-sys":                 true,
		"zeebo-this":            true,
	}
	got := make(map[string]bool, len(want))
	for _, library := range manifest.Libraries {
		if library.Origin == originEcosystemScan {
			got[library.ID] = true
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ecosystem-discovered libraries = %#v, want %#v", got, want)
	}
}

func TestTranslatorInvocationFiltersExactModule(t *testing.T) {
	invocation := makeTranslatorInvocation("/corpus", "example.com/root", "/tmp/out", "/repo", "/bin/llc-22", "/tmp/report.json")
	if invocation.Dir != "/corpus" {
		t.Fatalf("translator directory = %q, want corpus module", invocation.Dir)
	}
	if !containsString(invocation.Args, "-patterns=example.com/root/...") {
		t.Fatalf("translator args = %#v, want module package pattern", invocation.Args)
	}
	if !containsString(invocation.Args, "-module-path=example.com/root") {
		t.Fatalf("translator args = %#v, want exact module ownership filter", invocation.Args)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestValidateReportRejectsSilentlySkippedTarget(t *testing.T) {
	library := libraryManifest{
		ID: "example",
		Inventory: map[string]expectedInventory{
			"linux/amd64": {AsmFiles: 1, Packages: []string{"example.com/lib"}},
		},
	}
	report := matrixReport{
		Targets:      []targetReport{{Goos: "linux", Goarch: "amd64", TotalPkgs: 1, AsmPackages: []string{"example.com/lib"}, TotalAsm: 1, Success: 1}},
		TotalTargets: 1,
		TotalAsm:     1,
		Success:      1,
	}
	err := validateReport([]string{"linux/amd64", "linux/arm64"}, library, report)
	if err == nil || !strings.Contains(err.Error(), "target coverage changed") {
		t.Fatalf("validateReport() error = %v, want target coverage failure", err)
	}
}

func TestValidateReportRejectsInventoryDrift(t *testing.T) {
	library := libraryManifest{
		ID: "example",
		Inventory: map[string]expectedInventory{
			"linux/amd64": {AsmFiles: 1, Packages: []string{"example.com/lib"}},
		},
	}
	report := matrixReport{
		Targets:      []targetReport{{Goos: "linux", Goarch: "amd64", TotalPkgs: 1, AsmPackages: []string{"example.com/lib/newasm"}, TotalAsm: 1, Success: 1}},
		TotalTargets: 1,
		TotalAsm:     1,
		Success:      1,
	}
	err := validateReport([]string{"linux/amd64"}, library, report)
	if err == nil || !strings.Contains(err.Error(), "assembly inventory changed") {
		t.Fatalf("validateReport() error = %v, want inventory failure", err)
	}
}

func TestValidateReportAcceptsOnlyEvidenceBackedNotApplicableAssembly(t *testing.T) {
	library := libraryManifest{
		ID: "example",
		Inventory: map[string]expectedInventory{
			"linux/386": {AsmFiles: 1, Packages: []string{"example.com/lib"}},
		},
	}
	report := matrixReport{
		Targets: []targetReport{{
			Goos:          "linux",
			Goarch:        "386",
			TotalPkgs:     1,
			AsmPackages:   []string{"example.com/lib"},
			AsmFiles:      []string{"/go/pkg/mod/example.com/lib@v1.0.0/asm_386.s"},
			TotalAsm:      1,
			NotApplicable: 1,
			NotApplicableItems: []targetNotApplicableItem{{
				PkgPath:         "example.com/lib",
				AsmFile:         "/go/pkg/mod/example.com/lib@v1.0.0/asm_386.s",
				Kind:            targetNotApplicableGoTextArgSize,
				Symbol:          "example.com/lib.Block",
				DeclaredArgSize: 12,
				ExpectedArgSize: 16,
				Reason:          "TEXT argument size is incompatible with the Go declaration on 386",
			}},
		}},
		TotalTargets:  1,
		TotalAsm:      1,
		NotApplicable: 1,
	}
	if err := validateReport([]string{"linux/386"}, library, report); err != nil {
		t.Fatalf("validateReport() evidence-backed N/A error = %v", err)
	}

	report.Targets[0].NotApplicableItems[0].Kind = "unsupported_instruction"
	if err := validateReport([]string{"linux/386"}, library, report); err == nil || !strings.Contains(err.Error(), "invalid not-applicable evidence") {
		t.Fatalf("validateReport() error = %v, want invalid evidence failure", err)
	}
}
