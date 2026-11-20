package plan9asm

import (
	"os"
	"strings"
	"testing"
)

func TestRepositorySeparatesExternalCompatibility(t *testing.T) {
	for _, name := range []string{
		"cmd/plan9asmcorpus", "cmd/plan9asmdiscover", "internal/discoverymeta",
		"testdata/discovery", "testdata/corpus",
		"scripts/check-discovered-library-corpus.sh",
		"scripts/check-reported-library-corpus.sh",
	} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Errorf("external compatibility path must live in llgo-compat/plan9asm: %s (%v)", name, err)
		}
	}
	for _, name := range []string{
		"cmd/plan9asmscan", "cmd/plan9asmgooracle", "cmd/plan9asmll",
		"testdata/coverage", "testdata/conformance", "gotoolprofile",
		"scripts/check-go-asm-coverage.sh", "scripts/check-stdlib-corpus.sh",
	} {
		if _, err := os.Stat(name); err != nil {
			t.Errorf("translator/official regression path must remain: %s: %v", name, err)
		}
	}
	data, err := os.ReadFile(".github/workflows/go-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	for _, external := range []string{"discovered_library", "reported_library", "testdata/discovery", "cmd/plan9asmcorpus"} {
		if strings.Contains(string(data), external) {
			t.Errorf("translator CI still depends on external compatibility work: %s", external)
		}
	}
	data, err = os.ReadFile("scripts/check-arm64-plan9-corpus.sh")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "testdata/corpus") || !strings.Contains(string(data), "golang.org/x/arch@v0.31.0") {
		t.Fatal("official ARM64 decoder gate depends on removed external manifests or lost its pin")
	}
}
