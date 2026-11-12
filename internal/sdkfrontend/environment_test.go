package sdkfrontend

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// Keep the shared selection rule portable to Go 1.20, not only covered by a
// frontend nested module whose current package loader needs a newer toolchain.
func TestGoEnvFileSelection(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing-goenv")
	existing := filepath.Join(dir, "saved-goenv")
	const saved = "GOFLAGS=-tags=saved_profile\n"
	if err := os.WriteFile(existing, []byte(saved), 0600); err != nil {
		t.Fatal(err)
	}
	physical, err := sourcepath.Resolve(existing)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, requested, actual, want string
	}{
		{"absent implicit file", "", missing, "off"},
		{"saved implicit file", "", existing, physical},
		{"explicit missing file", missing, missing, missing},
		{"explicit saved file", existing, existing, physical},
		{"explicit off", "off", "off", "off"},
		// Stock Go reports an empty GOENV for explicit off. The enclosing
		// ordinary environment encoder retains the explicit command spelling.
		{"stock explicit off observation", "off", "", ""},
		{"empty actual configuration", "", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := GoEnvFile(test.requested, test.actual)
			if err != nil || got != test.want {
				t.Fatalf("compiler configuration selection: got %q, %v; want %q", got, err, test.want)
			}
		})
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("resolving implicit defaults created a configuration file: %v", err)
	}
	if data, err := os.ReadFile(existing); err != nil || string(data) != saved {
		t.Fatalf("resolving defaults changed saved compiler settings: %v", err)
	}
}
