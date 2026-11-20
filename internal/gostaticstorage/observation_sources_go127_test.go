//go:build go1.27

package gostaticstorage

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gotoolchain"
)

func TestGoAuditedObjectObservationSources(t *testing.T) {
	// The installed same-distribution Go 1.27.2 and 1.27.3 cmd source trees
	// were compared: all 4517 files (323 cmd/internal) are byte-identical.
	// Read the installed sources independently of any retained observation;
	// the patch version alone must never replace these exact format pins.
	if !gotoolchain.AuditedGo127(runtime.Version()) {
		t.Fatal("selected SDK patch has no object-format audit", runtime.Version())
	}
	if len(formatSources) != 8 || len(sdkCPUFormatSources) != 5 {
		t.Fatal("object/SDK source-role inventory changed")
	}
	for _, roles := range []map[string]string{formatSources, sdkCPUFormatSources} {
		for name, want := range roles {
			t.Run(name, func(t *testing.T) {
				data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), filepath.FromSlash(name)))
				if err != nil {
					t.Fatal(err)
				}
				if got := digest(data); got != want {
					t.Fatalf("actual observation source SHA256 = %s, want %s", got, want)
				}
			})
		}
	}
}
