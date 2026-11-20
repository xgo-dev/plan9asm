package gotoolprofile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeatureSubtoolDirectoryErrorsKeepOrigin(t *testing.T) {
	// Infrastructure failures need their origin even when Windows returns a
	// bare syscall error. They must not become assembly rejection evidence.
	for _, key := range []string{"GOROOT", "GOTOOLDIR", "GOCACHE"} {
		t.Run(key, func(t *testing.T) {
			present := t.TempDir()
			actual := map[string]string{"GOROOT": present, "GOTOOLDIR": present, "GOCACHE": present}
			actual[key] = filepath.Join(present, "missing")
			run := func(context.Context, string, []string, string, ...string) ([]byte, []byte, error) {
				t.Fatal("a missing directory must fail before invoking a tool")
				return nil, nil, nil
			}
			observed, err := captureDiscoveryFeatureSubtools(context.Background(), "", nil, actual, run)
			if observed != nil || !errors.Is(err, os.ErrNotExist) || !strings.HasPrefix(err.Error(), "resolve actual Go "+key+": ") {
				t.Fatalf("lost directory role or original error: observation=%v error=%v", observed, err)
			}
		})
	}
}
