//go:build go1.27

package plan9asm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sdkASMDataDiagnosticRetain(t *testing.T, source *GoX86SDKASMDataSource) {
	sdkASMDataDiagnosticRetainNamed(t, "", source)
}

func sdkASMDataDiagnosticRetainNamed(t *testing.T, suffix string, source *GoX86SDKASMDataSource) {
	t.Helper()
	folder := os.Getenv("PLAN9ASM_STATIC_STORAGE_ARTIFACT_DIR")
	if folder == "" {
		return
	}
	if err := os.MkdirAll(folder, 0700); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(source.observation)
	if err != nil {
		t.Fatal(err)
	}
	if suffix == "" {
		if err := os.WriteFile(filepath.Join(folder, "sdk-data-live-diagnostic.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	name := "sdk-data-observation-inputs-" + strings.ReplaceAll(t.Name(), "/", "-") + suffix + ".json"
	if err := os.WriteFile(filepath.Join(folder, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// This unpublished test scratch has no ready generation or public source
// token. Retain actual failed inputs so an independent SDK reader can explain
// a complete object mismatch rather than discarding it at factory cleanup.
func TestGoX86SDKASMDataLiveCRC32ObjectDiagnostic(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "hash/crc32")
	provided, err := sdkASMDataEnvironment(request)
	if err != nil {
		t.Fatal(err)
	}
	deadline, bounded := ctx.Deadline()
	if !bounded {
		t.Fatal("diagnostic lacks an original bounded context")
	}
	source := &GoX86SDKASMDataSource{request: request, context: ctx, originalContext: ctx,
		originalDeadline: deadline,
		directories:      make(map[string]os.FileInfo), misses: make(map[string]bool)}
	source.identity = source
	source.guard = newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{GoBinary: request.GoBinary,
		Directory: request.Directory, Target: request.Target, Environment: request.Environment})
	source.originalGuard = source.guard
	for _, directory := range []string{request.Directory, provided["GOCACHE"], provided["GOMODCACHE"],
		provided["GOPATH"], provided["TMPDIR"], provided["GOTMPDIR"]} {
		if err := source.retainDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.guard.snapshotDirectory(); err != nil {
		t.Fatal(err)
	}
	source.guard.owned, err = filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	source.guard.ownedInfo, err = os.Stat(source.guard.owned)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	err = source.capture(ctx, provided)
	sdkASMDataDiagnosticRetain(t, source)
	if err != nil {
		t.Fatal("actual complete SDK object diagnostic", err)
	}
	if source.ready || source.generation != 0 {
		t.Fatal("diagnostic scratch gained public lifetime authority")
	}
}
