package gotoolprofile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMD64OriginalObservationLargeAssemblyRetainsSourceGuard(t *testing.T) {
	request := amd64OriginalObservationFixture(t, "nested")
	assembly := filepath.Join(request.Directory, "value_amd64.s")
	original, err := os.ReadFile(assembly)
	if err != nil {
		t.Fatal(err)
	}
	source := string(original) + strings.Repeat("// generated source padding\n", 120000)
	if len(source) <= 2<<20 || len(source) >= 8<<20 {
		t.Fatalf("fixture lost its large-source boundary: %d bytes", len(source))
	}
	if err := os.WriteFile(assembly, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	stdout, stderr, err := RunBounded(ctx, request.Directory, request.Environment, request.GoBinary,
		"list", "-deps", "-compiled", "-export", "-json", "-mod=readonly", request.PackagePath)
	if err != nil || len(stdout) == 0 || len(stderr) != 0 {
		t.Fatalf("actual Go rejected large original assembly: %v; %s", err, stderr)
	}
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	})
	if observed.state.files.hashes[assembly] != bytesSHA256([]byte(source)) || observed.state.files.cpp[assembly].Expanded == "" {
		t.Fatal("large-source allowance lost actual original bytes or CPP consumption")
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(assembly, []byte(source+"// changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := observed.Verify(ctx); err == nil {
		t.Fatal("large original source mutation did not revoke its observation")
	}
}
