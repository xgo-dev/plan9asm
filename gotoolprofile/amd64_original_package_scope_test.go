package gotoolprofile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAMD64OriginalObservationUnimportedDescendantIsNotACompilerInput(t *testing.T) {
	request, dependency := amd64OriginalModuleDependencyFixture(t, "linux/amd64")
	header := filepath.Join(request.Directory, "headers", "value.h")
	if err := os.MkdirAll(filepath.Dir(header), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(header, []byte("#define SOURCE_DELTA 7\n"), 0600); err != nil {
		t.Fatal(err)
	}
	assembly := filepath.Join(request.Directory, "value_amd64.s")
	source, err := os.ReadFile(assembly)
	if err != nil {
		t.Fatal(err)
	}
	source = []byte("#include \"headers/value.h\"\n" + strings.Replace(string(source), "MOVQ AX,ret+8(FP)", "ADDQ $SOURCE_DELTA,AX\nMOVQ AX,ret+8(FP)", 1))
	if err := os.WriteFile(assembly, source, 0600); err != nil {
		t.Fatal(err)
	}

	// The actual compiler does not recursively consume testdata or an
	// unimported package. Every sparse member remains below the existing
	// 16 MiB file limit; together they exceed the unchanged 128 MiB graph.
	unselected := filepath.Join(request.Directory, "testdata", "unused")
	if err := os.MkdirAll(unselected, 0700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 9; index++ {
		file, err := os.Create(filepath.Join(unselected, fmt.Sprintf("member-%d.dat", index)))
		if err != nil {
			t.Fatal(err)
		}
		truncateErr := file.Truncate(16 << 20)
		closeErr := file.Close()
		if truncateErr != nil || closeErr != nil {
			t.Fatal(truncateErr, closeErr)
		}
	}
	ctx, cancel := amd64OriginalObservationContext(t)
	defer cancel()
	stdout, diagnostic, err := RunBounded(ctx, request.Directory, request.Environment,
		request.GoBinary, "list", "-export", "-mod=readonly", ".")
	if err != nil || strings.TrimSpace(string(stdout)) != request.PackagePath || len(diagnostic) != 0 {
		t.Fatalf("stock Go rejected the complete original source graph: %v\n%s\n%s", err, stdout, diagnostic)
	}
	observed, err := CaptureAMD64OriginalPackageObservation(ctx, request, RunBounded)
	if err != nil || observed == nil {
		t.Fatalf("unconsumed descendants enlarged the actual package source graph: %v", err)
	}
	t.Cleanup(func() {
		if err := observed.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, selected := range []string{assembly, header, filepath.Join(dependency, "dependency.go"), filepath.Join(dependency, "read_amd64.s"), filepath.Join(dependency, "local.h")} {
		if observed.state.files.hashes[selected] == "" {
			t.Fatalf("actual source/import/include lost its original guard: %s", selected)
		}
	}
	unused := filepath.Join(unselected, "member-0.dat")
	if observed.state.files.hashes[unused] != "" {
		t.Fatal("unconsumed testdata acquired a compiler-input role")
	}
	if err := os.WriteFile(unused, []byte("unrelated descendant change\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal("unconsumed descendant change revoked the actual source graph", err)
	}
	if err := os.WriteFile(header, []byte("#define SOURCE_DELTA 9\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := observed.Verify(ctx); err == nil {
		t.Fatal("changed active nested include escaped source verification")
	}
}
