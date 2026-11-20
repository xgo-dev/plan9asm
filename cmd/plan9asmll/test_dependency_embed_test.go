package main

import (
	"context"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/tools/go/packages"
)

func TestTestDependencyEmbedActualOrdinaryRole(t *testing.T) {
	for _, axis := range []struct {
		name, directive, file string
	}{
		{name: "file", directive: "//go:embed defaults.bin", file: "defaults.bin"},
		{name: "all directory", directive: "//go:embed all:assets", file: "assets/.defaults.bin"},
		{name: "Unicode pattern whitespace", directive: "//go:embed \u00a0defaults.bin", file: "defaults.bin"},
		{name: "Unicode separator", directive: "//go:embed\u00a0defaults.bin", file: "defaults.bin"},
	} {
		t.Run(axis.name, func(t *testing.T) {
			testDependencyEmbedActualOrdinaryRole(t, axis.directive, axis.file)
		})
	}
}

func testDependencyEmbedActualOrdinaryRole(t *testing.T, directive, asset string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sourceText := "package actualembed\nimport _ \"embed\"\n" + directive + "\nvar Defaults []byte\n"
	for name, contents := range map[string]string{
		"go.mod":      "module example.invalid/actualembed\n\ngo 1.20\n",
		"defaults.go": sourceText,
		asset:         "exact original embedded bytes\n",
	} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	selected, err := packages.Load(&packages.Config{
		Context: ctx, Dir: dir, Env: append(os.Environ(), "GOTOOLCHAIN=local"),
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedEmbedFiles | packages.NeedEmbedPatterns,
	}, ".")
	if err != nil || len(selected) != 1 || len(selected[0].Errors) != 0 {
		t.Fatalf("actual Go embed selection: %v %#v", err, selected)
	}
	pkg := selected[0]
	// Go 1.25 and earlier recognize only space/tab immediately after the
	// directive name. Compare the actual SDK's independent source reader;
	// ignored comments must not acquire the newer parser's embedded files.
	original, err := build.Default.ImportDir(dir, 0)
	if err != nil {
		t.Fatal("independent SDK source selection", err)
	}
	want := len(original.EmbedPatterns)
	if want != 1 && !(want == 0 && strings.HasPrefix(directive, "//go:embed\u00a0")) {
		t.Fatal("unexpected SDK directive selection", original.EmbedPatterns)
	}
	if isTestVariantPackage(pkg) || len(pkg.EmbedPatterns) != want || len(pkg.EmbedFiles) != want {
		t.Fatalf("ordinary exact Go embed selection was not retained: %#v", pkg)
	}
	if _, err := captureTypedSourceLoadGuard(ctx, selected, nil); (err != nil) != (want != 0) {
		t.Fatal("unqualified ordinary load changed its actual embed role", err)
	}
	source := gotoolprofile.TestSourcePackage{
		Package: gotoolprofile.PackageProof{
			PackagePath: pkg.PkgPath,
			GoFiles:     []string{"defaults.go"}, CompiledGoFiles: []string{"defaults.go"},
			SourceSHA256: map[string]string{"defaults.go": featureBytesSHA256([]byte(sourceText))},
		},
	}
	source.Embed, err = captureTestPackageEmbedSelection(source.Package, dir, pkg)
	if err != nil {
		t.Fatal(err)
	}
	consumer := &featureConsumer{TestEmbedGuards: map[string]testDependencyEmbedGuard{
		pkg.ID: {Source: source, Root: dir},
	}}
	guard, err := consumer.captureTestSourceLoadGuard(ctx, selected, nil)
	if err != nil {
		t.Fatalf("actual ordinary role with explicit bound original sources: %v", err)
	}
	if want == 0 {
		if len(source.Embed.Patterns) != 0 || len(source.Embed.Files) != 0 || guard.Sources[filepath.Join(dir, asset)] != "" {
			t.Fatal("ignored directive acquired an embedded input")
		}
		changed := strings.Replace(sourceText, "//go:embed\u00a0", "//go:embed ", 1)
		if err := os.WriteFile(filepath.Join(dir, "defaults.go"), []byte(changed), 0600); err != nil {
			t.Fatal(err)
		}
		if err := consumer.verifyTestEmbedPackage(pkg); err == nil {
			t.Fatal("changed directive revived the original empty selection")
		}
		t.Log("actual SDK ignores the directive boundary; empty selection and source mutation verified")
		return
	}
	if guard.Sources[pkg.EmbedFiles[0]] != source.Embed.Files[asset] {
		t.Fatal("private pre/post guard omitted the actual embedded bytes")
	}
	if err := os.WriteFile(filepath.Join(dir, asset), []byte("mutated embedded bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := consumer.captureTestSourceLoadGuard(ctx, selected, nil); err == nil {
		t.Fatal("actual embedded source changed after binding without failing")
	}
}
