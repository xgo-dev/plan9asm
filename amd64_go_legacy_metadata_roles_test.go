package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/golegacymod"
	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

func TestGoAMD64LegacyDeclarationMetadataRoles(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata := filepath.Join(t.TempDir(), "legacy.mod")
	member := filepath.Join(root, "go.mod")
	for _, name := range []string{metadata, member} {
		if err := os.WriteFile(name, []byte("module example.invalid/legacy\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	metadata, err = filepath.EvalSymlinks(metadata)
	if err != nil {
		t.Fatal(err)
	}
	original := gooriginalsrc.Module{Root: root, ModulePath: "example.invalid/legacy",
		SourceModule: "example.invalid/legacy", SourceVersion: "v1.0.0", GoMod: metadata,
		GoModOrigin: golegacymod.ProxyGoModProtocol}
	for _, role := range []string{"dependency", "invented member", "main"} {
		t.Run(role, func(t *testing.T) {
			data, err := json.Marshal(map[string]any{
				"Dir": root, "ImportPath": original.ModulePath,
				"Module": map[string]any{"Path": original.ModulePath, "Version": original.SourceVersion,
					"Dir": root, "GoMod": metadata},
			})
			if err != nil {
				t.Fatal(err)
			}
			var selected goAMD64FrameSelection
			if err := json.Unmarshal(data, &selected); err != nil {
				t.Fatal(err)
			}
			// Predicate data only, deliberately not an actual whole-ZIP origin
			// or frame token. The duplicate member tests source-role confusion.
			source := &GoAMD64FrameSource{downloadedOrigin: &gooriginalsrc.OriginSet{}, downloadedModule: &original,
				downloadedImports: map[string]gooriginalsrc.Module{original.ModulePath + "@" + original.SourceVersion: original}}
			if role == "invented member" {
				selected.Module.GoMod = member
			}
			if role == "main" {
				selected.Module.Main = true
				selected.Module.Version, selected.Module.GoVersion = "", "1.16"
			}
			_, err = source.downloadedDeclarationDirectory(selected)
			if role == "dependency" && err != nil || role != "dependency" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("legacy metadata lost its exact dependency-only origin", err)
			}
			if err := source.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("module predicate data manufactured frame authority", err)
			}
		})
	}
}
