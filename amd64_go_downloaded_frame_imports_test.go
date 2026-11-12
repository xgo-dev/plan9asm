package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/gooriginalsrc"
)

func TestGoAMD64DownloadedDeclarationMetadataRoles(t *testing.T) {
	root := t.TempDir()
	primary := gooriginalsrc.Module{Root: filepath.Join(root, "main"), ModulePath: "example.invalid/main", GoVersion: "1.20"}
	foreign := gooriginalsrc.Module{Root: filepath.Join(root, "dependency"), ModulePath: "example.invalid/dependency",
		SourceModule: "example.invalid/dependency", SourceVersion: "v1.0.0", GoVersion: "1.20"}
	for _, original := range []*gooriginalsrc.Module{&primary, &foreign} {
		if err := os.Mkdir(original.Root, 0700); err != nil {
			t.Fatal(err)
		}
		canonical, err := filepath.EvalSymlinks(original.Root)
		if err != nil {
			t.Fatal(err)
		}
		original.Root = canonical
		original.GoMod = filepath.Join(canonical, "go.mod")
		if err := os.WriteFile(original.GoMod, []byte("module "+original.ModulePath+"\ngo 1.20\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, axis := range []string{"foreign", "primary", "unknown version", "namespace", "language", "main role", "root",
		"metadata", "package directory", "package path", "replacement", "standard", "missing module", "missing owner"} {
		t.Run(axis, func(t *testing.T) {
			original, version, main := foreign, foreign.SourceVersion, false
			if axis == "primary" {
				original, version, main = primary, "", true
			}
			data, err := json.Marshal(map[string]any{
				"Dir": original.Root, "ImportPath": original.ModulePath,
				"Module": map[string]any{"Path": original.ModulePath, "Version": version, "Main": main,
					"Dir": original.Root, "GoMod": original.GoMod, "GoVersion": original.GoVersion},
			})
			if err != nil {
				t.Fatal(err)
			}
			var selected goAMD64FrameSelection
			if err := json.Unmarshal(data, &selected); err != nil {
				t.Fatal(err)
			}
			// This is metadata predicate data, deliberately not a sealed source
			// or a real OriginSet. It cannot Verify or supply frame authority.
			source := &GoAMD64FrameSource{downloadedOrigin: &gooriginalsrc.OriginSet{}, downloadedModule: &primary,
				downloadedImports: map[string]gooriginalsrc.Module{foreign.ModulePath + "@" + foreign.SourceVersion: foreign}}
			switch axis {
			case "unknown version":
				selected.Module.Version = "v2.0.0"
			case "namespace":
				selected.Module.Path = primary.ModulePath
			case "language":
				selected.Module.GoVersion = "1.21"
			case "main role":
				selected.Module.Main = true
			case "root":
				selected.Module.Dir = primary.Root
			case "metadata":
				selected.Module.GoMod = primary.GoMod
			case "package directory":
				selected.Dir = primary.Root
			case "package path":
				selected.ImportPath += "/unobserved"
			case "replacement":
				selected.Module.Replace = json.RawMessage(`{}`)
			case "standard":
				selected.Standard = true
			case "missing module":
				selected.Module = nil
			case "missing owner":
				source.downloadedOrigin = nil
			}
			directory, err := source.downloadedDeclarationDirectory(selected)
			if axis == "foreign" || axis == "primary" {
				if err != nil || directory != original.Root {
					t.Fatalf("consistent actual role lost metadata identity: %q, %v", directory, err)
				}
			} else if !errors.Is(err, ErrProbeNeedsContext) || directory != "" {
				t.Fatalf("changed original module role was accepted: %q, %v", directory, err)
			}
			if err := source.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("metadata predicate manufactured actual frame authority", err)
			}
		})
	}
}
