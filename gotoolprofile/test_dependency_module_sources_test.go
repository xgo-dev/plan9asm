package gotoolprofile

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/dirhash"
)

func testDependencyModuleFixture(t *testing.T) (TestModuleSource, string, string) {
	t.Helper()
	root, archive := t.TempDir(), filepath.Join(t.TempDir(), "module.zip")
	var err error
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"go.mod":                  "module example.invalid/boundary/loader\n\ngo 1.20\n",
		"loader.go":               "// original license\n//go:build !race\n\npackage loader\nimport \"example.invalid/boundary/loader/internal/layout\"\ntype Float = layout.Float\n",
		"internal/layout/type.go": "package layout\ntype Float = float32\n",
		"internal/layout/table.h": "#define VALUE 7\n",
	}
	source := TestModuleSource{
		Protocol: TestDependencyModuleProtocol, SourceModule: "example.invalid/boundary/loader", SourceVersion: "v1.0.0",
		GoModOrigin: TestModuleOriginalGoModOrigin,
		Sources:     make(map[string]string), Headers: make(map[string]string), Directories: make(map[string][]TestSourceEntry),
	}
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for file, data := range files {
		name := filepath.Join(root, filepath.FromSlash(file))
		if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		member, err := writer.Create(source.ID() + "/" + file)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(member, data); err != nil {
			t.Fatal(err)
		}
		source.Sources[file] = bytesSHA256([]byte(data))
		if path.Ext(file) == ".go" {
			header, err := TestSelectionHeader(file, []byte(data))
			if err != nil {
				t.Fatal(err)
			}
			source.Headers[file] = header
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(archive, buffer.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{".", "internal", "internal/layout"} {
		entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			proof := TestSourceEntry{Name: entry.Name(), Kind: "directory"}
			if !entry.IsDir() {
				proof.Kind, proof.SHA256 = "file", source.Sources[path.Join(dir, entry.Name())]
			}
			source.Directories[dir] = append(source.Directories[dir], proof)
		}
	}
	source.ZipSHA256 = bytesSHA256(buffer.Bytes())
	source.ModuleSum, err = dirhash.HashZip(archive, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	source.GoModSHA256 = source.Sources["go.mod"]
	source.GoModSum, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(files["go.mod"])), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return source, root, archive
}

func cloneTestModuleSource(t *testing.T, source TestModuleSource) TestModuleSource {
	t.Helper()
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var result TestModuleSource
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestTestDependencyModuleSourceActualZIPAndSnapshot(t *testing.T) {
	source, root, archive := testDependencyModuleFixture(t)
	if err := VerifyTestModuleSource(context.Background(), cloneTestModuleSource(t, source), root, archive); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*TestModuleSource){
		"old protocol":           func(p *TestModuleSource) { p.Protocol = "" },
		"different module":       func(p *TestModuleSource) { p.SourceModule += "/other" },
		"different version":      func(p *TestModuleSource) { p.SourceVersion = "v1.0.1" },
		"changed h1":             func(p *TestModuleSource) { p.ModuleSum = "h1:" + strings.Repeat("A", 43) + "=" },
		"changed proxy mod h1":   func(p *TestModuleSource) { p.GoModSum = "h1:" + strings.Repeat("B", 43) + "=" },
		"changed ZIP":            func(p *TestModuleSource) { p.ZipSHA256 = strings.Repeat("0", 64) },
		"missing root directory": func(p *TestModuleSource) { delete(p.Directories, ".") },
		"ZIP without original go.mod cannot invent proxy role": func(p *TestModuleSource) {
			delete(p.Sources, "go.mod")
			for i, entry := range p.Directories["."] {
				if entry.Name == "go.mod" {
					p.Directories["."] = append(p.Directories["."][:i], p.Directories["."][i+1:]...)
					break
				}
			}
			p.GoModSHA256 = ""
		},
		"missing ancestor":         func(p *TestModuleSource) { delete(p.Directories, "internal") },
		"missing selection header": func(p *TestModuleSource) { delete(p.Headers, "loader.go") },
		"arbitrary header unchanged full SHA and h1": func(p *TestModuleSource) {
			p.Headers["loader.go"] = "package loader\nimport \"unsafe\"\n"
		},
		"truncated directory": func(p *TestModuleSource) {
			p.Directories["internal/layout"] = p.Directories["internal/layout"][1:]
		},
		"extra unrelated file":   func(p *TestModuleSource) { p.Sources["missing.go"] = strings.Repeat("0", 64) },
		"redirected source name": func(p *TestModuleSource) { p.Headers["../loader.go"] = "package loader\n" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTestModuleSource(t, source)
			mutate(&changed)
			if err := VerifyTestModuleSource(context.Background(), changed, root, archive); err == nil {
				t.Fatal("accepted mutated source identity, selection input or ZIP membership")
			}
		})
	}
	for _, mutation := range []string{"header.h", "new.go", "source.go", "symlink.go"} {
		t.Run("actual file "+mutation, func(t *testing.T) {
			proof, directory, zipFile := testDependencyModuleFixture(t)
			name := "internal/layout/table.h"
			if mutation == "new.go" || mutation == "symlink.go" {
				name = "internal/layout/" + mutation
			} else if mutation == "source.go" {
				name = "loader.go"
			}
			filename := filepath.Join(directory, filepath.FromSlash(name))
			if mutation == "symlink.go" {
				if err := os.Symlink(filepath.Join(directory, "loader.go"), filename); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(filename, []byte("package changed\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyTestModuleSource(context.Background(), proof, directory, zipFile); err == nil {
				t.Fatal("accepted changed real source directory/header/non-Go member")
			}
		})
	}
}

func TestTestDependencyModuleSourceSelfConsistentNonZIPBytes(t *testing.T) {
	source, root, archive := testDependencyModuleFixture(t)
	data := []byte("package loader\ntype Float = float64\n")
	if err := os.WriteFile(filepath.Join(root, "loader.go"), data, 0600); err != nil {
		t.Fatal(err)
	}
	source.Sources["loader.go"] = bytesSHA256(data)
	source.Headers["loader.go"], _ = TestSelectionHeader("loader.go", data)
	for i := range source.Directories["."] {
		if source.Directories["."][i].Name == "loader.go" {
			source.Directories["."][i].SHA256 = source.Sources["loader.go"]
		}
	}
	if err := ValidateTestModuleSource(source); err != nil {
		t.Fatal("compact shape validation is not independent ZIP authentication:", err)
	}
	if err := VerifyTestModuleSource(context.Background(), source, root, archive); err == nil {
		t.Fatal("self-consistent mutated file/header cannot replace actual original ZIP bytes")
	}
}

func TestTestDependencyModuleSourceDuplicateZIPMembers(t *testing.T) {
	for _, duplicate := range []string{"loader.go", "internal/"} {
		t.Run(duplicate, func(t *testing.T) {
			source, root, archive := testDependencyModuleFixture(t)
			original, err := zip.OpenReader(archive)
			if err != nil {
				t.Fatal(err)
			}
			var buffer bytes.Buffer
			writer := zip.NewWriter(&buffer)
			for _, file := range original.File {
				member, err := writer.Create(file.Name)
				if err != nil {
					t.Fatal(err)
				}
				stream, err := file.Open()
				if err != nil {
					t.Fatal(err)
				}
				_, readErr := io.Copy(member, stream)
				closeErr := stream.Close()
				if readErr != nil || closeErr != nil {
					t.Fatal("read original member:", readErr, closeErr)
				}
			}
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			count := 1
			if strings.HasSuffix(duplicate, "/") {
				count = 2
			}
			for i := 0; i < count; i++ {
				member, err := writer.Create(source.ID() + "/" + duplicate)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.HasSuffix(duplicate, "/") {
					io.WriteString(member, "package loader\n")
				}
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(archive, buffer.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
			source.ZipSHA256 = bytesSHA256(buffer.Bytes())
			source.ModuleSum, err = dirhash.HashZip(archive, dirhash.Hash1)
			if err != nil {
				t.Fatalf("construct duplicate-entry h1 for independent membership check: %v", err)
			}
			if err := VerifyTestModuleSource(context.Background(), source, root, archive); err == nil {
				t.Fatal("accepted duplicate original ZIP source/directory marker")
			}
		})
	}
}

func TestTestDependencyModuleSourceStdlibAndCanonicalOrdering(t *testing.T) {
	source, root, _ := testDependencyModuleFixture(t)
	source.SourceModule, source.SourceVersion, source.ModuleSum, source.ZipSHA256 = "", "", "", ""
	source.GoModSum, source.GoModSHA256, source.GoVersion = "", "", "go1.27.1"
	source.GoModOrigin = ""
	if err := VerifyTestModuleSource(context.Background(), source, root, ""); err != nil {
		t.Fatal(err)
	}
	if err := VerifyTestModuleSource(context.Background(), source, root, filepath.Join(root, "zip")); err == nil {
		t.Fatal("stdlib cannot impersonate a downloaded external module")
	}
	sources := []TestModuleSource{source, {SourceModule: "example.invalid/aaa", SourceVersion: "v1.0.0"}}
	SortTestModuleSources(sources)
	if !sort.SliceIsSorted(sources, func(i, j int) bool { return sources[i].ID() < sources[j].ID() }) {
		t.Fatal("source-root inventory lacks stable public ordering")
	}
}

func TestTestDependencyModuleSourceCancelledAndMissingContext(t *testing.T) {
	source, root, archive := testDependencyModuleFixture(t)
	if err := VerifyTestModuleSource(nil, source, root, archive); err == nil {
		t.Fatal("unbounded caller cannot authorize a source-root proof")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := VerifyTestModuleSource(ctx, source, root, archive); err == nil {
		t.Fatal("cancelled source proof became successful evidence")
	}
}
