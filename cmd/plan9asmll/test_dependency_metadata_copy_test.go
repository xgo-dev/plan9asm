package main

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/gotoolprofile"
	"golang.org/x/mod/sumdb/dirhash"
)

func testModuleOriginalMetadataConsumer(t *testing.T) (*featureConsumer, testDependencyModuleGuard) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := []struct{ name, data string }{
		{"go.mod", "module example.invalid/metadata\n\ngo 1.20\n"},
		{"metadata.go", "package metadata\n"},
	}
	source := gotoolprofile.TestModuleSource{
		Protocol:     gotoolprofile.TestDependencyModuleProtocol,
		SourceModule: "example.invalid/metadata", SourceVersion: "v1.0.0",
		GoModOrigin: gotoolprofile.TestModuleOriginalGoModOrigin,
		Sources:     make(map[string]string), Headers: make(map[string]string),
		Directories: make(map[string][]gotoolprofile.TestSourceEntry),
	}
	var contents bytes.Buffer
	writer := zip.NewWriter(&contents)
	for _, file := range files {
		if err := os.WriteFile(filepath.Join(root, file.name), []byte(file.data), 0600); err != nil {
			t.Fatal(err)
		}
		member, err := writer.Create(source.ID() + "/" + file.name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(member, file.data); err != nil {
			t.Fatal(err)
		}
		digest := featureBytesSHA256([]byte(file.data))
		source.Sources[file.name] = digest
		source.Directories["."] = append(source.Directories["."], gotoolprofile.TestSourceEntry{
			Name: file.name, Kind: "file", SHA256: digest,
		})
	}
	source.Headers["metadata.go"] = files[1].data
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "original.zip")
	if err := os.WriteFile(archive, contents.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	source.ZipSHA256 = featureBytesSHA256(contents.Bytes())
	source.ModuleSum, err = dirhash.HashZip(archive, dirhash.Hash1)
	if err != nil {
		t.Fatal(err)
	}
	source.GoModSHA256 = source.Sources["go.mod"]
	source.GoModSum, err = dirhash.Hash1([]string{"go.mod"}, func(string) (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBufferString(files[0].data)), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	download := filepath.Join(t.TempDir(), "download.mod")
	if err := os.WriteFile(download, []byte(files[0].data), 0600); err != nil {
		t.Fatal(err)
	}
	guard := testDependencyModuleGuard{
		Source: source, Root: root, ZIP: archive, GoMod: download,
	}
	// Independently check this complete owned fixture before modeling an
	// already-bound private guard. This is not public SumDB authentication.
	ctx := context.Background()
	if err := gotoolprofile.VerifyTestModuleSource(ctx, source, root, archive); err != nil {
		t.Fatal(err)
	}
	consumer := &featureConsumer{
		Context: ctx, TestModuleGuards: map[string]testDependencyModuleGuard{source.ID(): guard},
	}
	if err := consumer.bindTestModuleSource(source, root, filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return consumer, guard
}

func TestTestModuleConsumerOriginalMetadataCopyFinalGuard(t *testing.T) {
	consumer, guard := testModuleOriginalMetadataConsumer(t)
	data, err := os.ReadFile(guard.GoMod)
	if err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(t.TempDir(), "actual-module.mod")
	if err := os.WriteFile(copy, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.bindTestModuleSource(guard.Source, guard.Root, copy); err != nil {
		t.Fatal(err)
	}
	bound := consumer.TestModuleGuards[guard.Source.ID()]
	canonical, err := filepath.EvalSymlinks(copy)
	if err != nil {
		t.Fatal(err)
	}
	if len(bound.MetadataPaths) != 3 || bound.MetadataPaths[copy] != canonical ||
		consumer.GeneratedGuard[copy] != guard.Source.GoModSHA256 {
		t.Fatal("actual metadata copy lacks its independent canonical/byte final guards")
	}
	if err := consumer.verifyTestModuleSources(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copy, []byte("module example.invalid/changed\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := consumer.verifyTestModuleSources(); err == nil {
		t.Fatal("repeated actual Module.GoMod copy changed after loading without failing final verification")
	}
}

func TestTestModuleConsumerOriginalMetadataCopiesRemainGuarded(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, string, []byte){
		"changed": func(t *testing.T, filename string, _ []byte) {
			if err := os.WriteFile(filename, []byte("changed metadata\n"), 0600); err != nil {
				t.Fatal(err)
			}
		},
		"deleted": func(t *testing.T, filename string, _ []byte) {
			if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
		},
		"equal leaf symlink": func(t *testing.T, filename string, data []byte) {
			replacement := filepath.Join(t.TempDir(), "equal.mod")
			if err := os.WriteFile(replacement, data, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(filename); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(replacement, filename); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			consumer, guard := testModuleOriginalMetadataConsumer(t)
			data, err := os.ReadFile(guard.GoMod)
			if err != nil {
				t.Fatal(err)
			}
			var copies []string
			for _, basename := range []string{"first.mod", "second.mod"} {
				filename := filepath.Join(t.TempDir(), basename)
				if err := os.WriteFile(filename, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := consumer.bindTestModuleSource(guard.Source, guard.Root, filename); err != nil {
					t.Fatal(err)
				}
				copies = append(copies, filename)
			}
			if err := consumer.verifyTestModuleSources(); err != nil {
				t.Fatal(err)
			}
			mutate(t, copies[0], data)
			if err := consumer.verifyTestModuleSources(); err == nil {
				t.Fatal("earlier repeated metadata copy lost its final guard after another observation")
			}
		})
	}
}

func TestTestModuleConsumerOriginalMetadataCanonicalPathCannotChange(t *testing.T) {
	for _, stage := range []string{"repeat load", "final guard"} {
		t.Run(stage, func(t *testing.T) {
			consumer, guard := testModuleOriginalMetadataConsumer(t)
			data, err := os.ReadFile(guard.GoMod)
			if err != nil {
				t.Fatal(err)
			}
			parent := t.TempDir()
			for _, dir := range []string{"first", "second"} {
				if err := os.Mkdir(filepath.Join(parent, dir), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(parent, dir, "actual.mod"), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			link := filepath.Join(parent, "selected")
			if err := os.Symlink(filepath.Join(parent, "first"), link); err != nil {
				t.Fatal(err)
			}
			metadata := filepath.Join(link, "actual.mod")
			if err := consumer.bindTestModuleSource(guard.Source, guard.Root, metadata); err != nil {
				t.Fatal(err)
			}
			if err := consumer.verifyTestModuleSources(); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(link); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(parent, "second"), link); err != nil {
				t.Fatal(err)
			}
			var rejected error
			if stage == "repeat load" {
				rejected = consumer.bindTestModuleSource(guard.Source, guard.Root, metadata)
			} else {
				rejected = consumer.verifyTestModuleSources()
			}
			if rejected == nil {
				t.Fatal("equal-byte parent redirection changed an observed metadata path without failing")
			}
		})
	}
}

func TestTestModuleConsumerOriginalMetadataConflictingGuardCannotAuthorizeCopy(t *testing.T) {
	consumer, guard := testModuleOriginalMetadataConsumer(t)
	data, err := os.ReadFile(guard.GoMod)
	if err != nil {
		t.Fatal(err)
	}
	copy := filepath.Join(t.TempDir(), "conflict.mod")
	if err := os.WriteFile(copy, data, 0600); err != nil {
		t.Fatal(err)
	}
	consumer.GeneratedGuard[copy] = featureBytesSHA256([]byte("other observed bytes"))
	if err := consumer.bindTestModuleSource(guard.Source, guard.Root, copy); err == nil {
		t.Fatal("actual metadata copy overwrote an incompatible prior byte identity")
	}
	if _, found := consumer.TestModuleGuards[guard.Source.ID()].MetadataPaths[copy]; found {
		t.Fatal("failed copy observation retained an authorized canonical path")
	}
	bound := consumer.TestModuleGuards[guard.Source.ID()]
	bound.MetadataPaths = nil
	consumer.TestModuleGuards[guard.Source.ID()] = bound
	if err := consumer.verifyTestModuleSources(); err == nil {
		t.Fatal("external module final guard accepted missing actual metadata observations")
	}
}
