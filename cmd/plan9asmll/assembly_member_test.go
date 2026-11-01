package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestActualAssemblyMemberExactSelection(t *testing.T) {
	directory := t.TempDir()
	selected := filepath.Join(directory, "p_arm64.s")
	other := filepath.Join(directory, "unselected_arm64.s")
	for _, path := range []string{selected, other} {
		if err := os.WriteFile(path, []byte("TEXT ·F(SB),$0-0\n RET\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(t.TempDir(), "package")
	ordinaryLoadDirectoryAlias(t, alias, directory)
	requested := filepath.Join(alias, filepath.Base(selected))
	member, err := observeActualAssemblyMember(requested, []string{selected})
	if err != nil || member.selected != selected || member.verify() != nil {
		t.Fatalf("exact compiler member through original directory alias: %+v %v", member, err)
	}
	for _, test := range []struct {
		name      string
		request   string
		selection []string
	}{
		{"unselected-equal-bytes", other, []string{selected}},
		{"missing", filepath.Join(alias, "missing.s"), []string{selected}},
		{"directory", directory, []string{selected}},
		{"empty-selection", requested, nil},
		{"duplicate-selection", requested, []string{selected, selected}},
		{"aliased-duplicate-selection", requested, []string{selected, requested}},
		{"oversized-selection", requested, make([]string, 513)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := observeActualAssemblyMember(test.request, test.selection); !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
				t.Fatalf("invalid actual selection gained a member: %v", err)
			}
		})
	}
	copyMember := &actualAssemblyMember{self: member, requested: member.requested, selected: member.selected, physical: member.physical, file: member.file, directories: member.directories}
	if !errors.Is(copyMember.verify(), plan9asm.ErrProbeNeedsContext) {
		t.Fatal("copied observation gained live identity")
	}
}

func TestActualAssemblyMemberOriginalAliasLifetime(t *testing.T) {
	for _, mutation := range []string{"retarget-equal-bytes", "replace-alias-same-target", "replace-file-equal-bytes"} {
		t.Run(mutation, func(t *testing.T) {
			directory, other := t.TempDir(), t.TempDir()
			selected := filepath.Join(directory, "p_arm64.s")
			bytes := []byte("TEXT ·F(SB),$0-0\n RET\n")
			for _, path := range []string{selected, filepath.Join(other, "p_arm64.s")} {
				if err := os.WriteFile(path, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(t.TempDir(), "package")
			ordinaryLoadDirectoryAlias(t, alias, directory)
			member, err := observeActualAssemblyMember(filepath.Join(alias, "p_arm64.s"), []string{selected})
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "replace-file-equal-bytes" {
				if err := os.Rename(selected, selected+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(selected, bytes, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Rename(alias, alias+".original"); err != nil {
					t.Fatal(err)
				}
				target := directory
				if mutation == "retarget-equal-bytes" {
					target = other
				}
				ordinaryLoadDirectoryAlias(t, alias, target)
			}
			if !errors.Is(member.verify(), plan9asm.ErrProbeNeedsContext) {
				t.Fatal("changed original request retained selected-source identity")
			}
			if mutation == "replace-file-equal-bytes" {
				if err := os.Remove(selected); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(selected+".original", selected); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(alias); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(alias+".original", alias); err != nil {
					t.Fatal(err)
				}
			}
			if !errors.Is(member.verify(), plan9asm.ErrProbeNeedsContext) {
				t.Fatal("restored request revived a revoked observation")
			}
		})
	}
}
