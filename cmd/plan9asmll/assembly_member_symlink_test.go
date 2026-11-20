package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm"
)

func TestActualAssemblyMemberFinalSymlinkIdentity(t *testing.T) {
	directory := t.TempDir()
	physical := filepath.Join(directory, "original.txt")
	other := filepath.Join(directory, "other.txt")
	for _, path := range []string{physical, other} {
		if err := os.WriteFile(path, []byte("TEXT ·F(SB),$0-0\n RET\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	selected := filepath.Join(directory, "p_arm64.s")
	if err := os.Symlink(physical, selected); err != nil {
		t.Fatal(err)
	}
	member, err := observeActualAssemblyMember(selected, []string{selected})
	if err != nil || member.verify() != nil {
		t.Fatalf("unchanged actual selected final symlink: %v", err)
	}
	if err := os.Rename(selected, selected+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, selected); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(member.verify(), plan9asm.ErrProbeNeedsContext) {
		t.Fatal("retargeted selected final symlink retained source identity")
	}
	if err := os.Remove(selected); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(selected+".original", selected); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(member.verify(), plan9asm.ErrProbeNeedsContext) {
		t.Fatal("restored selected final symlink revived source identity")
	}
	requested := filepath.Join(directory, "requested.s")
	if err := os.Symlink(selected, requested); err != nil {
		t.Fatal(err)
	}
	member, err = observeActualAssemblyMember(requested, []string{selected})
	if err != nil || member.verify() != nil {
		t.Fatalf("final symlink to exact actual selected file: %v", err)
	}
	if err := os.Rename(requested, requested+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(selected, requested); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(member.verify(), plan9asm.ErrProbeNeedsContext) {
		t.Fatal("same-target replacement erased original request node identity")
	}
}
