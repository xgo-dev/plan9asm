package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

// The independent Go listing and package loader can spell one SDK differently.
// Bind an actual selected file, not a path string or a same-content substitute.
func reflectDynamicStubAssemblySelected(directory string, members []string, source string) (bool, error) {
	physical, requested, err := reflectDynamicStubAssemblyIdentity(source)
	if err != nil {
		return false, err
	}
	selected := false
	seen := make(map[string]bool, len(members))
	for _, member := range members {
		if filepath.Base(member) != member || filepath.Ext(member) != ".s" {
			return false, fmt.Errorf("invalid original Go SFiles member %q", member)
		}
		candidate, info, err := reflectDynamicStubAssemblyIdentity(filepath.Join(directory, member))
		if err != nil {
			return false, err
		}
		if seen[candidate] {
			return false, fmt.Errorf("duplicate original Go assembly member %q", member)
		}
		seen[candidate] = true
		if candidate == physical {
			if !os.SameFile(requested, info) {
				return false, fmt.Errorf("original selected assembly changed its file identity")
			}
			selected = true
		}
	}
	return selected, nil
}

func reflectDynamicStubAssemblyIdentity(name string) (string, os.FileInfo, error) {
	physical, err := sourcepath.Resolve(name)
	if err != nil {
		return "", nil, err
	}
	info, err := sourcepath.Lstat(physical)
	if err != nil {
		return "", nil, err
	}
	if !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("original assembly is not a regular file: %s", name)
	}
	return physical, info, nil
}

func TestReflectDynamicStubSelectedAssemblyIdentity(t *testing.T) {
	actual := t.TempDir()
	const member = "asm_amd64.s"
	source := filepath.Join(actual, member)
	if err := os.WriteFile(source, []byte("original assembly\n"), 0600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "original-sdk-directory")
	ordinaryLoadDirectoryAlias(t, alias, actual)
	for _, paths := range [][2]string{
		{actual, source},
		{alias, source},
		{actual, filepath.Join(alias, member)},
	} {
		t.Run(filepath.Base(paths[0])+"-"+filepath.Base(filepath.Dir(paths[1])), func(t *testing.T) {
			selected, err := reflectDynamicStubAssemblySelected(paths[0], []string{member}, paths[1])
			if err != nil || !selected {
				t.Fatalf("actual selected file lost its opened identity: %v", err)
			}
		})
	}
}

func TestReflectDynamicStubSelectedAssemblyRejectsUnboundIdentity(t *testing.T) {
	actual := t.TempDir()
	const member = "asm_amd64.s"
	source := filepath.Join(actual, member)
	other := filepath.Join(actual, "unselected.s")
	for _, name := range []string{source, other} {
		if err := os.WriteFile(name, []byte("identical assembly bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, test := range []struct {
		name    string
		members []string
		source  string
		invalid bool
	}{
		{"unselected-equal-bytes", []string{member}, other, false},
		{"empty-selection", nil, source, false},
		{"missing-request", []string{member}, filepath.Join(actual, "missing.s"), true},
		{"missing-selected-member", []string{"missing.s"}, source, true},
		{"directory-request", []string{member}, actual, true},
		{"duplicate-selected-member", []string{member, member}, source, true},
		{"escaped-selected-member", []string{filepath.Join("..", member)}, source, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			selected, err := reflectDynamicStubAssemblySelected(actual, test.members, test.source)
			if selected || (err != nil) != test.invalid {
				t.Fatalf("unbound assembly obtained original selection: selected=%t err=%v", selected, err)
			}
		})
	}

	t.Run("retargeted-directory-alias", func(t *testing.T) {
		replacement := t.TempDir()
		if err := os.WriteFile(filepath.Join(replacement, member), []byte("identical assembly bytes\n"), 0600); err != nil {
			t.Fatal(err)
		}
		alias := filepath.Join(t.TempDir(), "original-sdk-directory")
		ordinaryLoadDirectoryAlias(t, alias, actual)
		requested := filepath.Join(alias, member)
		if selected, err := reflectDynamicStubAssemblySelected(actual, []string{member}, requested); err != nil || !selected {
			t.Fatalf("original alias is not selected: %v", err)
		}
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		ordinaryLoadDirectoryAlias(t, alias, replacement)
		if selected, err := reflectDynamicStubAssemblySelected(actual, []string{member}, requested); err != nil || selected {
			t.Fatalf("retargeted equal-byte alias borrowed original selection: %v", err)
		}
	})
}
