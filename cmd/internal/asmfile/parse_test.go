package asmfile

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIncludesFollowSelectedGoCommand(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte("go1.20.14\ntime 1970-01-01T00:00:00Z\n"), 0600); err != nil {
		t.Fatal(err)
	}
	name := "selected-sdk.h"
	path := filepath.Join(root, "pkg", "include", name)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("from source SDK"), 0600); err != nil {
		t.Fatal(err)
	}
	goenv := filepath.Join(root, "goenv")
	if err := os.WriteFile(goenv, []byte("GOROOT="+root+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOENV", goenv)
	t.Setenv("GOROOT", "")
	t.Setenv("GOTOOLCHAIN", "local")
	var dirs goSDKIncludes
	got, data, err := dirs.read(name)
	if err != nil || dirs.version != "go1.20.14" || got != path || string(data) != "from source SDK" {
		t.Fatalf("selected header = %q, %q, %v", got, data, err)
	}
}

func TestRejectInvalidSourceVersion(t *testing.T) {
	root := t.TempDir()
	for _, v := range []string{"\nsecond line", "wrong", "go1.20junk"} {
		if err := os.WriteFile(filepath.Join(root, "VERSION"), []byte(v), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := selectedSDKVersion(root); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}
