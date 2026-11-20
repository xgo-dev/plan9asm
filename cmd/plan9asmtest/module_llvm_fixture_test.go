package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// Keep real consumer fixtures on the same selected binding and checksums as
// the repository, including an explicitly selected replacement.
func moduleLLVMFixtureGoMod(t *testing.T, name string) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	driver, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, driver, "list", "-mod=readonly", "-m", "-json", "github.com/xgo-dev/llvm")
	command.Dir = root
	command.WaitDelay = 5 * time.Second
	data, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("select actual fixture LLVM binding: %v\n%s", err, data)
	}
	var selected struct {
		Path, Version string
		Replace       *struct{ Path, Version, Dir string }
	}
	if err := json.Unmarshal(data, &selected); err != nil {
		t.Fatal(err)
	}
	if selected.Path != "github.com/xgo-dev/llvm" || selected.Version == "" {
		t.Fatalf("missing selected fixture LLVM binding: %s", data)
	}
	module := fmt.Sprintf("module %s\n\ngo 1.20\nrequire %s %s\n", name, selected.Path, selected.Version)
	if replacement := selected.Replace; replacement != nil {
		path := replacement.Path
		if replacement.Version == "" {
			if replacement.Dir == "" {
				t.Fatal("local fixture LLVM replacement has no directory")
			}
			path = replacement.Dir
		}
		module += fmt.Sprintf("replace %s => %s", selected.Path, strconv.Quote(path))
		if replacement.Version != "" {
			module += " " + replacement.Version
		}
		module += "\n"
	}
	return module
}
