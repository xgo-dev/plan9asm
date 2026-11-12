package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsInheritedLLVMBuildContext(t *testing.T) {
	// The Windows LLVM setup supplies byollvm to nested Go commands as well.
	// Explicit top-level flags must agree; clearing GOFLAGS would silently
	// change the source selection of subprocesses invoked by a test.
	t.Setenv("GOFLAGS", "-tags=byollvm")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	dir := t.TempDir()
	for name, source := range map[string]string{
		"go.mod":      "module example.org/inherited-build-context\n\ngo 1.20\n",
		"selected.go": "//go:build byollvm\n\npackage selected\nconst Value = 7\n",
		"other.go":    "//go:build !byollvm\n\npackage wrong\nconst Value = 9\n",
		"selected_test.go": `//go:build byollvm

package selected
import (
    "os/exec"
    "strings"
    "testing"
)
func TestSelection(t *testing.T) {
    if Value != 7 { t.Fatal("outer source selection changed") }
    command := exec.Command("go", "list", "-f", "{{.Name}}", ".")
    data, err := command.CombinedOutput()
    if err != nil || strings.TrimSpace(string(data)) != "selected" {
        t.Fatalf("nested source selection changed: %s %v", data, err)
    }
}
`,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config{Go: "go", Dir: dir, Package: ".", Out: filepath.Join(t.TempDir(), "suite"),
		Shards: 2, Workers: 2, Timeout: time.Minute, Flags: []string{"-tags=byollvm"}}
	if err := runSuite(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	var report suiteReport
	if err := ciReadJSON(filepath.Join(cfg.Out, "report.json"), &report); err != nil {
		t.Fatal(err)
	}
	if report.RootPassed != 1 || report.RootSkipped != 0 || report.RootMissing != 0 ||
		len(report.Flags) != 1 || report.Flags[0] != "-tags=byollvm" {
		t.Fatalf("actual inherited/declared build selection missing: %+v", report)
	}
	for _, flags := range [][]string{nil, {"-tags=foreign"}, {"-tags=byollvm", "-tags=foreign"}} {
		cfg.Flags = flags
		cfg.Out = filepath.Join(t.TempDir(), "rejected")
		if err := runSuite(context.Background(), cfg); err == nil {
			t.Fatalf("undeclared/conflicting inherited build selection accepted: %v", flags)
		}
		if _, err := os.Stat(cfg.Out); !os.IsNotExist(err) {
			t.Fatalf("conflicting build selection started a suite: %v", err)
		}
	}
}
