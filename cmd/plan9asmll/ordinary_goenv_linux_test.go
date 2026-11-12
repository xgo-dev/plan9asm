package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Exercise the real compiler's implicit configuration location without changing
// a user's HOME or configuration. Linux cmd/go uses XDG_CONFIG_HOME here.
func TestRunOneTargetFixedLocalMissingImplicitGoEnv(t *testing.T) {
	pkg, _, config := amd64FixedLocalCLIFixture(t, "PADDL 16(SP),X0")
	configuration := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configuration)
	t.Setenv("GOENV", "")
	t.Chdir(pkg.Dir)
	report, _, err := runOneTarget(targetSpec{Goos: "linux", Goarch: "amd64"},
		[]string{"."}, nil, nil, pkg.Module.Path, t.TempDir(), false, 0, false,
		false, true, "", config)
	if err != nil || report.TotalAsm != 1 || report.Success != 1 || report.Failed != 0 {
		t.Fatalf("implicit absent compiler configuration prevented actual fixed-local compilation: %v; %+v", err, report)
	}
	if _, err := os.Stat(filepath.Join(configuration, "go", "env")); !os.IsNotExist(err) {
		t.Fatalf("compiler profile preparation wrote a default configuration: %v", err)
	}
}
