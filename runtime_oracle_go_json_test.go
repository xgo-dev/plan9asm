package plan9asm

import (
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestRuntimeOracleGoJSONRetainsSeparateDownloadDiagnostics(t *testing.T) {
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleGoJSONFixture$")
	command.Env = append(os.Environ(), "PLAN9ASM_GO_JSON_FIXTURE=1")
	output, diagnostics, err := runtimeOracleMachineOutput(ctx, command)
	if err != nil || string(diagnostics) != "go: downloading fixture.invalid/module v1.0.0\n" {
		t.Fatalf("actual command outcome or diagnostics lost: %v: %q", err, diagnostics)
	}
	var actual struct{ ImportPath string }
	if err := json.Unmarshal(output, &actual); err != nil || actual.ImportPath != "fixture.invalid/module" {
		t.Fatalf("download diagnostics contaminated machine stdout: %v: %q", err, output)
	}
}

func TestRuntimeOracleGoJSONFixture(t *testing.T) {
	if os.Getenv("PLAN9ASM_GO_JSON_FIXTURE") != "1" {
		return
	}
	_, _ = os.Stderr.WriteString("go: downloading fixture.invalid/module v1.0.0\n")
	_, _ = os.Stdout.WriteString(`{"ImportPath":"fixture.invalid/module"}`)
	os.Exit(0)
}
