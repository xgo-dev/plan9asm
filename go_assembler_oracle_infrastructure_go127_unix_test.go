//go:build go1.27 && unix

package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestGoAssemblerOraclesRejectInfrastructure(t *testing.T) {
	if arch := os.Getenv("PLAN9ASM_ASSEMBLER_ORACLE_CHILD_ARCH"); arch != "" {
		source := "TEXT ·bad(SB),$0-0\n\tNOT_AN_INSTRUCTION\n\tRET\n"
		wantSuccess := os.Getenv("PLAN9ASM_ASSEMBLER_ORACLE_CHILD_SUCCESS") == "1"
		if arch == "arm64" {
			requireARM64GoAssemblerResult(t, source, wantSuccess)
		} else {
			requireX86GoAssemblerResult(t, arch, source, wantSuccess)
		}
		return
	}

	// Each child owns a private PATH. Its deliberately broken tool must fail
	// the original test helper, not masquerade as an expected source rejection.
	for _, arch := range []string{"arm64", "amd64", "386"} {
		for _, test := range []struct {
			name        string
			script      string
			wantSuccess bool
		}{
			{name: "missing tool"},
			{name: "unknown exit", script: "exit 1\n"},
			{name: "assembler footer only", script: "printf 'asm: assembly failed\\n' >&2\nexit 1\n"},
			{name: "killed process", script: "kill -TERM \"$$\"\n"},
			{name: "success without object", script: "exit 0\n", wantSuccess: true},
		} {
			t.Run(arch+"/"+test.name, func(t *testing.T) {
				dir := t.TempDir()
				if test.script != "" {
					if err := os.WriteFile(filepath.Join(dir, "go"), []byte("#!/bin/sh\n"+test.script), 0700); err != nil {
						t.Fatal(err)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestGoAssemblerOraclesRejectInfrastructure$")
				command.Env = append(os.Environ(),
					"PATH="+dir,
					"PLAN9ASM_ASSEMBLER_ORACLE_CHILD_ARCH="+arch,
					"PLAN9ASM_ASSEMBLER_ORACLE_CHILD_SUCCESS=0",
				)
				if test.wantSuccess {
					command.Env = append(command.Env, "PLAN9ASM_ASSEMBLER_ORACLE_CHILD_SUCCESS=1")
				}
				output, err := runtimeOracleCombinedOutput(ctx, command)
				if ctx.Err() != nil {
					t.Fatalf("failure probe exceeded its owned deadline: %v\n%s", ctx.Err(), output)
				}
				if err == nil || !strings.Contains(string(output), "Go assembler oracle infrastructure failure") {
					t.Fatalf("broken tool was accepted as source/assembly evidence: %v\n%s", err, output)
				}
			})
		}
	}
}
