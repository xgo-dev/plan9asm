package plan9asm

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestX86LogicalRuntimeBatchesRetainCompleteInventory(t *testing.T) {
	fixtures := x86LogicalRuntimeFixtures(t)
	if len(fixtures) != 472 {
		t.Fatalf("complete opcode/width/memory/mask inventory: got %d, want 472", len(fixtures))
	}
	seen := make(map[string]bool, len(fixtures))
	for index, batch := range x86LogicalRuntimeBatches(fixtures) {
		if len(batch) == 0 || len(batch) > 64 {
			t.Errorf("batch %d has %d fixtures, require 1..64", index, len(batch))
		}
		for _, fixture := range batch {
			if seen[fixture.name] {
				t.Fatalf("duplicate fixture %s", fixture.name)
			}
			seen[fixture.name] = true
		}
	}
	if len(seen) != len(fixtures) {
		t.Fatalf("batch union lost fixtures: got %d, want %d", len(seen), len(fixtures))
	}
	for _, fixture := range fixtures {
		if !seen[fixture.name] {
			t.Errorf("missing fixture %s", fixture.name)
		}
	}
}

// This is the real numerical oracle with a deliberately wrong implementation,
// not an instruction-semantics pass. Its former return code was 256, which a
// Unix parent observes as success. A large case ID must remain diagnostic data.
func TestX86LogicalRuntimeOracleCannotWrapFailureToSuccess(t *testing.T) {
	fixture := x86LogicalRuntimeFixtures(t)[245]
	program := x86LogicalRuntimeC([]x86LogicalRuntimeFixture{fixture}) + fmt.Sprintf(`
void %s(uint8_t *out, const uint8_t *a, const uint8_t *b, uint64_t mask) {
    memset(out, 0, 65);
}
`, fixture.name)
	requireX86GeneratedOracleFailure(t, program, fixture.name+" numerical/canary failure")
}

func requireX86GeneratedOracleFailure(t *testing.T, program, diagnostic string) {
	t.Helper()
	execution := x86FloatCompareExecutionTools(t)
	dir := t.TempDir()
	source, executable := filepath.Join(dir, "mutation.c"), filepath.Join(dir, "mutation")
	if err := os.WriteFile(source, []byte(program), 0600); err != nil {
		t.Fatal(err)
	}
	execution.compileC(t, source, executable)
	arguments := execution.command(executable)
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, arguments[0], arguments[1:]...))
	var failure *exec.ExitError
	if !errors.As(err, &failure) || failure.ExitCode() != 1 {
		t.Fatalf("wrong result must terminate with failure 1, got %v; output=%s", err, output)
	}
	if !strings.Contains(string(output), diagnostic) {
		t.Fatalf("failure diagnostic lost the exact fixture: %s", output)
	}
}
