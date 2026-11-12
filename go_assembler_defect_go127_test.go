//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type goAssemblerDefectObservation struct {
	source, original, object string
	output                   []byte
	commandErr, contextErr   error
}

func observeGoAssemblerMalformedInput(t *testing.T, original, experiment string) goAssemblerDefectObservation {
	t.Helper()
	dir := t.TempDir()
	observation := goAssemblerDefectObservation{
		source: filepath.Join(dir, "forms.s"), original: original,
		object: filepath.Join(dir, "forms.o"),
	}
	if err := os.WriteFile(observation.source, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	stage, cancelStage := runtimeOracleStageContext(t)
	defer cancelStage()
	ctx, cancel := context.WithTimeout(stage, time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "go", "tool", "asm", "-p", "example.com/forms", "-o", observation.object, observation.source)
	command.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOOS=linux", "GOARCH=arm64")
	if experiment != "" {
		command.Env = append(command.Env, "GOEXPERIMENT="+experiment)
	}
	observation.output, observation.commandErr = runtimeOracleCombinedOutput(ctx, command)
	observation.contextErr = ctx.Err()
	return observation
}

// This recognizes an observed compiler defect, not a successful compilation
// or a Go operand-rejection certificate. Ordinary form oracles still reject
// every panic and exit 2. Only these separately named regression tests may
// observe the exact panic/stack pairs, and no resulting object is consumed.
func goAssemblerMalformedInputOutcome(observation goAssemblerDefectObservation, panicText, stackFrame string) (bool, error) {
	if panicText == "" || stackFrame == "" {
		return false, fmt.Errorf("known-defect observation requires its exact panic and stack")
	}
	data, ok := goAssemblerOracleFixture(observation.source)
	if !ok || string(data) != observation.original {
		return false, fmt.Errorf("known-defect observation lost its original source")
	}
	if err := goAssemblerOracleOutcome(observation.source, observation.object, observation.output,
		observation.commandErr, observation.contextErr, false, "arm64"); err == nil {
		return false, nil // A future assembler may diagnose this source normally.
	}
	if observation.contextErr != nil {
		return false, fmt.Errorf("known-defect observation canceled: %w", observation.contextErr)
	}
	exit, ok := observation.commandErr.(*exec.ExitError)
	if !ok || exit.ProcessState == nil || !exit.ProcessState.Exited() || exit.ExitCode() != 2 {
		return false, fmt.Errorf("known-defect observation has an unexpected process outcome: %v", observation.commandErr)
	}
	output := string(observation.output)
	for _, marker := range []string{"fatal error:", "runtime: failed to", "runtime: out of memory", "executable file not found"} {
		if strings.Contains(output, marker) {
			return false, fmt.Errorf("known-defect observation infrastructure failure: %s", marker)
		}
	}
	if !strings.Contains(output, "panic: "+panicText) || !strings.Contains(output, stackFrame) {
		return false, fmt.Errorf("known-defect observation has an unknown panic or stack")
	}
	return true, nil
}

func TestGoAssemblerKnownMalformedInputDefects(t *testing.T) {
	tests := []struct {
		name, source, experiment, panicText, stackFrame string
	}{
		{"missing-vector-constant-operand", "TEXT badvectorconstant(SB),$0-0\n\tVMOVQ $1, V1\n\tRET\n", "",
			"runtime error: invalid memory address or nil pointer dereference", "cmd/internal/obj/arm64.progedit("},
		{"neon-register-in-sve-index", "TEXT badsveindex(SB),$0-0\n\tZINDEX R0, R1, V0.D\n\tRET\n", "simd",
			"unknown AClass, addr =", "cmd/internal/obj/arm64.aclass("},
		{"cross-text-target", arm64PrivateRegisterHelperSource("4,$0-0", "CALL mix<>(SB)") +
			"TEXT ·Escape(SB),4,$0-0\nB -3(PC)\n", "",
			"setting branch target when type is not TYPE_BRANCH", "cmd/internal/obj.(*Addr).SetTarget("},
	}
	for _, op := range arm64NamedPCBranchOps {
		for _, target := range []string{"999(PC)", "-999(PC)", "9223372036854775807(PC)", "-9223372036854775808(PC)"} {
			tests = append(tests, struct {
				name, source, experiment, panicText, stackFrame string
			}{
				op + "/" + target,
				"TEXT pcInvalid(SB),$0-24\n" + arm64NamedPCBranchInstruction(op, target) + "\nRET\n", "",
				"setting branch target when type is not TYPE_BRANCH", "cmd/internal/obj.(*Addr).SetTarget(",
			})
		}
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			observation := observeGoAssemblerMalformedInput(t, test.source, test.experiment)
			defect, err := goAssemblerMalformedInputOutcome(observation, test.panicText, test.stackFrame)
			if err != nil {
				t.Fatalf("%v\n%s\noriginal source:\n%s", err, observation.output, test.source)
			}
			if defect {
				t.Logf("GO_ASSEMBLER_DEFECT_OBSERVATION: %s; not Go form-rejection or object-compilation evidence\n%s", test.panicText, observation.output)
			}
		})
	}
}

func TestGoAssemblerMalformedInputObservationRejectsInfrastructure(t *testing.T) {
	const source = "TEXT badvectorconstant(SB),$0-0\n\tVMOVQ $1, V1\n\tRET\n"
	actual := observeGoAssemblerMalformedInput(t, source, "")
	const panicText = "runtime error: invalid memory address or nil pointer dereference"
	const stack = "cmd/internal/obj/arm64.progedit("
	if _, err := goAssemblerMalformedInputOutcome(actual, "", ""); err == nil {
		t.Fatal("empty known-defect identity accepted")
	}
	accepted := observeGoAssemblerMalformedInput(t, "TEXT valid(SB),$0-0\nRET\n", "")
	if _, err := goAssemblerMalformedInputOutcome(accepted, panicText, stack); err == nil {
		t.Fatal("a successful object became a source-defect observation")
	}
	for _, change := range []string{"no output", "unrelated panic", "missing stack", "changed source", "joined cleanup", "deadline", "launch", "late infrastructure"} {
		t.Run(change, func(t *testing.T) {
			observation := actual
			switch change {
			case "no output":
				observation.output = nil
			case "unrelated panic":
				observation.output = []byte("panic: unknown compiler error\n" + stack)
			case "missing stack":
				observation.output = []byte("panic: " + panicText)
			case "changed source":
				observation.original += "RET\n"
			case "joined cleanup":
				observation.commandErr = errors.Join(actual.commandErr, errors.New("owned cleanup failure"))
			case "deadline":
				observation.contextErr = context.DeadlineExceeded
			case "launch":
				observation.commandErr = errors.New("compiler launch failed")
			case "late infrastructure":
				observation.output = append(append([]byte(nil), actual.output...), []byte("fatal error: out of memory\n")...)
			}
			if _, err := goAssemblerMalformedInputOutcome(observation, panicText, stack); err == nil {
				t.Fatal("unknown tool/infrastructure outcome became a known source-defect observation")
			}
		})
	}
}
