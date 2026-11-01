package plan9asm

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestRuntimeOracleStageDeadline(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, test := range []struct {
		name     string
		deadline time.Time
		has      bool
		want     time.Time
	}{
		{name: "no overall deadline", want: now.Add(5 * time.Minute)},
		{name: "long overall deadline", deadline: now.Add(20 * time.Minute), has: true, want: now.Add(5 * time.Minute)},
		{name: "short overall deadline", deadline: now.Add(30 * time.Second), has: true, want: now.Add(27 * time.Second)},
		{name: "exact reserve boundary", deadline: now.Add(5*time.Minute + 3*time.Second), has: true, want: now.Add(5 * time.Minute)},
		{name: "only cleanup remains", deadline: now.Add(2 * time.Second), has: true, want: now.Add(-time.Second)},
		{name: "overall already expired", deadline: now.Add(-10 * time.Second), has: true, want: now.Add(-13 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := runtimeOracleStageDeadline(now, test.deadline, test.has)
			if !got.Equal(test.want) {
				t.Fatalf("stage deadline = %s, want %s", got, test.want)
			}
		})
	}
}

func TestRuntimeOracleStageBudgetsAreIndependent(t *testing.T) {
	now := time.Unix(1700000000, 0)
	whole := now.Add(12 * time.Minute)
	first := runtimeOracleStageDeadline(now, whole, true)
	second := runtimeOracleStageDeadline(now.Add(4*time.Minute), whole, true)
	third := runtimeOracleStageDeadline(now.Add(8*time.Minute), whole, true)
	if !first.Equal(now.Add(5*time.Minute)) || !second.Equal(now.Add(9*time.Minute)) ||
		!third.Equal(whole.Add(-3*time.Second)) {
		t.Fatalf("stage budgets did not reset or exceeded whole deadline: %s %s %s", first, second, third)
	}
}

func TestRuntimeOracleProofLifetimeKeepsStageAndOverallBounds(t *testing.T) {
	now := time.Unix(1700000000, 0)
	whole := now.Add(30 * time.Minute)
	lease := runtimeOracleBoundedDeadline(now, whole, true, runtimeOracleProofTimeout)
	if !lease.Equal(now.Add(20 * time.Minute)) {
		t.Fatal("composed proof lost its finite multi-stage lifetime", lease)
	}
	for _, elapsed := range []time.Duration{0, 4 * time.Minute, 8 * time.Minute} {
		stage := runtimeOracleStageDeadline(now.Add(elapsed), lease, true)
		if !stage.Equal(now.Add(elapsed + 5*time.Minute)) {
			t.Fatal("proof lifetime enlarged or consumed a stage budget", elapsed, stage)
		}
	}
	for _, remaining := range []time.Duration{8 * time.Minute, 2 * time.Second, -time.Second} {
		deadline := runtimeOracleBoundedDeadline(now, now.Add(remaining), true, runtimeOracleProofTimeout)
		if !deadline.Equal(now.Add(remaining - runtimeOracleStageCleanupReserve)) {
			t.Fatal("proof lease exceeded the overall deadline or lost cleanup", remaining, deadline)
		}
	}
	ctx, cancel := runtimeOracleProofContext(t)
	deadline, has := ctx.Deadline()
	if !has || deadline.After(time.Now().Add(runtimeOracleProofTimeout)) {
		t.Fatal("actual proof context is unbounded", deadline, has)
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("proof cancellation was lost", ctx.Err())
	}
}

func TestRuntimeOracleSourceProofFixturesUseComposedLifetimes(t *testing.T) {
	// These factories retain live owners after returning. Their consumers run
	// multiple capture, binding and API checks against the same context; a
	// command-stage lease incorrectly expires partway through that proof.
	for _, fixture := range []struct{ file, function string }{
		{"go_x86_numerical_read_consumer_guard_test.go", "numericalConsumerFactory"},
		{"go_x86_numerical_read_family_test.go", "numericalExecutionFixture"},
		{"go_x86_numerical_read_local_test.go", "numericalLocalFactoryWithContext"},
		{"go_x86_numerical_read_sdk_test.go", "numericalSDKCRC32Request"},
		{"go_x86_numerical_read_sdk_test.go", "numericalSDKCPURequest"},
		{"go_x86_sdk_asm_data_live_test.go", "sdkASMDataRequest"},
	} {
		t.Run(fixture.function, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), fixture.file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			proofs, stages, found := 0, 0, false
			for _, declaration := range file.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Name.Name != fixture.function {
					continue
				}
				found = true
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := call.Fun.(*ast.Ident); ok {
						switch name.Name {
						case "runtimeOracleProofContext":
							proofs++
						case "runtimeOracleStageContext":
							stages++
						}
					}
					return true
				})
			}
			if !found || proofs != 1 || stages != 0 {
				t.Fatalf("source-proof factory has found=%v proof leases=%d command-stage leases=%d", found, proofs, stages)
			}
		})
	}
}

func TestRuntimeOracleStageContextUsesActualTestDeadline(t *testing.T) {
	before := time.Now()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	deadline, found := ctx.Deadline()
	if !found || deadline.After(time.Now().Add(runtimeOracleStageTimeout)) || deadline.Before(before) {
		t.Fatalf("missing or unbounded actual stage context: %s, %v", deadline, found)
	}
	if whole, found := t.Deadline(); found && deadline.After(whole.Add(-runtimeOracleStageCleanupReserve)) {
		t.Fatalf("stage consumes its test's cleanup reserve: stage %s, whole %s", deadline, whole)
	}
	cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("stage cancellation was lost: %v", ctx.Err())
	}
}

func TestRuntimeOracleStageExpiredBudgetDoesNotLaunch(t *testing.T) {
	now := time.Now()
	deadline := runtimeOracleStageDeadline(now, now.Add(2*time.Second), true)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleCommandFixture$")
	output, err := runtimeOracleCombinedOutput(ctx, command)
	if !errors.Is(err, context.DeadlineExceeded) || len(output) != 0 || command.Process != nil {
		t.Fatalf("expired stage launched a process or lost its failure: %v %q", err, output)
	}
}

func TestRuntimeExecUsesSeparateBoundedStageContexts(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "runtime_exec_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var function *ast.FuncDecl
	for _, decl := range file.Decls {
		if candidate, ok := decl.(*ast.FuncDecl); ok && candidate.Name.Name == "compileAndRunRuntimeTestWithCompiler" {
			function = candidate
		}
	}
	if function == nil {
		t.Fatal("runtime compilation consumer missing")
	}
	contexts, commands, consumers, cancellations := 0, 0, 0, 0
	ast.Inspect(function.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := call.Fun.(*ast.Ident); ok {
			switch ident.Name {
			case "runtimeOracleStageContext":
				contexts++
			case "runtimeOracleCombinedOutput":
				consumers++
			case "cancel":
				cancellations++
			}
		}
		if method, ok := call.Fun.(*ast.SelectorExpr); ok {
			if receiver, ok := method.X.(*ast.Ident); ok && receiver.Name == "exec" {
				if method.Sel.Name != "CommandContext" {
					t.Errorf("runtime stage lost its context: exec.%s", method.Sel.Name)
				}
				commands++
			}
		}
		return true
	})
	if contexts != 3 || commands != 3 || consumers != 3 || cancellations != 3 {
		t.Fatalf("three independently bounded stages required: context=%d command=%d consumer=%d cancel=%d",
			contexts, commands, consumers, cancellations)
	}
}
