package plan9asm

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// Startup and observation have independent bounds. Only a consumed caller-ready
// marker starts the complete nonreturning window; it does not identify an ASM PC.
// Parent expiry or an exit without our direct-child kill witness never passes.
// Drivers must publish a continuation marker immediately if the target returns:
// process teardown can outlive the window and is not target nonreturning behavior.
func runtimeOracleObserveSink(parent context.Context, command func(context.Context) *exec.Cmd, startup, window time.Duration) ([]byte, error) {
	if parent == nil || command == nil || startup <= 0 || window <= 0 {
		return nil, fmt.Errorf("sink requires its parent, command and positive bounds")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	// time.Now carries a monotonic clock. Factory time and a ready-vs-timer
	// selection race must not extend this absolute startup budget.
	startupDeadline := time.Now().Add(startup)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	cmd := command(ctx)
	if cmd == nil || cmd.Process != nil || cmd.Stdout != nil || cmd.Stderr != nil {
		return nil, fmt.Errorf("sink requires a fresh command without output writers")
	}
	if !time.Now().Before(startupDeadline) {
		return nil, errors.Join(fmt.Errorf("sink command factory exhausted its startup deadline"), parent.Err())
	}
	output := &runtimeOracleSinkOutput{ready: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = output, output
	cmd.WaitDelay = 2 * time.Second
	done := make(chan error, 1)
	go func() { done <- runtimeOracleRun(cmd) }()

	finish := func(cause error) ([]byte, error) {
		killedDirectChild := false
		if cause == nil {
			// A final SIGKILL alone cannot distinguish our cancellation from
			// a prior crash while a descendant still holds the output pipe.
			// Readiness publishes Start's Process; failure paths do not read
			// that concurrently initialized field. Kill must acknowledge this
			// invocation's owned direct child before group cleanup begins.
			if cmd.Process == nil {
				cause = fmt.Errorf("ready sink has no owned direct child")
			} else if err := cmd.Process.Kill(); err != nil {
				cause = fmt.Errorf("sink direct-child cancellation was not acknowledged: %w", err)
			} else {
				killedDirectChild = true
			}
		}
		cancel()
		cleanup := time.NewTimer(3 * time.Second)
		defer cleanup.Stop()
		var runErr error
		select {
		case runErr = <-done:
		case <-cleanup.C:
			data, outputErr := output.snapshot()
			return data, errors.Join(cause, outputErr, fmt.Errorf("sink command cleanup exceeded its bound"))
		}
		data, outputErr := output.snapshot()
		if cause != nil || outputErr != nil || parent.Err() != nil {
			return data, errors.Join(cause, outputErr, parent.Err(), runErr)
		}
		if !runtimeOracleSinkCanceledExit(runErr, killedDirectChild) || string(data) != "entered\n" {
			return data, errors.Join(fmt.Errorf("sink returned, trapped or changed its output: %q", data), runErr)
		}
		return data, nil
	}
	finishedEarly := func(err error) ([]byte, error) {
		data, outputErr := output.snapshot()
		return data, errors.Join(fmt.Errorf("sink exited before its complete entered window"), err, outputErr, parent.Err())
	}

	start := time.NewTimer(time.Until(startupDeadline))
	defer start.Stop()
	select {
	case err := <-done:
		return finishedEarly(err)
	case <-ctx.Done():
		return finish(ctx.Err())
	case <-start.C:
		return finish(fmt.Errorf("sink entry marker not consumed before startup deadline"))
	case <-output.ready:
		start.Stop()
		if !time.Now().Before(startupDeadline) {
			return finish(fmt.Errorf("sink entry marker not consumed before startup deadline"))
		}
	}

	observe := time.NewTimer(window)
	defer observe.Stop()
	select {
	case err := <-done:
		return finishedEarly(err)
	case <-ctx.Done():
		return finish(ctx.Err())
	case <-observe.C:
		// An already available exit cannot be mistaken for our cancellation.
		select {
		case err := <-done:
			return finishedEarly(err)
		default:
		}
		return finish(nil)
	}
}

type runtimeOracleSinkOutput struct {
	mu      sync.Mutex
	data    bytes.Buffer
	ready   chan struct{}
	entered bool
	err     error
}

func (output *runtimeOracleSinkOutput) Write(data []byte) (int, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	const limit = 64 * 1024
	if output.err != nil {
		return 0, output.err
	}
	if len(data) > limit-output.data.Len() {
		output.err = fmt.Errorf("sink output exceeds %d bytes", limit)
		return 0, output.err
	}
	count, err := output.data.Write(data)
	if !output.entered && bytes.HasPrefix(output.data.Bytes(), []byte("entered\n")) {
		output.entered = true
		close(output.ready)
	}
	return count, err
}

func (output *runtimeOracleSinkOutput) snapshot() ([]byte, error) {
	output.mu.Lock()
	defer output.mu.Unlock()
	return append([]byte(nil), output.data.Bytes()...), output.err
}

func TestRuntimeOracleSinkColdStartupDoesNotConsumeObservation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	start := time.Now()
	output, err := runtimeOracleObserveSink(ctx, runtimeOracleSinkFixtureCommand("delayed"), time.Second, 80*time.Millisecond)
	if err != nil || string(output) != "entered\n" {
		t.Fatalf("cold startup consumed the entered observation: %v output=%q", err, output)
	}
	if time.Since(start) < 380*time.Millisecond {
		t.Fatal("sink was not observed for the full window after entry")
	}
}

func TestRuntimeOracleSinkRejectsStartupBudgetConsumedByFactory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	factory := func(ctx context.Context) *exec.Cmd {
		time.Sleep(300 * time.Millisecond)
		return runtimeOracleSinkFixtureCommand("entered")(ctx)
	}
	output, err := runtimeOracleObserveSink(ctx, factory, 80*time.Millisecond, 80*time.Millisecond)
	if err == nil {
		t.Fatalf("expired startup budget accepted: output=%q", output)
	}
	if len(output) != 0 {
		t.Fatalf("expired factory launched its command: output=%q error=%v", output, err)
	}
}

func runtimeOracleSinkFixtureCommand(mode string) func(context.Context) *exec.Cmd {
	return func(ctx context.Context) *exec.Cmd {
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestRuntimeOracleSinkFixture$")
		// A race-instrumented fixture deliberately sleeps in os.Exit by
		// default. Remove only that artificial exit delay, so the negative
		// fixtures test real early process exit, not instrumentation sleep.
		// Actual Go/LLVM assembly oracles do not inherit this override.
		command.Env = append(os.Environ(), "PLAN9ASM_RUNTIME_SINK_FIXTURE="+mode, "GORACE=atexit_sleep_ms=0")
		return command
	}
}

func TestRuntimeOracleSinkFixture(t *testing.T) {
	mode := os.Getenv("PLAN9ASM_RUNTIME_SINK_FIXTURE")
	if mode == "" {
		return
	}
	if mode == "delayed" {
		time.Sleep(300 * time.Millisecond)
	}
	if mode == "missing" {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	if mode == "early-exit" {
		os.Exit(0)
	}
	if mode == "bad-marker" {
		fmt.Println("not entered")
	} else if mode == "split-marker" {
		fmt.Print("enter")
		time.Sleep(10 * time.Millisecond)
		fmt.Print("ed\n")
	} else if mode == "returned" || mode == "returned-delayed-exit" {
		// Publish the completed control path in one write. Neither a slow
		// Windows process teardown nor scheduling after readiness may turn
		// this completed target into a successful nonreturning observation.
		fmt.Print("entered\nreturned\n")
	} else if mode == "trapped" {
		fmt.Print("entered\ntrapped\n")
	} else {
		fmt.Println("entered")
	}
	switch mode {
	case "returned":
		os.Exit(0)
	case "returned-delayed-exit":
		// Simulate teardown after the observed call has returned. Process
		// liveness alone cannot distinguish this from the target's sink.
		time.Sleep(300 * time.Millisecond)
		os.Exit(0)
	case "trapped":
		os.Exit(23)
	case "late-return":
		time.Sleep(30 * time.Millisecond)
		fmt.Println("returned")
		os.Exit(0)
	case "extra-output":
		fmt.Fprintln(os.Stderr, "unexpected continuation")
	case "overflow":
		fmt.Print(strings.Repeat("x", 64*1024))
	case "delayed", "entered", "missing", "bad-marker", "split-marker":
	default:
		t.Fatalf("unknown sink fixture %q", mode)
	}
	time.Sleep(5 * time.Second)
	os.Exit(0)
}

func TestRuntimeOracleSinkRejectsMissingEntryAndEarlyExit(t *testing.T) {
	for _, mode := range []string{"missing", "bad-marker", "early-exit", "returned", "returned-delayed-exit", "trapped", "late-return", "extra-output", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			output, err := runtimeOracleObserveSink(ctx, runtimeOracleSinkFixtureCommand(mode), time.Second, 100*time.Millisecond)
			if err == nil {
				t.Fatalf("invalid sink accepted: %s output=%q", mode, output)
			}
			if mode == "returned" || mode == "returned-delayed-exit" || mode == "late-return" {
				if string(output) != "entered\nreturned\n" || ctx.Err() != nil {
					t.Fatalf("return witness was lost or replaced by infrastructure failure: %v output=%q", err, output)
				}
			}
			if mode == "extra-output" && !strings.Contains(string(output), "unexpected continuation") {
				t.Fatalf("sink failure lost its output: %q", output)
			}
		})
	}
}

func TestRuntimeOracleSinkEntryAndSplitMarker(t *testing.T) {
	for _, mode := range []string{"entered", "split-marker"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			output, err := runtimeOracleObserveSink(ctx, runtimeOracleSinkFixtureCommand(mode), time.Second, 80*time.Millisecond)
			if err != nil || string(output) != "entered\n" {
				t.Fatalf("complete entered window rejected: %v output=%q", err, output)
			}
		})
	}
}

func TestRuntimeOracleSinkParentDeadlineCannotPass(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	output, err := runtimeOracleObserveSink(ctx, runtimeOracleSinkFixtureCommand("entered"), time.Second, time.Second)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("incomplete observation lost its parent deadline: %v output=%q", err, output)
	}
}

func TestRuntimeOracleSinkParentCancellationCannotPass(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	readyFactory := func(ctx context.Context) *exec.Cmd {
		time.AfterFunc(100*time.Millisecond, cancel)
		return runtimeOracleSinkFixtureCommand("entered")(ctx)
	}
	output, err := runtimeOracleObserveSink(ctx, readyFactory, time.Second, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("incomplete observation lost parent cancellation: %v output=%q", err, output)
	}
}

func TestRuntimeOracleSinkRequiresFreshBoundedCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, test := range []struct {
		name            string
		parent          context.Context
		factory         func(context.Context) *exec.Cmd
		startup, window time.Duration
	}{
		{name: "no parent", factory: runtimeOracleSinkFixtureCommand("entered"), startup: time.Second, window: time.Second},
		{name: "no factory", parent: ctx, startup: time.Second, window: time.Second},
		{name: "no startup bound", parent: ctx, factory: runtimeOracleSinkFixtureCommand("entered"), window: time.Second},
		{name: "no observation bound", parent: ctx, factory: runtimeOracleSinkFixtureCommand("entered"), startup: time.Second},
		{name: "no command", parent: ctx, factory: func(context.Context) *exec.Cmd { return nil }, startup: time.Second, window: time.Second},
		{name: "existing output", parent: ctx, factory: func(ctx context.Context) *exec.Cmd {
			command := runtimeOracleSinkFixtureCommand("entered")(ctx)
			command.Stdout = os.Stdout
			return command
		}, startup: time.Second, window: time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			output, err := runtimeOracleObserveSink(test.parent, test.factory, test.startup, test.window)
			if err == nil || len(output) != 0 {
				t.Fatalf("invalid sink command was launched: %v output=%q", err, output)
			}
		})
	}
	cancel()
	if _, err := runtimeOracleObserveSink(ctx, runtimeOracleSinkFixtureCommand("entered"), time.Second, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled parent launched a sink: %v", err)
	}
}

func TestRuntimeOracleSinkOutputOverflowIsFailure(t *testing.T) {
	output := &runtimeOracleSinkOutput{ready: make(chan struct{})}
	if _, err := output.Write([]byte("entered\n")); err != nil {
		t.Fatal(err)
	}
	if count, err := output.Write(make([]byte, 64*1024)); err == nil || count != 0 {
		t.Fatalf("sink overflow accepted: %d %v", count, err)
	}
	data, err := output.snapshot()
	if err == nil || string(data) != "entered\n" {
		t.Fatalf("sink overflow was erased or its retained output changed: %v %q", err, data)
	}
}
