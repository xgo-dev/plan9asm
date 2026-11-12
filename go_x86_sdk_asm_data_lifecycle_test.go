//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sdkASMDataReentrantContext struct {
	context.Context
	armed    atomic.Bool
	callback func()
	method   string
	lost     atomic.Bool
	shift    atomic.Int64
}

func (ctx *sdkASMDataReentrantContext) Err() error {
	ctx.call("Err")
	return ctx.Context.Err()
}

func (ctx *sdkASMDataReentrantContext) Deadline() (time.Time, bool) {
	ctx.call("Deadline")
	if ctx.lost.Load() {
		return time.Time{}, false
	}
	deadline, bounded := ctx.Context.Deadline()
	return deadline.Add(time.Duration(ctx.shift.Load())), bounded
}

func (ctx *sdkASMDataReentrantContext) Done() <-chan struct{} {
	ctx.call("Done")
	return ctx.Context.Done()
}

func (ctx *sdkASMDataReentrantContext) call(method string) {
	if (ctx.method == "" && method == "Err" || ctx.method == method) && ctx.armed.CompareAndSwap(true, false) {
		ctx.callback()
	}
}

func TestGoX86SDKASMDataLiveValidationAPIReentry(t *testing.T) {
	for _, route := range []string{"verification", "original"} {
		for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
			t.Run(route+"/"+api, func(t *testing.T) {
				sdkASMDataCheckIsolatedReentry(t, route, "Err", api)
			})
		}
	}
}

func TestGoX86SDKASMDataLiveContextMethodReentry(t *testing.T) {
	for _, route := range []string{"verification", "original"} {
		for _, method := range []string{"Deadline", "Done"} {
			for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
				t.Run(route+"/"+method+"/"+api, func(t *testing.T) {
					sdkASMDataCheckIsolatedReentry(t, route, method, api)
				})
			}
		}
	}
}

func sdkASMDataCheckIsolatedReentry(t *testing.T, route, method, api string) {
	t.Helper()
	const childKey = "PLAN9ASM_SDK_DATA_REENTRY_CHILD"
	receipt := "sdk-data-reentry-ok:" + t.Name() + "\n"
	if os.Getenv(childKey) != t.Name() {
		// A context cannot interrupt a synchronous callback holding a mutex.
		// Own a child instead of mistaking slow source verification for deadlock
		// or leaving an in-process worker blocked during source.Close cleanup.
		ctx, cancel := runtimeOracleStageContext(t)
		defer cancel()
		deadline, _ := ctx.Deadline()
		parts := strings.Split(t.Name(), "/")
		for index, part := range parts {
			parts[index] = "^" + regexp.QuoteMeta(part) + "$"
		}
		command := exec.CommandContext(ctx, os.Args[0], "-test.run="+strings.Join(parts, "/"),
			"-test.count=1", "-test.timeout="+(time.Until(deadline)+runtimeOracleStageCleanupReserve).String())
		command.Env = append(os.Environ(), childKey+"="+t.Name())
		output, err := runtimeOracleCombinedOutput(ctx, command)
		if err != nil || strings.Count(string(output), receipt) != 1 {
			t.Fatalf("bounded actual SDK reentry child failed or did not complete: %v\n%s", err, output)
		}
		return
	}

	ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
	reentrant := &sdkASMDataReentrantContext{Context: ctx, method: method}
	captureContext := ctx
	if route == "original" {
		captureContext = reentrant
	}
	source, err := CaptureGoX86SDKASMDataSource(captureContext, request)
	if err != nil {
		t.Fatal("actual SDK source precondition", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	raw, err := source.Readback(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var nested error
	reentrant.callback = func() {
		_, nested = sdkASMDataInvoke(t, api, source, ctx, raw)
	}
	reentrant.armed.Store(true)
	if err := errors.Join(source.Verify(reentrant), nested); err != nil {
		t.Fatal("live original/nested observation failed", err)
	}
	if reentrant.armed.Load() {
		t.Fatal("actual verification did not invoke the context reentry callback")
	}
	fmt.Print(receipt)
}

func TestGoX86SDKASMDataLiveLostOriginalDeadline(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
	original := &sdkASMDataReentrantContext{Context: ctx}
	source, err := CaptureGoX86SDKASMDataSource(original, request)
	if err != nil {
		t.Fatal("actual bounded original source precondition", err)
	}
	defer source.Close()
	original.lost.Store(true)
	// A fresh caller with a deadline must not restore the original capture
	// context's lost bounded lifecycle or turn it into a new generation.
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("fresh bounded caller restored a lost original deadline", err)
	}
	original.lost.Store(false)
	if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
		t.Fatal("restored original deadline revived the failed source")
	}
}

func sdkASMDataInvoke(t *testing.T, api string, source *GoX86SDKASMDataSource, ctx context.Context, raw []byte) ([]byte, error) {
	t.Helper()
	switch api {
	case "Verify":
		return nil, source.Verify(ctx)
	case "Readback":
		return source.Readback(ctx)
	case "CheckReadback":
		return nil, source.CheckReadback(ctx, raw)
	default:
		t.Fatal("unknown observation API", api)
		return nil, nil
	}
}

func TestGoX86SDKASMDataLiveOriginalDeadlineCannotChange(t *testing.T) {
	for _, change := range []struct {
		name  string
		shift time.Duration
	}{
		{"earlier", -time.Minute},
		{"later", time.Minute},
	} {
		for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
			t.Run(change.name+"/"+api, func(t *testing.T) {
				ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
				original := &sdkASMDataReentrantContext{Context: ctx}
				source, err := CaptureGoX86SDKASMDataSource(original, request)
				if err != nil {
					t.Fatal("actual bounded original source precondition", err)
				}
				defer source.Close()
				raw, err := source.Readback(ctx)
				if err != nil {
					t.Fatal(err)
				}

				original.shift.Store(int64(change.shift))
				returned, err := sdkASMDataInvoke(t, api, source, ctx, raw)
				if !errors.Is(err, ErrProbeNeedsContext) || len(returned) != 0 {
					t.Fatal("changed bounded original deadline kept its captured generation", err)
				}
				original.shift.Store(0)
				if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("restoring the original deadline revived a revoked source")
				}
			})
		}
	}
}

func TestGoX86SDKASMDataLiveOriginalDeadlineCallbackCannotPublish(t *testing.T) {
	for _, route := range []string{"original", "verification"} {
		for _, api := range []string{"Verify", "Readback", "CheckReadback"} {
			t.Run(route+"/"+api, func(t *testing.T) {
				ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
				original := &sdkASMDataReentrantContext{Context: ctx}
				source, err := CaptureGoX86SDKASMDataSource(original, request)
				if err != nil {
					t.Fatal("actual bounded original source precondition", err)
				}
				defer source.Close()
				raw, err := source.Readback(ctx)
				if err != nil {
					t.Fatal(err)
				}

				callback := &sdkASMDataReentrantContext{Context: ctx}
				verification := context.Context(callback)
				if route == "original" {
					callback, verification = original, ctx
				}
				callback.method = "Done"
				callback.callback = func() { original.shift.Store(int64(time.Minute)) }
				callback.armed.Store(true)
				returned, err := sdkASMDataInvoke(t, api, source, verification, raw)
				if !errors.Is(err, ErrProbeNeedsContext) || len(returned) != 0 {
					t.Fatal("context callback published a changed original generation", err)
				}
				original.shift.Store(0)
				if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
					t.Fatal("restoring callback-mutated deadline revived the source")
				}
			})
		}
	}
}

func TestGoX86SDKASMDataLiveCallerDeadlineOnlyTightens(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	for _, kind := range []string{"earlier", "same", "later", "unbounded"} {
		t.Run(kind, func(t *testing.T) {
			caller := context.Background()
			wanted := source.originalDeadline
			if kind != "unbounded" {
				deadline := wanted
				if kind == "earlier" {
					deadline = deadline.Add(-time.Minute)
					wanted = deadline
				} else if kind == "later" {
					deadline = deadline.Add(time.Minute)
				}
				bounded, cancel := context.WithDeadline(caller, deadline)
				defer cancel()
				caller = bounded
			}
			private, stop, err := sdkASMDataPrivateContext(caller, ctx, source.originalDeadline)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			actual, bounded := private.Deadline()
			if !bounded || !actual.Equal(wanted) {
				t.Fatal("caller extended or replaced the captured deadline", actual, wanted)
			}
			if err := source.Verify(caller); err != nil {
				t.Fatal("unchanged original generation rejected a caller deadline", err)
			}
		})
	}
}

func TestGoX86SDKASMDataLiveCloseDuringContextCallback(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	owned := source.guard.owned
	var nested error
	reentrant := &sdkASMDataReentrantContext{Context: ctx, callback: func() {
		nested = source.Close()
		if _, err := os.Stat(owned); err != nil {
			nested = errors.Join(nested, fmt.Errorf("active lease lost its artifact owner: %w", err))
		}
	}}
	reentrant.armed.Store(true)
	if err := source.Verify(reentrant); !errors.Is(err, ErrProbeNeedsContext) || nested != nil {
		t.Fatal("reentrant Close published a stale observation or lost active artifacts", err, nested)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("last active lease did not dispose closed artifacts", err)
	}
}

func TestGoX86SDKASMDataLiveConcurrentVerifyAndClose(t *testing.T) {
	ctx, source := sdkASMDataCapture(t)
	var group sync.WaitGroup
	errorsOut := make(chan error, 4)
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			errorsOut <- source.Verify(ctx)
		}()
	}
	group.Wait()
	close(errorsOut)
	for err := range errorsOut {
		if err != nil {
			t.Fatal("ordinary concurrent Verify was spuriously revoked", err)
		}
	}
	entered, resume := make(chan struct{}), make(chan struct{})
	reentrant := &sdkASMDataReentrantContext{Context: ctx, callback: func() {
		close(entered)
		<-resume
	}}
	reentrant.armed.Store(true)
	done := make(chan error, 1)
	go func() { done <- source.Verify(reentrant) }()
	<-entered
	owned := source.guard.owned
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(owned); err != nil {
		t.Fatal("concurrent Close disposed active callback inputs", err)
	}
	close(resume)
	if err := <-done; !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("concurrent Close published a source from a stale generation", err)
	}
	if _, err := os.Stat(owned); !os.IsNotExist(err) {
		t.Fatal("concurrent Close retained its closed artifact directory", err)
	}
}

func TestGoX86SDKASMDataLiveContextCauses(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline", "nil"} {
		t.Run(cause, func(t *testing.T) {
			ctx, source := sdkASMDataCapture(t)
			verification := context.Context(nil)
			want := ErrProbeNeedsContext
			if cause == "cancel" {
				cancelled, cancel := context.WithCancel(ctx)
				cancel()
				verification, want = cancelled, context.Canceled
			} else if cause == "deadline" {
				expired, cancel := context.WithDeadline(ctx, time.Now().Add(-time.Second))
				defer cancel()
				verification, want = expired, context.DeadlineExceeded
			}
			if err := source.Verify(verification); !errors.Is(err, want) ||
				cause != "nil" && errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("verification lost actual context cause", err)
			}
			if !errors.Is(source.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("fresh context revived a permanently failed observation")
			}
		})
	}
}
