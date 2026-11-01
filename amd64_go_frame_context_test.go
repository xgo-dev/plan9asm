package plan9asm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type goAMD64FrameCallbackContext struct {
	context.Context
	method   string
	armed    atomic.Bool
	called   atomic.Bool
	locked   atomic.Bool
	callback func()
}

func (ctx *goAMD64FrameCallbackContext) call(method string) {
	if ctx.method == method && ctx.armed.CompareAndSwap(true, false) {
		ctx.called.Store(true)
		ctx.callback()
	}
}

func (ctx *goAMD64FrameCallbackContext) Err() error {
	ctx.call("Err")
	return ctx.Context.Err()
}

func (ctx *goAMD64FrameCallbackContext) Deadline() (time.Time, bool) {
	ctx.call("Deadline")
	return ctx.Context.Deadline()
}

func (ctx *goAMD64FrameCallbackContext) Done() <-chan struct{} {
	ctx.call("Done")
	return ctx.Context.Done()
}

func goAMD64FrameCloseCallback(t *testing.T, original context.Context, source *GoAMD64FrameSource, method string) *goAMD64FrameCallbackContext {
	t.Helper()
	ctx := &goAMD64FrameCallbackContext{Context: original, method: method}
	ctx.callback = func() {
		// A synchronous Close here would deadlock if the callback owns mu.
		// Record the actual lock boundary without leaving a blocked goroutine
		// or a deferred cleanup that can never complete in the RED test.
		if !source.mu.TryLock() {
			ctx.locked.Store(true)
			return
		}
		source.mu.Unlock()
		if err := source.Close(); err != nil {
			t.Errorf("context callback could not close its original source: %v", err)
		}
	}
	return ctx
}

func TestGoAMD64FrameVerifyContextCallbacksMayClose(t *testing.T) {
	for _, method := range []string{"Err", "Deadline", "Done"} {
		t.Run(method, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			original, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(original, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			ctx := goAMD64FrameCloseCallback(t, original, source, method)
			ctx.armed.Store(true)
			err = source.Verify(ctx)
			if ctx.locked.Load() || !ctx.called.Load() {
				t.Fatalf("caller %s callback ran under frame lock (Close would deadlock) or was never sampled", method)
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("callback-closed source verified", err)
			}
			if err := source.Verify(original); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("callback source revocation was not permanent", err)
			}
		})
	}
}

func TestGoAMD64FrameBindRetainsOriginalContextLifetime(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	source := requireGoAMD64FrameCapture(t, pkg, request)
	original, cancel := runtimeOracleStageContext(t)
	defer cancel()
	bound, err := source.BindFixedLocal(original, pkg, file, options)
	if err != nil {
		t.Fatal(err)
	}
	binding := bound.Sigs[pkg.Path+".Value"].x86FixedLocal
	if binding == nil || binding.context != original {
		t.Fatal("binding retained temporary private command context instead of caller lifetime")
	}
	if err := binding.verify(); err != nil {
		t.Fatal("stopping private binder commands revoked the live original binding", err)
	}
	cancel()
	if err := binding.verify(); !errors.Is(err, context.Canceled) {
		t.Fatal("original caller cancellation was ignored", err)
	}
	if err := source.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("fresh context revived a source revoked by original binding cancellation", err)
	}
}

type goAMD64FramePostContext struct {
	context.Context
	samples  int
	callback func()
}

func (ctx *goAMD64FramePostContext) Err() error {
	ctx.samples++
	if ctx.samples == 3 {
		// The first two samples capture the caller lifetime. This sample is
		// the final callback boundary after the complete locked command round.
		ctx.callback()
	}
	return ctx.Context.Err()
}

func TestGoAMD64FrameVerifyPostContextMutationRevokes(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	original, cancel := runtimeOracleStageContext(t)
	defer cancel()
	source, err := CaptureGoAMD64FrameSource(original, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	ctx := &goAMD64FramePostContext{Context: original, callback: func() {
		if !source.mu.TryLock() {
			t.Fatal("post-context callback held the frame lock")
		}
		source.mu.Unlock()
		if err := os.WriteFile(filepath.Join(request.Directory, request.AssemblyFile), []byte("changed original source\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) || ctx.samples < 3 {
		t.Fatal("final caller callback changed source after the last complete input guard", err)
	}
	if err := source.Verify(original); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("final callback mutation did not permanently revoke source", err)
	}
}

type goAMD64FrameChangingContext struct {
	context.Context
	shift time.Duration
	done  <-chan struct{}
}

func (ctx *goAMD64FrameChangingContext) Deadline() (time.Time, bool) {
	deadline, bounded := ctx.Context.Deadline()
	return deadline.Add(ctx.shift), bounded
}

func (ctx *goAMD64FrameChangingContext) Done() <-chan struct{} {
	return ctx.done
}

func TestGoAMD64FramePrivateContextExactLifetime(t *testing.T) {
	if private, err := captureGoAMD64FramePrivateContext(nil); private != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("nil caller acquired a private command context", err)
	}
	for _, bounded := range []bool{false, true} {
		original := context.Background()
		cancel := func() {}
		if bounded {
			original, cancel = context.WithTimeout(original, time.Minute)
		}
		private, err := captureGoAMD64FramePrivateContext(original)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		want, wantBounded := original.Deadline()
		got, gotBounded := private.Deadline()
		if gotBounded != wantBounded || gotBounded && !got.Equal(want) || private.verify() != nil {
			t.Fatal("private context changed actual ordinary caller lifetime")
		}
		private.stop()
		if original.Err() != nil || !errors.Is(private.Err(), context.Canceled) {
			t.Fatal("owned private cleanup canceled its original caller")
		}
		cancel()
	}
	for _, axis := range []string{"deadline", "done", "cancel"} {
		t.Run(axis, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			caller := &goAMD64FrameChangingContext{Context: original, done: original.Done()}
			private, err := captureGoAMD64FramePrivateContext(caller)
			if err != nil {
				t.Fatal(err)
			}
			defer private.stop()
			switch axis {
			case "deadline":
				caller.shift = time.Second
			case "done":
				caller.done = make(chan struct{})
			case "cancel":
				cancel()
			}
			if err := private.verify(); axis == "cancel" && !errors.Is(err, context.Canceled) ||
				axis != "cancel" && !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed actual caller lifetime was accepted", err)
			}
		})
	}
}
