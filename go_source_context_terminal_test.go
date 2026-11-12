package plan9asm

import (
	"context"
	"errors"
	"testing"
	"time"
)

type sourceTerminalTestContext struct {
	context.Context
	errCalls, deadlineCalls, doneCalls int
	shift                              time.Duration
	lost                               bool
	callback                           func(string, int)
	additionalCause                    error
	doneOverride                       <-chan struct{}
	useDoneOverride                    bool
}

func (ctx *sourceTerminalTestContext) Err() error {
	ctx.errCalls++
	if ctx.callback != nil {
		ctx.callback("Err", ctx.errCalls)
	}
	err := ctx.Context.Err()
	if err != nil {
		return errors.Join(err, ctx.additionalCause)
	}
	return nil
}

func (ctx *sourceTerminalTestContext) Deadline() (time.Time, bool) {
	ctx.deadlineCalls++
	if ctx.callback != nil {
		ctx.callback("Deadline", ctx.deadlineCalls)
	}
	deadline, bounded := ctx.Context.Deadline()
	return deadline.Add(ctx.shift), bounded && !ctx.lost
}

func (ctx *sourceTerminalTestContext) Done() <-chan struct{} {
	ctx.doneCalls++
	if ctx.callback != nil {
		ctx.callback("Done", ctx.doneCalls)
	}
	if ctx.useDoneOverride {
		return ctx.doneOverride
	}
	return ctx.Context.Done()
}

// These are lifetime predicates only. None of these zero-ready values is
// passed to a source/owner constructor, Verify, Bind or publication API.
func sourceTerminalTestRoutes() map[string]func(context.Context, *sourceTerminalTestContext, time.Time) error {
	return map[string]func(context.Context, *sourceTerminalTestContext, time.Time) error{
		"SDK-metadata": func(caller context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			return (&GoX86SDKASMDataSource{context: original, originalContext: original, originalDeadline: frozen}).liveContext(caller)
		},
		"SDK-readonly": func(caller context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			return (&GoX86SDKReadonlyLiteralDataOwner{context: original, originalContext: original, originalDeadline: frozen}).liveContext(caller)
		},
		"SDK-minimum": func(caller context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			return (&GoX86SDKLiteralAlignment{context: original, originalContext: original, deadline: frozen}).liveContext(caller)
		},
		"SDK-private-bridge": func(caller context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			_, stop, err := sdkASMDataPrivateContext(caller, original, frozen)
			if stop != nil {
				stop()
			}
			return err
		},
		"ordinary-frame": func(_ context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			return (&goAMD64FramePrivateContext{Context: context.Background(), original: original, deadline: frozen,
				bounded: true, done: original.Context.Done(), cancel: func() {}}).verify()
		},
		"SDK-numerical-join": func(caller context.Context, original *sourceTerminalTestContext, frozen time.Time) error {
			owner := &GoX86SDKReadonlyLiteralDataOwner{context: original.Context, originalContext: original.Context, originalDeadline: frozen}
			return (&numericalSDKLiteralJoin{context: original, Deadline: frozen, owner: owner}).liveContext(caller)
		},
	}
}

func TestGoSourceContextTerminalSuccessHasNoLaterCallbacks(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		t.Run(name, func(t *testing.T) {
			base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			frozen, _ := base.Deadline()
			original := &sourceTerminalTestContext{Context: base}
			terminal, later := false, 0
			original.callback = func(method string, _ int) {
				if terminal {
					later++
				}
				if method == "Deadline" {
					terminal = true
				}
			}
			err := invoke(context.Background(), original, frozen)
			t.Logf("Err=%d Deadline=%d Done=%d later=%d error=%v", original.errCalls, original.deadlineCalls, original.doneCalls, later, err)
			if err != nil || !terminal || later != 0 {
				t.Fatal("successful terminal deadline was followed by user callbacks", err)
			}
		})
	}
}

func TestGoSourceContextTerminalLostBound(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		t.Run(name, func(t *testing.T) {
			base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			frozen, _ := base.Deadline()
			original := &sourceTerminalTestContext{Context: base}
			original.callback = func(method string, count int) {
				if method == "Err" && count == 2 {
					original.lost = true
				}
			}
			if err := invoke(context.Background(), original, frozen); !original.lost || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("last Err removed the original bound", err)
			}
		})
	}
}

func TestGoSourceContextTerminalCaptureCannotFreezeStaleLifetime(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	original := &sourceTerminalTestContext{Context: base}
	original.callback = func(method string, count int) {
		if method == "Err" && count == 2 {
			original.shift = time.Minute
		}
	}
	private, err := captureGoAMD64FramePrivateContext(original)
	if private != nil {
		private.stop()
	}
	t.Logf("Err=%d Deadline=%d Done=%d shift=%s error=%v", original.errCalls, original.deadlineCalls, original.doneCalls, original.shift, err)
	if original.shift == 0 || !errors.Is(err, ErrProbeNeedsContext) || private != nil {
		t.Fatal("frame capture published an already stale lifetime", err)
	}
}

func TestGoSourceContextTerminalOriginalErrCannotChangeLifetime(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		for _, shift := range []time.Duration{-time.Minute, time.Minute} {
			t.Run(name+"/"+shift.String(), func(t *testing.T) {
				base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				frozen, _ := base.Deadline()
				original := &sourceTerminalTestContext{Context: base}
				original.callback = func(method string, count int) {
					if method == "Err" && count == 2 {
						original.shift = shift
					}
				}
				err := invoke(context.Background(), original, frozen)
				t.Logf("Err=%d Deadline=%d Done=%d shift=%s error=%v", original.errCalls, original.deadlineCalls, original.doneCalls, original.shift, err)
				if original.shift != shift || !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("late original Err changed lifetime after the accepted snapshot", err)
				}
			})
		}
	}
}

func TestGoSourceContextTerminalJoinedOwnerCallbackCannotChangeLifetime(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	frozen, _ := base.Deadline()
	original := &sourceTerminalTestContext{Context: base}
	original.callback = func(method string, count int) {
		if method == "Err" && count == 4 {
			original.shift = time.Minute
		}
	}
	owner := &GoX86SDKReadonlyLiteralDataOwner{context: base, originalContext: base, originalDeadline: frozen}
	joined := &numericalSDKLiteralJoin{context: original, Deadline: frozen, owner: owner}
	err := joined.liveContext(original)
	t.Logf("Err=%d Deadline=%d Done=%d shift=%s error=%v", original.errCalls, original.deadlineCalls, original.doneCalls, original.shift, err)
	if original.shift == 0 || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("joined context changed during the owner's last callback", err)
	}
}

func TestGoSourceContextTerminalCancellationSignalsAndCauses(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		for _, method := range []string{"Err", "Done", "Deadline", "Deadline-and-change"} {
			t.Run(name+"/"+method, func(t *testing.T) {
				base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				frozen, _ := base.Deadline()
				cause := errors.New("original caller cancellation cause")
				original := &sourceTerminalTestContext{Context: base, additionalCause: cause}
				reached := false
				original.callback = func(sampled string, count int) {
					if method == "Err" && sampled == "Err" && count == 2 || method == "Done" && sampled == "Done" && count == 1 ||
						(method == "Deadline" || method == "Deadline-and-change") && sampled == "Deadline" && count == 1 {
						reached = true
						cancel()
						if method == "Deadline-and-change" {
							original.shift = time.Minute
						}
					}
				}
				err := invoke(context.Background(), original, frozen)
				if !reached || !errors.Is(err, context.Canceled) || !errors.Is(err, cause) {
					t.Fatal("callback cancellation lost the actual cause", err)
				}
				if method == "Deadline-and-change" && !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("changed lifetime lost its independent classification", err)
				}
			})
		}
	}
}

func TestGoSourceContextTerminalClosedDoneCannotReturnSuccess(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		t.Run(name, func(t *testing.T) {
			base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			frozen, _ := base.Deadline()
			done := make(chan struct{})
			original := &sourceTerminalTestContext{Context: base, doneOverride: done, useDoneOverride: true}
			original.callback = func(method string, count int) {
				if method == "Deadline" && count == 1 {
					close(done)
				}
			}
			err := invoke(context.Background(), original, frozen)
			if !errors.Is(err, ErrProbeNeedsContext) || base.Err() != nil {
				t.Fatal("closed Done with nil Err acquired a successful lifetime", err)
			}
			if original.errCalls > 4 || original.deadlineCalls != 1 || original.doneCalls > 2 {
				t.Fatal("closed-Done failure resampled or retried user callbacks")
			}
		})
	}
}

func TestGoSourceContextTerminalSameContextRolesAreBounded(t *testing.T) {
	for name, invoke := range sourceTerminalTestRoutes() {
		t.Run(name, func(t *testing.T) {
			base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			frozen, _ := base.Deadline()
			original := &sourceTerminalTestContext{Context: base}
			if err := invoke(original, original, frozen); err != nil {
				t.Fatal("one unchanged context could not occupy both existing roles", err)
			}
			if original.errCalls > 6 || original.deadlineCalls > 2 || original.doneCalls > 3 {
				t.Fatal("duplicate roles caused an unbounded sampling loop")
			}
			if original.errCalls == 0 || original.deadlineCalls == 0 || original.doneCalls == 0 {
				t.Fatal("context lifetime was not observed")
			}
		})
	}
}

func TestGoSourceContextTerminalFrameDoneCannotChangeInLastErr(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	original := &sourceTerminalTestContext{Context: base}
	private, err := captureGoAMD64FramePrivateContext(original)
	if err != nil {
		t.Fatal(err)
	}
	defer private.stop()
	original.errCalls, original.deadlineCalls, original.doneCalls = 0, 0, 0
	original.callback = func(method string, count int) {
		if method == "Err" && count == 2 {
			original.doneOverride, original.useDoneOverride = make(chan struct{}), true
		}
	}
	err = private.verify()
	if !original.useDoneOverride || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("last Err changed the original frame Done channel after sampling", err)
	}
}

func TestGoSourceContextTerminalPrivateBridgeOnlyTightensAndStops(t *testing.T) {
	for _, axis := range []string{"earlier", "later", "background"} {
		t.Run(axis, func(t *testing.T) {
			original, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			frozen, _ := original.Deadline()
			caller, stopCaller := context.Context(context.Background()), context.CancelFunc(func() {})
			want := frozen
			if axis == "earlier" {
				want = frozen.Add(-30 * time.Second)
				caller, stopCaller = context.WithDeadline(caller, want)
			} else if axis == "later" {
				caller, stopCaller = context.WithDeadline(caller, frozen.Add(time.Minute))
			}
			defer stopCaller()
			private, stop, err := sdkASMDataPrivateContext(caller, original, frozen)
			if err != nil || private == nil || stop == nil {
				t.Fatal("unchanged private bridge did not capture actual lifetimes", err)
			}
			got, bounded := private.Deadline()
			stop()
			if !bounded || !got.Equal(want) || !errors.Is(private.Err(), context.Canceled) || original.Err() != nil || caller.Err() != nil {
				t.Fatal("private bridge extended a deadline or cleanup changed caller lifetime")
			}
		})
	}
	for _, axis := range []string{"original", "caller"} {
		t.Run("signal/"+axis, func(t *testing.T) {
			original, cancelOriginal := context.WithTimeout(context.Background(), time.Minute)
			defer cancelOriginal()
			caller, cancelCaller := context.WithCancel(context.Background())
			defer cancelCaller()
			frozen, _ := original.Deadline()
			private, stop, err := sdkASMDataPrivateContext(caller, original, frozen)
			if err != nil {
				t.Fatal(err)
			}
			defer stop()
			if axis == "original" {
				cancelOriginal()
			} else {
				cancelCaller()
			}
			select {
			case <-private.Done():
				if !errors.Is(private.Err(), context.Canceled) {
					t.Fatal("captured Done did not cancel the private command context")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("private command context lost the captured cancellation signal")
			}
		})
	}
}

func TestGoSourceContextTerminalIdentityAndBoundedRoleGuards(t *testing.T) {
	base, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	frozen, _ := base.Deadline()
	original, replacement := &sourceTerminalTestContext{Context: base}, &sourceTerminalTestContext{Context: base}
	checks := map[string]func() error{
		"SDK-metadata": func() error {
			return (&GoX86SDKASMDataSource{context: replacement, originalContext: original, originalDeadline: frozen}).liveContext(base)
		},
		"SDK-readonly": func() error {
			return (&GoX86SDKReadonlyLiteralDataOwner{context: replacement, originalContext: original, originalDeadline: frozen}).liveContext(base)
		},
		"SDK-minimum": func() error {
			return (&GoX86SDKLiteralAlignment{context: replacement, originalContext: original, deadline: frozen}).liveContext(base)
		},
	}
	for name, check := range checks {
		t.Run(name, func(t *testing.T) {
			if err := check(); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("shared lifetime sampling replaced the original context identity guard", err)
			}
		})
	}
	if original.errCalls+replacement.errCalls+original.doneCalls+replacement.doneCalls != 0 {
		t.Fatal("foreign context identity was sampled before its role rejected it")
	}
	for name, invoke := range sourceTerminalTestRoutes() {
		if name == "ordinary-frame" {
			continue // Its unchanged unbounded role is independently tested below.
		}
		t.Run(name+"/unbounded", func(t *testing.T) {
			unbounded := &sourceTerminalTestContext{Context: context.Background()}
			if err := invoke(context.Background(), unbounded, frozen); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("SDK source acquired an unbounded original lifetime", err)
			}
		})
	}
	private, err := captureGoAMD64FramePrivateContext(context.Background())
	if err != nil {
		t.Fatal("ordinary frame lost its distinct unbounded role", err)
	}
	defer private.stop()
	if err := private.verify(); err != nil {
		t.Fatal("ordinary unbounded lifetime did not verify", err)
	}
}
