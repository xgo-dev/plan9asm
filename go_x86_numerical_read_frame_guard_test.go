//go:build go1.27

package plan9asm

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm/internal/gostaticstorage"
)

func numericalFrameCopies(t *testing.T, source *GoX86NumericalReadSource) ([]gostaticstorage.TextRecord, []gostaticstorage.TextRecord, []numericalSBReadFact) {
	t.Helper()
	copyValue := func(value, result any) {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, result); err != nil {
			t.Fatal(err)
		}
	}
	var observed, expected []gostaticstorage.TextRecord
	var reads []numericalSBReadFact
	copyValue(source.native.OriginalText, &observed)
	copyValue(source.native.OriginalText, &expected)
	copyValue(source.readFacts(), &reads)
	return observed, expected, reads
}

type numericalFrameReentryContext struct {
	context.Context
	mu         sync.Mutex
	once       sync.Once
	closeFrame func()
}

type numericalFrameObserverCancelContext struct {
	context.Context
	cancel context.CancelFunc
	once   sync.Once
	method string
	frame  *GoAMD64FrameSource
	called atomic.Bool
	locked atomic.Bool
}

func TestGoX86NumericalSBReadSourceCopyCannotBorrowGeneration(t *testing.T) {
	pkg, file, options, create := numericalConsumerFactory(t, "amd64")
	for _, operation := range []string{"Verify", "Bind", "Close"} {
		t.Run(operation, func(t *testing.T) {
			source, bound := create(t)
			ctx := bound.NumericalReads.context
			if err := source.Verify(ctx); err != nil {
				t.Fatal("original live source precondition", err)
			}
			copySource := new(GoX86NumericalReadSource)
			reflect.ValueOf(copySource).Elem().Set(reflect.ValueOf(source).Elem())
			var err error
			switch operation {
			case "Verify":
				err = copySource.Verify(ctx)
			case "Bind":
				var copied Options
				copied, err = copySource.BindNumericalReads(ctx, pkg, file, options)
				if copied.NumericalReads != nil {
					t.Error("copied source issued a new self-identifying numerical read token")
				}
			case "Close":
				err = copySource.Close()
			}
			if !errors.Is(err, ErrProbeNeedsContext) {
				t.Errorf("copied source borrowed the original generation for %s: %v", operation, err)
			}
			if err := source.Verify(ctx); err != nil {
				t.Error("rejecting a copied source revoked or removed the original owner's artifacts", err)
			}
		})
	}
}

func numericalFrameObserverRoute(owner string) bool {
	// The public owner may sample through a private lifetime helper. Follow
	// the complete route, including inlined frames, while retaining the exact
	// observer role: an unrelated or outer numerical callback cannot trigger it.
	var callers [32]uintptr
	count := runtime.Callers(2, callers[:])
	frames := runtime.CallersFrames(callers[:count])
	for {
		frame, more := frames.Next()
		if strings.HasSuffix(frame.Function, owner) {
			return true
		}
		if !more {
			return false
		}
	}
}

func (ctx *numericalFrameObserverCancelContext) observe(method string) {
	if method != ctx.method || !numericalFrameObserverRoute("(*GoAMD64FrameSource).verifyFrameOnly") {
		return
	}
	ctx.once.Do(func() {
		ctx.called.Store(true)
		if !ctx.frame.mu.TryLock() {
			ctx.locked.Store(true)
		} else {
			ctx.frame.mu.Unlock()
		}
		ctx.cancel()
	})
}

func (ctx *numericalFrameObserverCancelContext) Err() error {
	ctx.observe("Err")
	return ctx.Context.Err()
}

func (ctx *numericalFrameObserverCancelContext) Deadline() (time.Time, bool) {
	ctx.observe("Deadline")
	return ctx.Context.Deadline()
}

func (ctx *numericalFrameObserverCancelContext) Done() <-chan struct{} {
	ctx.observe("Done")
	return ctx.Context.Done()
}

func TestGoX86NumericalSBReadFrameProducerCopiedFrameCannotBorrowGeneration(t *testing.T) {
	ctx, pkg, request, _, bound, _, _ := numericalLocalFactory(t)
	request.NumericalReads = bound.NumericalReads
	frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if err != nil {
		t.Fatal(err)
	}
	defer frame.Close()
	copyFrame := new(GoAMD64FrameSource)
	// This copies the whole opaque public value while its mutex is unlocked;
	// neither serialization nor reconstruction of a certificate is involved.
	reflect.ValueOf(copyFrame).Elem().Set(reflect.ValueOf(frame).Elem())
	if err := copyFrame.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("a whole-value frame copy borrowed an independently owned generation", err)
	}
	if err := copyFrame.Close(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("a foreign frame generation could remove original owned artifacts", err)
	}
	if err := frame.Verify(ctx); err != nil {
		t.Fatal("rejecting a copied frame invalidated the original generation", err)
	}
}

func TestGoX86NumericalSBReadFrameProducerObserverCancellationCause(t *testing.T) {
	for _, method := range []string{"Err", "Deadline", "Done"} {
		t.Run(method, func(t *testing.T) {
			ctx, pkg, request, _, bound, _, _ := numericalLocalFactory(t)
			request.NumericalReads = bound.NumericalReads
			frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer frame.Close()
			inner, cancel := context.WithCancel(ctx)
			defer cancel()
			wrapped := &numericalFrameObserverCancelContext{Context: inner, cancel: cancel, method: method, frame: frame}
			if err := wrapped.Err(); err != nil {
				t.Fatal("ordinary context sample was cancelled", err)
			}
			wrapped.Deadline()
			wrapped.Done()
			if wrapped.called.Load() {
				t.Fatal("ordinary context samples reached an unrelated frame observer")
			}
			if err := frame.Verify(wrapped); !errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("joined observer cancellation was relabeled as a source exclusion", err)
			}
			if !wrapped.called.Load() || wrapped.locked.Load() {
				t.Fatal("actual inner observer callback was absent or sampled under the frame lock")
			}
			if !errors.Is(frame.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("fresh context revived the cancelled frame generation")
			}
		})
	}
}

func (ctx *numericalFrameReentryContext) Err() error {
	ctx.mu.Lock()
	callback := ctx.closeFrame
	ctx.mu.Unlock()
	if callback != nil && numericalFrameObserverRoute("(*GoX86NumericalReadSource).Verify") {
		ctx.once.Do(callback)
	}
	return ctx.Context.Err()
}

func TestGoX86NumericalSBReadFrameProducerReentryAndContextCauses(t *testing.T) {
	t.Run("reentry", func(t *testing.T) {
		var wrapped *numericalFrameReentryContext
		ctx, pkg, request, _, bound, _, _ := numericalLocalFactoryWithContext(t, func(parent context.Context) context.Context {
			wrapped = &numericalFrameReentryContext{Context: parent}
			return wrapped
		})
		request.NumericalReads = bound.NumericalReads
		frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
		if err != nil {
			t.Fatal(err)
		}
		defer frame.Close()
		callbackReached := make(chan struct{}, 1)
		wrapped.mu.Lock()
		wrapped.closeFrame = func() {
			callbackReached <- struct{}{}
			// Check the lock at the callback, not the duration of the full
			// source/object replay. Race instrumentation can make that replay
			// exceed ten seconds even after this reentrant Close succeeded.
			if !frame.mu.TryLock() {
				t.Error("Frame lock survived an external numerical verification callback")
				return
			}
			frame.mu.Unlock()
			if err := frame.Close(); err != nil {
				t.Error(err)
			}
		}
		wrapped.mu.Unlock()
		if err := wrapped.Err(); err != nil || len(callbackReached) != 0 {
			t.Fatal("ordinary context observation invoked the reentry callback", err)
		}
		err = frame.Verify(ctx)
		if len(callbackReached) != 1 {
			t.Fatal("reentry fixture never reached the numerical owner callback", err)
		}
		if !errors.Is(err, ErrProbeNeedsContext) || !errors.Is(frame.Verify(context.Background()), ErrProbeNeedsContext) {
			t.Fatal("reentrant owner guard published or revived the frame", err)
		}
	})
	for _, cause := range []string{"cancelled", "deadline"} {
		t.Run(cause, func(t *testing.T) {
			ctx, pkg, request, _, bound, _, _ := numericalLocalFactory(t)
			request.NumericalReads = bound.NumericalReads
			frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer frame.Close()
			invalid, stop := context.WithCancel(ctx)
			want := context.Canceled
			if cause == "deadline" {
				stop()
				invalid, stop = context.WithDeadline(ctx, time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			} else {
				stop()
			}
			defer stop()
			if err := frame.Verify(invalid); !errors.Is(err, want) || errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("public joined frame Verify lost actual context cause", err)
			}
			if !errors.Is(frame.Verify(ctx), ErrProbeNeedsContext) {
				t.Fatal("fresh context revived a failed numerical frame generation")
			}
		})
	}
}

func TestGoX86NumericalSBReadFrameProducerCompleteBijectionGuards(t *testing.T) {
	_, pkg, _, file, _, numerical, _ := numericalLocalFactory(t)
	observed, expected, reads := numericalFrameCopies(t, numerical)
	if err := goAMD64FrameNumericalObjectJoin(observed, expected, reads); err != nil {
		t.Fatal("actual independent original-object guard precondition", err)
	}
	for _, test := range []struct {
		name   string
		mutate func([]gostaticstorage.TextRecord, []gostaticstorage.TextRecord, *[]numericalSBReadFact)
	}{
		{"whole code", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Code[0] ^= 1 }},
		{"whole source PC", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Positions[0].Line++ }},
		{"TEXT ABI", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].ABI = 1 }},
		{"field PC", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Relocations[0].Offset++ }},
		{"field width", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Relocations[0].Size = 8 }},
		{"relocation type", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Relocations[0].Type = 1 }},
		{"target symbol", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) {
			o[0].Relocations[0].Target.Name += "foreign"
		}},
		{"target ABI", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Relocations[0].Target.ABI = 1 }},
		{"addend", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { o[0].Relocations[0].Add++ }},
		{"missing read", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { *r = (*r)[1:] }},
		{"duplicate read", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { *r = append(*r, (*r)[0]) }},
		{"reordered reads", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { (*r)[0], (*r)[1] = (*r)[1], (*r)[0] }},
		{"read instruction PC", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { (*r)[0].PC++ }},
		{"read code", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { (*r)[0].Code[0] ^= 1 }},
		{"read owner", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) {
			(*r)[0].Variable.NativeName += "foreign"
		}},
		{"read offset", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { (*r)[0].Offset++ }},
		{"read width", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) { (*r)[0].Width++ }},
		{"instruction order", func(o, e []gostaticstorage.TextRecord, r *[]numericalSBReadFact) {
			(*r)[1].Instruction = (*r)[0].Instruction
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			o, e, r := numericalFrameCopies(t, numerical)
			test.mutate(o, e, &r)
			if !errors.Is(goAMD64FrameNumericalObjectJoin(o, e, r), ErrProbeNeedsContext) {
				t.Fatal("changed complete original relocation/read bijection was accepted")
			}
		})
	}
	listing := string(numerical.native.OriginalListing)
	relocation := goAMD64FrameNumericalRelocationLine(observed[0].Relocations[0])
	for _, mutation := range []string{"missing", "duplicate", "foreign", "reordered"} {
		t.Run("listing "+mutation, func(t *testing.T) {
			changed := listing
			switch mutation {
			case "missing":
				changed = strings.Replace(changed, relocation, "", 1)
			case "duplicate":
				changed = strings.Replace(changed, relocation, relocation+"\n\t"+relocation, 1)
			case "foreign":
				changed = strings.Replace(changed, relocation, relocation+"foreign", 1)
			case "reordered":
				second := goAMD64FrameNumericalRelocationLine(observed[0].Relocations[1])
				changed = strings.Replace(changed, relocation, "RELOCATION_PLACEHOLDER", 1)
				changed = strings.Replace(changed, second, relocation, 1)
				changed = strings.Replace(changed, "RELOCATION_PLACEHOLDER", second, 1)
			}
			origins := make(map[string]int)
			for _, source := range numerical.cpp.Sources {
				data, exists := numerical.native.Sources[source.File]
				if !exists {
					t.Fatal("actual source bytes absent from original native proof", source.File)
				}
				origins[source.File] = len(strings.Split(string(data), "\n"))
			}
			if _, err := goAMD64FrameListingWithNumericalObject([]byte(changed), file, pkg, origins, observed); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("changed complete actual listing relocation was accepted", err)
			}
		})
	}
}

func TestGoX86NumericalSBReadFrameProducerCopiedTokenIsNotFactoryIdentity(t *testing.T) {
	ctx, pkg, request, _, bound, _, _ := numericalLocalFactory(t)
	copyBinding := *bound.NumericalReads
	request.NumericalReads = &copyBinding
	frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
	if frame != nil {
		frame.Close()
	}
	if frame != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("copied opaque numerical token replaced the exact live factory identity", err)
	}
}

func numericalFrameDuringVerify(t *testing.T, frame *GoAMD64FrameSource, ctx context.Context, invalidate func()) error {
	t.Helper()
	finished := make(chan error, 1)
	go func() { finished <- frame.Verify(ctx) }()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case err := <-finished:
			t.Fatal("verification ended before the real observer round", err)
		case <-deadline.C:
			t.Fatal("no real locked independent frame observer round")
		default:
		}
		if !frame.mu.TryLock() {
			// The immutable metadata snapshot is brief. Require the real
			// observer lock to remain held across a scheduling interval.
			time.Sleep(5 * time.Millisecond)
			if !frame.mu.TryLock() {
				invalidate()
				select {
				case err := <-finished:
					return err
				case <-time.After(10 * time.Second):
					t.Fatal("invalidated independent observer did not terminate")
				}
			}
			frame.mu.Unlock()
		} else {
			frame.mu.Unlock()
		}
		time.Sleep(time.Millisecond)
	}
}

func TestGoX86NumericalSBReadFrameProducerConcurrentRevocation(t *testing.T) {
	for _, role := range []string{"owner", "source", "frame", "capture context"} {
		t.Run(role, func(t *testing.T) {
			ctx, pkg, request, _, bound, numerical, cancel := numericalLocalFactory(t)
			request.NumericalReads = bound.NumericalReads
			frame, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal(err)
			}
			defer frame.Close()
			err = numericalFrameDuringVerify(t, frame, ctx, func() {
				switch role {
				case "owner":
					numerical.originalOwners[0].Close()
				case "source":
					if err := numerical.Close(); err != nil {
						t.Error(err)
					}
				case "frame":
					if err := frame.Close(); err != nil {
						t.Error(err)
					}
				case "capture context":
					cancel()
				}
			})
			if role == "capture context" && (!errors.Is(err, context.Canceled) || errors.Is(err, ErrProbeNeedsContext)) {
				t.Fatal("actual capture cancellation was classified as source exclusion", err)
			}
			if err == nil || !errors.Is(frame.Verify(context.Background()), ErrProbeNeedsContext) {
				t.Fatal("concurrent source/owner/frame failure revived or published an observation", err)
			}
		})
	}
}
