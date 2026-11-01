package plan9asm

import (
	"context"
	"errors"
	"time"
)

// Caller contexts are callbacks, not safe command contexts under an observer
// lock. Capture only their actual lifetime outside locks; commands consume a
// standard private context with the same (never extended) deadline/Done signal.
// The original context remains the published binding's lifetime authority.
type goAMD64FramePrivateContext struct {
	context.Context
	original context.Context
	deadline time.Time
	bounded  bool
	done     <-chan struct{}
	cancel   context.CancelFunc
	stop     func()
}

func captureGoAMD64FramePrivateContext(original context.Context) (*goAMD64FramePrivateContext, error) {
	if original == nil {
		return nil, goAMD64FrameContext("missing caller context")
	}
	if err := original.Err(); err != nil {
		return nil, err
	}
	deadline, bounded := original.Deadline()
	done := original.Done()
	if _, err := sampleGoSourceContext(context.Background(), original,
		goSourceContextLifetime{deadline: deadline, bounded: bounded, done: done, checkDone: true}, false,
		goAMD64FrameContext("caller context lifetime changed during capture")); err != nil {
		return nil, err
	}
	var private context.Context
	var cancel context.CancelFunc
	if bounded {
		private, cancel = context.WithDeadline(context.Background(), deadline)
	} else {
		private, cancel = context.WithCancel(context.Background())
	}
	finished, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-done:
			cancel()
		case <-private.Done():
		case <-finished:
		}
	}()
	return &goAMD64FramePrivateContext{Context: private, original: original,
		deadline: deadline, bounded: bounded, done: done, cancel: cancel,
		stop: func() {
			close(finished)
			cancel()
			<-stopped
		}}, nil
}

// Always called outside observer locks. Retain actual cancellation causes and
// reject a caller that changes its captured lifetime while work is in flight.
func (ctx *goAMD64FramePrivateContext) verify() error {
	_, err := sampleGoSourceContext(ctx.Context, ctx.original,
		goSourceContextLifetime{deadline: ctx.deadline, bounded: ctx.bounded, done: ctx.done, checkDone: true}, false,
		goAMD64FrameContext("caller context lifetime changed during observation"))
	if goSourceContextDone(ctx.done) {
		ctx.cancel()
	}
	// Context is the privately constructed standard command context, not the
	// original caller implementation. No user callback follows the checkpoint.
	return errors.Join(err, ctx.Context.Err())
}
