package plan9asm

import (
	"context"
	"time"
)

// Context implementations are caller-controlled callbacks. Sample their
// methods before taking operation locks, then bridge only the captured Done
// channels/deadlines to a standard private command context. The caller's actual
// cancellation cause is still checked outside locks before and after the work.
func sdkASMDataPrivateContext(caller, original context.Context, frozenDeadline time.Time) (context.Context, func(), error) {
	if caller == nil || original == nil {
		return nil, nil, sdkASMDataContext("missing verification/capture context")
	}
	sample, err := sampleGoSourceContext(caller, original,
		goSourceContextLifetime{deadline: frozenDeadline, bounded: true}, true,
		sdkASMDataContext("original capture context deadline changed or canceled without a cause"))
	if err != nil {
		return nil, nil, err
	}
	deadline := frozenDeadline
	if sample.callerBounded && sample.callerDeadline.Before(deadline) {
		deadline = sample.callerDeadline
	}
	private, cancel := context.WithDeadline(context.Background(), deadline)
	finished, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		select {
		case <-sample.callerDone:
			cancel()
		case <-sample.originalDone:
			cancel()
		case <-private.Done():
		case <-finished:
		}
	}()
	return private, func() {
		close(finished)
		cancel()
		<-stopped
	}, nil
}
