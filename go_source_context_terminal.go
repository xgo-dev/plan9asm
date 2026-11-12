package plan9asm

import (
	"context"
	"errors"
	"time"
)

// This is only an existing source role's frozen lifetime, not a source token.
// Ordinary frames additionally bind the original Done channel and may have no
// deadline; SDK roles retain their independently required bounded deadline.
type goSourceContextLifetime struct {
	deadline  time.Time
	bounded   bool
	done      <-chan struct{}
	checkDone bool
}

type goSourceContextSample struct {
	callerDeadline           time.Time
	callerBounded            bool
	callerDone, originalDone <-chan struct{}
}

// Context methods are arbitrary caller callbacks. All Err/Done callbacks and
// any caller deadline sample precede the terminal original Deadline. A
// potentially successful return invokes no user callback after that sample.
// Captured channels can still reveal cancellation caused by Deadline itself.
func sampleGoSourceContext(caller, original context.Context, lifetime goSourceContextLifetime, callerDeadline bool, changed error) (sample goSourceContextSample, result error) {
	if caller == nil || original == nil {
		return sample, changed
	}
	if err := errors.Join(caller.Err(), original.Err()); err != nil {
		return sample, err
	}
	if callerDeadline {
		sample.callerDeadline, sample.callerBounded = caller.Deadline()
	}
	if err := errors.Join(caller.Err(), original.Err()); err != nil {
		return sample, err
	}
	sample.callerDone, sample.originalDone = caller.Done(), original.Done()
	deadline, bounded := original.Deadline()
	if bounded != lifetime.bounded || bounded && !deadline.Equal(lifetime.deadline) ||
		lifetime.checkDone && sample.originalDone != lifetime.done {
		result = changed
	}
	if goSourceContextDone(sample.callerDone) || goSourceContextDone(sample.originalDone) {
		// This branch cannot succeed. Err is read only to preserve the actual
		// cancellation cause; an inconsistent closed-Done/Err-nil context
		// still fails, without retrying or taking another lifetime snapshot.
		if err := errors.Join(caller.Err(), original.Err()); err != nil {
			return sample, errors.Join(result, err)
		}
		return sample, changed
	}
	return sample, result
}

func goSourceContextDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}
