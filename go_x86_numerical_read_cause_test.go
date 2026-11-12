//go:build go1.27

package plan9asm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestGoX86NumericalSBReadCaptureCancellationCause(t *testing.T) {
	for _, sdkCPU := range []bool{false, true} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(cause.Error()+map[bool]string{false: "/ordinary", true: "/SDK"}[sdkCPU], func(t *testing.T) {
				var ctx context.Context
				var cancel context.CancelFunc
				if cause == context.Canceled {
					ctx, cancel = context.WithCancel(context.Background())
					cancel()
				} else {
					ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
					defer cancel()
				}
				owner, err := CaptureGoNumericalStorageOwner(ctx, GoNumericalStorageCaptureRequest{SDKCPU: sdkCPU})
				if owner != nil || !errors.Is(err, cause) || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatalf("cancelled infrastructure lost its cause or became source Context: owner=%v error=%v", owner, err)
				}
			})
		}
	}
}

func TestGoX86NumericalSBReadSourceCancellationCauseAndPermanentRevocation(t *testing.T) {
	_, _, _, create := numericalConsumerFactory(t, "amd64")
	for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(cause.Error(), func(t *testing.T) {
			source, options := create(t)
			var invalid context.Context
			var cancel context.CancelFunc
			if cause == context.Canceled {
				invalid, cancel = context.WithCancel(options.NumericalReads.context)
				cancel()
			} else {
				invalid, cancel = context.WithDeadline(options.NumericalReads.context, time.Now().Add(-time.Second))
				defer cancel()
			}
			t.Run("capture", func(t *testing.T) {
				result, err := CaptureGoX86NumericalReadSource(invalid, source.request)
				if result != nil || !errors.Is(err, cause) || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("cancelled source capture was classified as a proof exclusion", cause, err)
				}
			})
			t.Run("verify", func(t *testing.T) {
				if err := source.Verify(invalid); !errors.Is(err, cause) || errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("cancelled verification lost its infrastructure cause", cause, err)
				}
				if !errors.Is(source.Verify(options.NumericalReads.context), ErrProbeNeedsContext) {
					t.Fatal("fresh context revived a source after failed verification")
				}
			})
		})
	}
}
