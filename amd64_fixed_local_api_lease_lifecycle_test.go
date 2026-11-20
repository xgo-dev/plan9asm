package plan9asm

import (
	"errors"
	"testing"
	"time"
)

func TestFixedLocalFreshCaptureNeverRevivesPreviousAPILease(t *testing.T) {
	pkg, request, file, options := fixedLocalFrameFixture(t, "PADDQ 16(SP),X0")
	var previous Options
	var previousSource *GoAMD64FrameSource
	for _, capture := range []string{"first", "second", "third"} {
		t.Run(capture, func(t *testing.T) {
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			source, err := CaptureGoAMD64FrameSource(ctx, pkg, request)
			if err != nil {
				t.Fatal("fresh independent original-Go capture", err)
			}
			defer func() {
				if err := source.Close(); err != nil {
					t.Error(err)
				}
			}()
			if source == previousSource {
				t.Fatal("a new API reused the closed previous observation")
			}
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if err != nil {
				t.Fatal("fresh observation lost the original complete source binding", err)
			}
			if ir, err := Translate(file, bound); err != nil || ir == "" {
				t.Fatal("fresh source cannot independently consume the same original payload", err)
			}
			if previousSource != nil {
				if ir, err := Translate(file, previous); !errors.Is(err, ErrProbeNeedsContext) || ir != "" {
					t.Fatal("new capture revived a previous API's closed/cancelled binding", err)
				}
			}
			previous, previousSource = bound, source
		})
	}
}

func TestFixedLocalFreshAPILeaseRetainsOriginalStageBudget(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, delay := range []time.Duration{0, 4 * time.Minute, 8 * time.Minute} {
		start := now.Add(delay)
		if got := runtimeOracleStageDeadline(start, time.Time{}, false); got != start.Add(5*time.Minute) {
			t.Fatal("API lease changed the original five-minute bound", delay, got)
		}
	}
	deadline := now.Add(4 * time.Minute)
	if got := runtimeOracleStageDeadline(now, deadline, true); got != deadline.Add(-3*time.Second) {
		t.Fatal("fresh API lease escaped the real test deadline/cleanup reserve", got)
	}
	if got := runtimeOracleStageDeadline(deadline, deadline, true); !got.Before(deadline) {
		t.Fatal("new API revived an exhausted test lifetime", got)
	}
}
