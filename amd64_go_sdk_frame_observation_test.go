package plan9asm

import (
	"context"
	"errors"
	"testing"
)

func TestSDKAMD64OriginalFrameObservationMissingLifetime(t *testing.T) {
	for _, observed := range []*GoAMD64SDKFrameObservation{nil, {}} {
		if err := observed.Verify(context.Background()); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("missing observation acquired a verification role", err)
		}
		if data, err := observed.Readback(context.Background()); !errors.Is(err, ErrProbeNeedsContext) || data != nil {
			t.Fatal("missing observation published a source/frame readback", err)
		}
	}
	if err := (*GoAMD64SDKFrameObservation)(nil).Close(); err != nil {
		t.Fatal("nil Close is not harmless", err)
	}
	if err := (&GoAMD64SDKFrameObservation{}).Close(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("uninitialized observer acquired cleanup ownership", err)
	}
}
