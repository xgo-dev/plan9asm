//go:build go1.27

package plan9asm

import (
	"errors"
	"testing"
	"time"
)

func TestGoX86SDKNumericalReadFreshGraphVerification(t *testing.T) {
	ctx, request, metadata, owner := numericalSDKAssemblyFixture(t)
	source, err := CaptureGoX86SDKNumericalReadSource(ctx, request)
	if err != nil {
		t.Fatal("actual complete SDK numerical source precondition", err)
	}
	t.Cleanup(func() { closeNumericalConsumerSource(t, source) })
	for index := 0; index < 2; index++ {
		begin := time.Now().UnixNano()
		if err := source.Verify(ctx); err != nil {
			t.Fatal("fresh complete SDK verification", err)
		}
		t.Logf("SDK_VERIFY_WINDOW index=%d begin=%d end=%d", index, begin, time.Now().UnixNano())
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("closed SDK source revived", err)
	}
	if err := metadata.Verify(ctx); err != nil {
		t.Fatal("numerical Close closed independent assembly source", err)
	}
	if err := owner.Verify(ctx); err != nil {
		t.Fatal("numerical Close closed independent numerical storage", err)
	}
}
