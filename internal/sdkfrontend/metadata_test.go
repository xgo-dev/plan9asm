package sdkfrontend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xgo-dev/plan9asm"
)

func TestSharedSDKMetadataCanceledCaptureHasNoOwner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	file, source, err := CaptureMetadata(ctx, CaptureRequest{})
	if file != nil || source != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled input created a metadata owner", err)
	}
	file, source, err = CaptureMetadata(nil, CaptureRequest{})
	if file != nil || source != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("missing context created a metadata owner", err)
	}
}

func TestSharedSDKMetadataInvalidOriginHasNoOwner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	directory, outside := t.TempDir(), t.TempDir()
	assembly := filepath.Join(outside, "outside.s")
	if err := os.WriteFile(assembly, []byte("TEXT example<>(SB),4,$0-0\nRET\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, source, err := CaptureMetadata(ctx, CaptureRequest{Directory: directory, AssemblyFile: assembly})
	if file != nil || source != nil || !errors.Is(err, plan9asm.ErrProbeNeedsContext) {
		t.Fatal("out-of-package origin created a metadata owner", err)
	}
}
