//go:build go1.27

package plan9asm

import "testing"

func TestSDKAMD64PrimaryInventoryActualCompleteMD5(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("complete unchanged SDK compiler-selected source/native frame", err)
	}
	defer observed.Close()
	source := observed.source
	if source.guard.selection.Module != nil || source.guard.selection.ImportPath != request.PackagePath ||
		len(source.observation.Frames) != 1 || len(source.observation.Frames[0].Records) != 1 ||
		!source.observation.Frames[0].Records[0].NoSplit || source.observation.Frames[0].Records[0].Locals != 16 ||
		source.observation.Frames[0].Records[0].Args != 32 {
		t.Fatal("SDK-primary exact selected source or native frame inventory changed")
	}
	if err := observed.Verify(ctx); err != nil {
		t.Fatal("live complete SDK source with independent child identities", err)
	}
}
