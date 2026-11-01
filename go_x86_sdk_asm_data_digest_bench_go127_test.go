//go:build go1.27

package plan9asm

import (
	"testing"
	"time"
)

// Measure only complete encoder calls on one unchanged, real SDK capture per
// package. Capture, live Verify and teardown are outside all timed intervals.
// A is the frozen buffered legacy encoder; B is the current production encoder.
// The ABBA order and shared state avoid recapture paths/timestamps as confounders.
// This is not a full Verify/translation benchmark or a cached-source fast path.
func BenchmarkGoX86SDKASMDataDigestActualEncoder(b *testing.B) {
	for _, pkg := range []string{"internal/cpu", "hash/crc32", "internal/runtime/maps"} {
		b.Run(pkg, func(b *testing.B) {
			ctx, request := sdkASMDataRequest(b, "amd64", pkg)
			source, err := CaptureGoX86SDKASMDataSource(ctx, request)
			if err != nil {
				b.Fatal("real SDK capture failed before benchmark", err)
			}
			b.Cleanup(func() {
				if err := source.Close(); err != nil {
					b.Error(err)
				}
			})
			if err := source.Verify(ctx); err != nil {
				b.Fatal("real SDK preflight verification failed", err)
			}
			state := sdkASMDataDigestBenchmarkState(source)
			want, err := source.digest()
			if err != nil {
				b.Fatal(err)
			}
			for _, encoder := range []func(any) ([32]byte, error){sdkASMDataDigestLegacy, digestSDKASMDataState} {
				if got, err := encoder(state); err != nil || got != want {
					b.Fatal("benchmark state differs from complete live source digest", err)
				}
			}
			b.Logf("package=%s captured-state-sha256=%x", pkg, want)
			for _, sample := range []struct {
				name   string
				encode func(any) ([32]byte, error)
			}{
				{"A1-legacy", sdkASMDataDigestLegacy},
				{"B1-current", digestSDKASMDataState},
				{"B2-current", digestSDKASMDataState},
				{"A2-legacy", sdkASMDataDigestLegacy},
			} {
				b.Run(sample.name, func(b *testing.B) {
					b.ReportAllocs()
					b.ResetTimer()
					for iteration := 0; iteration < b.N; iteration++ {
						got, err := sample.encode(state)
						if err != nil || got != want {
							b.Fatal("complete current state hash changed", err)
						}
					}
				})
			}
			if err := source.Verify(ctx); err != nil {
				b.Fatal("real SDK postflight verification failed", err)
			}
		})
	}
}

// Preserve the exact anonymous root type/field order of source.digest. The
// preflight compares its hash with source.digest, so future schema additions
// fail instead of quietly shrinking the measured state. Only the wrapper is
// copied; all current map/slice contents remain the actual capture's contents.
func sdkASMDataDigestBenchmarkState(source *GoX86SDKASMDataSource) any {
	return struct {
		Request           GoX86SDKASMDataCaptureRequest
		Guard             GoAMD64FrameCaptureRequest
		Selection         goAMD64FrameSelection
		Env               map[string]string
		Imports           map[string]goAMD64FrameSelection
		Inputs            map[string][32]byte
		Entries           []string
		Misses            map[string]bool
		Observation       sdkASMDataLiveObservation
		OriginalDeadline  time.Time
		OriginalProfile   bool
		CaptureRole       sdkASMDataCaptureRole
		OriginalConfig    string
		FrameListingBytes int
	}{source.request, source.guard.request, source.guard.selection, source.guard.env, source.guard.imports,
		source.guard.inputs, source.guard.entries, source.misses, source.observation, source.originalDeadline,
		source.originalProfile, source.captureRole, source.originalConfig, source.frameListingBytes}
}
