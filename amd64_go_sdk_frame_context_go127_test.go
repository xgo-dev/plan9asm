//go:build go1.27

package plan9asm

import (
	"errors"
	"strings"
	"testing"
)

func TestGoAMD64SDKFrameBindContextCallbacksMayClose(t *testing.T) {
	for _, method := range []string{"Err", "Deadline", "Done"} {
		t.Run(method, func(t *testing.T) {
			original, request := sdkASMDataRequest(t, "amd64", "crypto/md5")
			observed, err := CaptureGoAMD64SDKFrameObservation(original, request)
			if err != nil {
				t.Fatal(err)
			}
			defer observed.Close()
			pkg := sdkAMD64FrameActualPackage(t, observed.source)
			source, err := CaptureGoAMD64SDKFrameSource(original, pkg, GoAMD64FrameCaptureRequest{
				GoBinary: request.GoBinary, Directory: request.Directory, AssemblyFile: "md5block_amd64.s",
				Target: request.Target, Environment: request.Environment,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer source.Close()
			file, err := Parse(ArchAMD64, observed.source.observation.CPP[0].Output)
			if err != nil {
				t.Fatal(err)
			}
			ctx := goAMD64FrameCloseCallback(t, original, source, method)
			options := Options{Goarch: "amd64", TargetTriple: "x86_64-unknown-linux-gnu",
				Sigs: map[string]FuncSig{request.PackagePath + ".block": source.functions[request.PackagePath+".block"].signature},
				ResolveSym: func(symbol string) string {
					// The initial Verify has completed. The next context sample
					// in the binder must still occur outside the observer lock.
					ctx.armed.Store(true)
					return request.PackagePath + "." + strings.TrimPrefix(symbol, "·")
				}}
			bound, err := source.BindFixedLocal(ctx, pkg, file, options)
			if ctx.locked.Load() || !ctx.called.Load() {
				t.Fatalf("SDK Bind caller %s callback ran under frame lock (Close would deadlock) or was never sampled", method)
			}
			if !errors.Is(err, ErrProbeNeedsContext) || len(bound.Sigs) != 0 {
				t.Fatal("callback-closed SDK source published a local binding", err)
			}
			if err := source.Verify(original); !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("SDK Bind revived its callback-closed source", err)
			}
		})
	}
}
