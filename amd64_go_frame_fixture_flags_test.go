package plan9asm

import (
	"errors"
	"os"
	"testing"
)

func TestGoAMD64FrameFixtureSeparatesHarnessBuildTags(t *testing.T) {
	// The Windows LLVM harness needs this tag; the independent, pure-Go
	// source fixture does not import LLVM and must have its own build role.
	t.Setenv("GOFLAGS", "-tags=byollvm")
	for _, target := range []string{"linux/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			pkg, request := goAMD64FrameSourceFixture(t)
			request.Target = target
			source := requireGoAMD64FrameCapture(t, pkg, request)
			ctx, cancel := runtimeOracleStageContext(t)
			defer cancel()
			if err := source.Verify(ctx); err != nil {
				t.Fatal(err)
			}
			if os.Getenv("GOFLAGS") != "-tags=byollvm" {
				t.Fatal("fixture changed its parent harness environment")
			}
			// An explicit caller request is still nonordinary. This fixture
			// separation cannot relax production profile/source validation.
			request.Environment = append(request.Environment, "GOFLAGS=-tags=foreign")
			if changed, err := CaptureGoAMD64FrameSource(ctx, pkg, request); changed != nil || !errors.Is(err, ErrProbeNeedsContext) {
				t.Fatal("explicit foreign source profile was accepted", err)
			}
		})
	}
}
