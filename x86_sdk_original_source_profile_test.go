package plan9asm

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestX86SDKOriginalSourceProfileDoesNotBorrowNativeFrame(t *testing.T) {
	for _, target := range []string{"linux/386", "windows/386", "linux/amd64", "darwin/amd64", "windows/amd64"} {
		t.Run(target, func(t *testing.T) {
			goos, arch, _ := strings.Cut(target, "/")
			request := GoX86SDKASMDataCaptureRequest{Target: target, Environment: []string{
				"GOOS=" + goos, "GOARCH=" + arch, "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off",
				"CGO_ENABLED=0", "GOENV=off", "GOEXPERIMENT=", "GOPACKAGESDRIVER=off",
			}}
			before := append([]string(nil), request.Environment...)
			actual, err := sdkX86OriginalSourceEnvironment(request)
			if err != nil || actual["GOARCH"] != arch || !reflect.DeepEqual(before, request.Environment) {
				t.Fatal("source observation changed the actual producer profile", err)
			}
			_, err = sdkAMD64FrameEnvironment(request)
			if arch == "386" && !errors.Is(err, ErrProbeNeedsContext) || arch == "amd64" && err != nil {
				t.Fatal("source-only role changed the separate AMD64 frame target boundary", err)
			}
			for _, change := range []string{"GOFLAGS=-overlay=other", "GOARCH=arm64", "GOTOOLCHAIN=auto", "GOENV=relative", "GOEXPERIMENT=changed", "GOPACKAGESDRIVER=custom"} {
				changed := request
				changed.Environment = append([]string(nil), request.Environment...)
				key, _, _ := strings.Cut(change, "=")
				for index, value := range changed.Environment {
					if strings.HasPrefix(value, key+"=") {
						changed.Environment[index] = change
					}
				}
				if _, err := sdkX86OriginalSourceEnvironment(changed); !errors.Is(err, ErrProbeNeedsContext) {
					t.Fatal("different compiler/profile acquired the original source role", change, err)
				}
			}
		})
	}
}
