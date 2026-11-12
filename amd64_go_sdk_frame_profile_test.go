package plan9asm

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSDKAMD64OriginalFrameProfilePreservesDefaults(t *testing.T) {
	request := GoX86SDKASMDataCaptureRequest{Target: "linux/amd64", Environment: []string{
		"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=1", "GOENV=" + filepath.Join(t.TempDir(), "env"),
		"GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off",
	}}
	original := append([]string(nil), request.Environment...)
	actual, err := sdkAMD64FrameEnvironment(request)
	if err != nil || actual["CGO_ENABLED"] != "1" || actual["GOENV"] == "off" ||
		!reflect.DeepEqual(request.Environment, original) {
		t.Fatal("SDK-primary profile replaced the original default/config", err)
	}
	if _, present := actual["GOPROXY"]; present {
		t.Fatal("SDK-primary profile invented a proxy override")
	}
	if _, present := actual["GOAMD64"]; present {
		t.Fatal("SDK-primary profile invented a CPU default override")
	}
	if _, err := sdkASMDataEnvironment(request); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("SDK-primary request weakened the existing public DATA profile", err)
	}
}

func TestSDKAMD64OriginalFrameConfigExactByteBoundary(t *testing.T) {
	for _, size := range []int{sdkAMD64FrameConfigBytes, sdkAMD64FrameConfigBytes + 1} {
		path := filepath.Join(t.TempDir(), "env")
		if err := os.WriteFile(path, []byte(strings.Repeat("#", size)), 0600); err != nil {
			t.Fatal(err)
		}
		path, err := sourcepath.Resolve(path)
		if err != nil {
			t.Fatal(err)
		}
		source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{})}
		err = source.captureSDKFrameConfig(path)
		if size == sdkAMD64FrameConfigBytes {
			if err != nil || len(source.guard.inputs) != 1 {
				t.Fatal("exact original config bound was rejected", err)
			}
		} else if !errors.Is(err, ErrProbeNeedsContext) || len(source.guard.inputs) != 0 || source.originalConfigID != nil {
			t.Fatal("oversized original config was retained", err)
		}
	}
}

func TestSDKAMD64OriginalFrameConfigGuardEagerIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "env")
	data := []byte("GOPROXY=off\n")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	path, err := sourcepath.Resolve(path)
	if err != nil {
		t.Fatal(err)
	}
	source := &GoX86SDKASMDataSource{guard: newGoOriginalInputGuard(GoAMD64FrameCaptureRequest{})}
	if err := source.captureSDKFrameConfig(path); err != nil {
		t.Fatal(err)
	}
	if err := source.verifyDirectories(); err != nil {
		t.Fatal("unchanged eager config identity", err)
	}
	// Capture retained an open-handle ID. Byte equality cannot substitute for
	// that identity when the next verification observes a new file at the path.
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.verifyDirectories(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("equal-byte replacement acquired retained original config identity", err)
	}
}

func TestSDKAMD64OriginalFrameProfileRejectsUnboundRoles(t *testing.T) {
	for _, bad := range []string{"GOENV=", "GOENV=relative", "CGO_ENABLED=", "CGO_ENABLED=2", "GOFLAGS=-overlay=foreign.json",
		"GOTOOLCHAIN=auto", "GOWORK=workspace", "GOEXPERIMENT=foreign", "GOPACKAGESDRIVER=foreign"} {
		request := GoX86SDKASMDataCaptureRequest{Target: "linux/amd64", Environment: []string{
			"GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0", "GOENV=off", "GOFLAGS=", "GOTOOLCHAIN=local", "GOWORK=off",
		}}
		key, _, _ := strings.Cut(bad, "=")
		var env []string
		for _, pair := range request.Environment {
			if !strings.HasPrefix(pair, key+"=") {
				env = append(env, pair)
			}
		}
		request.Environment = append(env, bad)
		if _, err := sdkAMD64FrameEnvironment(request); !errors.Is(err, ErrProbeNeedsContext) {
			t.Fatal("foreign or duplicate profile acquired SDK-primary source", bad, err)
		}
	}
}
