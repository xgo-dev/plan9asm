//go:build go1.27

package plan9asm

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestSDKAMD64OriginalFrameProfileActualCompleteSource(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "vendor/golang.org/x/crypto/chacha20poly1305")
	config := filepath.Join(t.TempDir(), "go-env")
	// This is a separate config producer input, never a replacement SDK source.
	if err := os.WriteFile(config, []byte("GOPROXY=https://original-config.invalid,direct\n"), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := sourcepath.Resolve(config)
	if err != nil {
		t.Fatal(err)
	}
	var env []string
	for _, pair := range request.Environment {
		key, _, _ := strings.Cut(pair, "=")
		if key != "GOENV" && key != "GOPROXY" && key != "CGO_ENABLED" && key != "GOAMD64" && key != "GOEXPERIMENT" {
			env = append(env, pair)
		}
	}
	env = append(env, "GOENV="+config)
	raw, err := goasmcmd.Run(ctx, request.Directory, env, request.GoBinary, "env", "-json", "CGO_ENABLED")
	var defaults map[string]string
	if err != nil || json.Unmarshal(raw, &defaults) != nil || defaults["CGO_ENABLED"] != "0" && defaults["CGO_ENABLED"] != "1" {
		t.Fatal("actual target compiler cgo default", err)
	}
	request.Environment = append(env, "CGO_ENABLED="+defaults["CGO_ENABLED"])
	original := append([]string(nil), request.Environment...)
	public, err := CaptureGoX86SDKASMDataSource(ctx, request)
	if public != nil || !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("new role leaked into public DATA source", err)
	}
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("actual unchanged SDK source/profile/header/object observation", err)
	}
	defer observed.Close()
	source := observed.source
	if source.guard.env["GOENV"] != config || source.guard.env["CGO_ENABLED"] != defaults["CGO_ENABLED"] ||
		source.guard.env["GOPROXY"] != "https://original-config.invalid,direct" ||
		strings.Join(source.request.Environment, "\x00") != strings.Join(original, "\x00") ||
		len(source.observation.Objects.Sources) != 1 || len(source.observation.Objects.Sources[0].Original.Texts) != 3 {
		t.Fatal("SDK-primary source/default profile or complete three TEXT inventory changed")
	}
	frames := source.observation.Frames
	if len(frames) != 1 || len(frames[0].Records) != 3 || frames[0].Records[0].ArgsKnown ||
		frames[0].Records[0].Args != -0x80000000 || !frames[0].Records[0].Static || !frames[0].Records[0].NoSplit ||
		frames[0].Records[1].NoSplit || frames[0].Records[1].Args != 97 || frames[0].Records[1].Locals != 296 ||
		frames[0].Records[2].NoSplit || frames[0].Records[2].Args != 96 || frames[0].Records[2].Locals != 296 {
		t.Fatal("complete original private helper/stack-split native metadata was omitted or relabeled", frames)
	}
	t.Logf("native listing bytes %d/%d; actual target CGO default %s; complete 3 TEXT frames %+v",
		source.frameListingBytes, sdkAMD64FrameListingBytes, defaults["CGO_ENABLED"], frames[0].Records)
	copy := *observed
	if err := copy.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("copied SDK-primary observation acquired original lifetime", err)
	}
	if data, err := copy.Readback(ctx); !errors.Is(err, ErrProbeNeedsContext) || data != nil {
		t.Fatal("copied SDK-primary observation published original source/frame readback", err)
	}
	if err := copy.Close(); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("copied SDK-primary observation removed original artifacts", err)
	}
	if err := source.Verify(ctx); err != nil {
		t.Fatal("live original config/profile", err)
	}
	before, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, bytes.ReplaceAll(before, []byte("original-config"), []byte("replaced-config")), 0600); err != nil {
		t.Fatal(err)
	}
	if err := source.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("changed original config retained SDK-primary source", err)
	}
	if _, err := source.Readback(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("failed config verification did not revoke SDK-primary source", err)
	}
}

func TestSDKAMD64OriginalFrameProfileRejectsEqualByteConfigReplacement(t *testing.T) {
	ctx, request := sdkASMDataRequest(t, "amd64", "internal/cpu")
	config := filepath.Join(t.TempDir(), "go-env")
	bytes := []byte("GOPROXY=off\n")
	if err := os.WriteFile(config, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := sourcepath.Resolve(config)
	if err != nil {
		t.Fatal(err)
	}
	for index, pair := range request.Environment {
		if strings.HasPrefix(pair, "GOENV=") {
			request.Environment[index] = "GOENV=" + config
		}
	}
	observed, err := CaptureGoAMD64SDKFrameObservation(ctx, request)
	if err != nil {
		t.Fatal("actual original SDK source/config", err)
	}
	defer observed.Close()
	if err := os.Rename(config, config+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, bytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := observed.Verify(ctx); !errors.Is(err, ErrProbeNeedsContext) {
		t.Fatal("equal-byte replacement acquired lazily captured original config identity", err)
	}
}
