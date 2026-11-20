package plan9asm

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xgo-dev/plan9asm/internal/goasmcmd"
	"github.com/xgo-dev/plan9asm/internal/sourcepath"
)

func TestGoAMD64FrameSourceFinalCallbackDriverRetargetRevokes(t *testing.T) {
	pkg, request := goAMD64FrameSourceFixture(t)
	physicalDriver := request.GoBinary
	original, cancel := runtimeOracleStageContext(t)
	defer cancel()
	alias := goAMD64FrameDriverDirectoryAlias(t, original, filepath.Dir(physicalDriver))
	request.GoBinary = filepath.Join(alias, filepath.Base(physicalDriver))
	request.Environment = append(request.Environment, "GOROOT="+filepath.Dir(filepath.Dir(physicalDriver)))
	source, err := CaptureGoAMD64FrameSource(original, pkg, request)
	if err != nil {
		t.Fatal("actual parent-alias source precondition:", err)
	}
	t.Cleanup(func() {
		if err := source.Close(); err != nil {
			t.Error(err)
		}
	})
	if err := source.Verify(original); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(physicalDriver)
	if err != nil || sha256.Sum256(data) != source.inputs[physicalDriver] {
		t.Fatal("cannot retain same-bytes driver replacement:", err)
	}
	replacement := t.TempDir()
	replacementDriver := filepath.Join(replacement, filepath.Base(physicalDriver))
	if err := os.WriteFile(replacementDriver, data, 0700); err != nil {
		t.Fatal(err)
	}
	data = nil
	output, err := goasmcmd.Run(original, request.Directory, request.Environment, replacementDriver, "version")
	if err != nil || !strings.Contains(string(output), source.env["GOVERSION"]) {
		t.Fatalf("same-bytes replacement is not independently executable: %v\n%s", err, output)
	}
	physicalReplacement, err := sourcepath.Resolve(replacementDriver)
	if err != nil {
		t.Fatal(err)
	}
	retargeted := false
	ctx := &sourceTerminalTestContext{Context: original}
	ctx.callback = func(method string, count int) {
		// Capture samples Err three times. The final post-command round
		// samples it twice more before its terminal Done/Deadline checks.
		if method != "Err" || count != 5 {
			return
		}
		if !source.mu.TryLock() {
			t.Fatal("final driver callback held the frame lock")
		}
		source.mu.Unlock()
		if err := os.Remove(alias); err != nil {
			t.Fatal(err)
		}
		goAMD64FrameDriverDirectoryLink(t, original, alias, replacement)
		if actual, err := sourcepath.Resolve(request.GoBinary); err != nil || actual != physicalReplacement {
			t.Fatalf("final callback did not retarget the actual driver: %q; %v", actual, err)
		}
		retargeted = true
	}
	err = source.Verify(ctx)
	t.Logf("final callback Err=%d Done=%d Deadline=%d retargeted=%t error=%v ready=%t",
		ctx.errCalls, ctx.doneCalls, ctx.deadlineCalls, retargeted, err, source.ready)
	if !retargeted || ctx.errCalls != 5 || ctx.deadlineCalls != 3 {
		t.Fatal("final context callback was not reached")
	}
	if !errors.Is(err, ErrProbeNeedsContext) || source.ready {
		t.Errorf("final callback changed the actual driver after its last route guard: error=%v ready=%t", err, source.ready)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	goAMD64FrameDriverDirectoryLink(t, original, alias, filepath.Dir(physicalDriver))
	if err := source.Verify(original); !errors.Is(err, ErrProbeNeedsContext) || source.ready {
		t.Fatal("restoring the driver alias revived the final-callback observation:", err)
	}
}
