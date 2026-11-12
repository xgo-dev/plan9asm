//go:build darwin && arm64

package plan9asm

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestDarwinNativeARM64CompilerUsesActualSelectedSDK(t *testing.T) {
	_, _, compiler, runner := arm64FPPairRuntimeTools(t)
	if len(runner) != 0 {
		t.Fatal("native Darwin compiler acquired a cross-runtime runner")
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path")
	command.Env = os.Environ()
	output, stderr, err := runtimeOracleMachineOutput(ctx, command)
	if err != nil || len(stderr) != 0 || !strings.HasSuffix(string(output), "\n") {
		t.Fatalf("independent actual SDK query: %v\n%s%s", err, output, stderr)
	}
	root, err := filepath.EvalSymlinks(strings.TrimSuffix(string(output), "\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--no-default-config", "-isysroot", root}
	if !reflect.DeepEqual(compiler[1:], want) {
		t.Fatalf("native compiler flags=%q want actual SDK flags=%q", compiler[1:], want)
	}
	t.Logf("actual native LLVM22 compiler=%q SDK=%q flags=%q", compiler[0], root, compiler[1:])
}
