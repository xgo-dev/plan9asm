package plan9asm

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeTargetTriplesLLVM22AllArchitectures(t *testing.T) {
	llc, err := exec.LookPath("llc")
	if err != nil {
		t.Fatal("required LLVM22 llc:", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	version, err := exec.CommandContext(ctx, llc, "--version").CombinedOutput()
	cancel()
	if err != nil || !strings.Contains(string(version), "LLVM version 22.") {
		t.Fatalf("required LLVM22 llc: %v\n%s", err, version)
	}
	for _, target := range []struct {
		goos, goarch, triple string
	}{
		{"darwin", "amd64", "x86_64-apple-macosx"},
		{"darwin", "arm64", "arm64-apple-macosx"},
		{"linux", "386", "i386-unknown-linux-gnu"},
		{"linux", "amd64", "x86_64-unknown-linux-gnu"},
		{"linux", "arm", "armv7-unknown-linux-gnueabihf"},
		{"linux", "arm64", "aarch64-unknown-linux-gnu"},
		{"windows", "386", "i686-w64-windows-gnu"},
		{"windows", "amd64", "x86_64-w64-windows-gnu"},
		{"windows", "arm64", "aarch64-w64-windows-gnu"},
		{"js", "wasm", "wasm32-unknown-unknown"},
		{"wasip1", "wasm", "wasm32-unknown-wasi"},
	} {
		t.Run(target.goos+"/"+target.goarch, func(t *testing.T) {
			triple := testTargetTriple(target.goos, target.goarch)
			if triple != target.triple {
				t.Errorf("runtime target triple got %q want %q", triple, target.triple)
			}
			dir := t.TempDir()
			input := filepath.Join(dir, "minimal.ll")
			object := filepath.Join(dir, "minimal.o")
			if err := os.WriteFile(input, []byte("define void @minimal() { ret void }\n"), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			output, err := exec.CommandContext(ctx, llc, "-mtriple="+triple, "-filetype=obj", input, "-o", object).CombinedOutput()
			cancel()
			if err != nil || len(output) != 0 {
				t.Fatalf("actual LLVM22 target object: %v\n%s", err, output)
			}
			info, err := os.Stat(object)
			if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
				t.Fatalf("LLVM22 did not emit a nonempty regular object: %v", err)
			}
		})
	}
}

func TestRuntimeTargetTriplesRejectUnknownCombinations(t *testing.T) {
	for _, target := range [][2]string{
		{"linux", "not-an-arch"}, {"not-an-os", "amd64"},
		{"darwin", "386"}, {"windows", "arm"},
		{"linux", "wasm"}, {"js", "amd64"}, {"wasip1", "arm64"},
	} {
		t.Run(target[0]+"/"+target[1], func(t *testing.T) {
			defer func() {
				failure, ok := recover().(string)
				want := "unsupported test target " + target[0] + "/" + target[1]
				if !ok || failure != want {
					t.Errorf("unknown test target did not explicitly fail before invoking LLVM: %q", failure)
				}
			}()
			_ = testTargetTriple(target[0], target[1])
		})
	}
}
