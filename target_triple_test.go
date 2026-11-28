package plan9asm

import (
	"errors"
	"testing"
)

// testTargetTriple returns a practical LLVM target triple for tests.
// We only need a small set for current coverage.
func testTargetTriple(goos, goarch string) string {
	switch goos {
	case "darwin":
		switch goarch {
		case "amd64":
			return "x86_64-apple-macosx"
		case "arm64":
			return "arm64-apple-macosx"
		}
	case "linux":
		switch goarch {
		case "amd64":
			return "x86_64-unknown-linux-gnu"
		case "arm64":
			return "aarch64-unknown-linux-gnu"
		}
	case "windows":
		switch goarch {
		case "amd64":
			return "x86_64-pc-windows-msvc"
		case "arm64":
			return "aarch64-pc-windows-msvc"
		}
	}

	// Fallback for unsupported combos in tests.
	return goarch + "-unknown-" + goos
}

func TestCrossArchRejectForeignCPUInstruction(t *testing.T) {
	for _, tc := range []struct {
		arch       Arch
		op, triple string
	}{
		{ArchAMD64, "CPUID", "aarch64-unknown-linux-gnu"},
		{ArchAMD64, "XGETBV", "wasm32-unknown-unknown"},
	} {
		file, err := Parse(tc.arch, "TEXT cpu(SB),4,$0\n"+tc.op+"\nRET\n")
		if err != nil {
			t.Fatal(err)
		}
		_, err = Translate(file, Options{TargetTriple: tc.triple, Sigs: map[string]FuncSig{"cpu": {Ret: I32}}})
		if !errors.Is(err, ErrProbeNeedsContext) {
			t.Errorf("%s -> %s: %v", tc.op, tc.triple, err)
		}
	}
}
