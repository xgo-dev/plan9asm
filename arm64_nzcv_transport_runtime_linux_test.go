package plan9asm

import (
	"os"
	"runtime"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64NZCVTransport(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross runtime requires Linux/amd64")
	}
	compiler := []string{"aarch64-linux-gnu-gcc", "-no-pie"}
	runner := []string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"}
	arm64NZCVReadRuntime(t, "aarch64-unknown-linux-gnu", "linux", compiler, runner)
	arm64NZCVMatrixRuntime(t, "aarch64-unknown-linux-gnu", "linux", compiler, runner)
}
