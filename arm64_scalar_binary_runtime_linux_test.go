package plan9asm

import (
	"os"
	"runtime"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64ScalarBinaryDeadNative(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross runtime requires Linux/amd64")
	}
	arm64ScalarBinaryDeadRuntime(t, "aarch64-unknown-linux-gnu", "linux",
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

func TestCrossLinuxRuntimeMatrixARM64ScalarBinaryFullStateNative(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross runtime requires Linux/amd64")
	}
	arm64BinaryStateRuntime(t, "aarch64-unknown-linux-gnu", "linux",
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"}, true)
}
