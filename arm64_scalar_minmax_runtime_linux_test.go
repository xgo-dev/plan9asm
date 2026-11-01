package plan9asm

import (
	"os"
	"runtime"
	"testing"
)

func TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxDeadNative(t *testing.T) {
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross runtime requires Linux/amd64")
	}
	arm64MinMaxDeadRuntime(t, "aarch64-unknown-linux-gnu", "linux",
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"})
}

// Complete family roots are separate scheduler inputs. Keep every original
// bank, state, API and optimization axis without extending the CI deadline.
func TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxFMAX(t *testing.T) {
	arm64MinMaxLinuxFamilyRuntime(t, "FMAX")
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxFMIN(t *testing.T) {
	arm64MinMaxLinuxFamilyRuntime(t, "FMIN")
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxFMAXNM(t *testing.T) {
	arm64MinMaxLinuxFamilyRuntime(t, "FMAXNM")
}

func TestCrossLinuxRuntimeMatrixARM64ScalarMinMaxFMINNM(t *testing.T) {
	arm64MinMaxLinuxFamilyRuntime(t, "FMINNM")
}

func arm64MinMaxLinuxFamilyRuntime(t *testing.T, family string) {
	t.Helper()
	if os.Getenv("PLAN9ASM_CROSS_EXEC") != "1" {
		t.Skip("required Linux/QEMU cross-runtime owner")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("cross runtime requires Linux/amd64")
	}
	arm64MinMaxStateRuntimeFamily(t, "aarch64-unknown-linux-gnu", "linux",
		[]string{"aarch64-linux-gnu-gcc", "-no-pie"},
		[]string{"qemu-aarch64", "-cpu", "max", "-L", "/usr/aarch64-linux-gnu"}, family, true)
}
