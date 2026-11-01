//go:build linux && amd64 && plan9asm_native_avx512

package plan9asm

import (
	"os"
	"testing"
)

// Explicit hardware qualification retains the original complete fixtures.
// An absent CPU feature is fatal in each original preflight, never a skip.
func x86RequireNativeAVX512Qualification(t *testing.T) {
	t.Helper()
	if mode := os.Getenv("PLAN9ASM_AVX512_RUNTIME"); mode != "" && mode != "required" {
		t.Fatalf("explicit native AVX512 qualification requires required policy, got %q", mode)
	}
}

func TestAMD64FPClassRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64FPClassRuntimeSemantics(t)
}

func TestAMD64FixupImmediateRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64FixupImmediateRuntimeSemantics(t)
}

func TestAMD64FloatingRangeDoubleAndScalarRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64FloatingRangeDoubleAndScalarRuntimeSemantics(t)
}

func TestAMD64FloatingRangeRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64FloatingRangeRuntimeSemantics(t)
}

func TestAMD64GetExpRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64GetExpRuntimeSemantics(t)
}

func TestAMD64GetMantRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64GetMantRuntimeSemantics(t)
}

func TestAMD64PackedAbsSignRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64PackedAbsSignRuntimeSemantics(t)
}

func TestAMD64ScalarIntegerFloatRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64ScalarIntegerFloatRuntimeSemantics(t)
}

func TestAMD64ScalarPrecisionConvertRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64ScalarPrecisionConvertRuntimeSemantics(t)
}

func TestAMD64ScalarSqrtRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64ScalarSqrtRuntimeSemantics(t)
}

func TestAMD64ScaleFRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64ScaleFRuntimeSemantics(t)
}

func TestAMD64ScaledRoundRuntimeSemantics(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyAMD64ScaledRoundRuntimeSemantics(t)
}

func TestCrossLinuxRuntimeMatrixX86FMA3GoCallerNumericalFamily(t *testing.T) {
	x86RequireNativeAVX512Qualification(t)
	qualifyCrossLinuxRuntimeMatrixX86FMA3GoCallerNumericalFamily(t)
}
