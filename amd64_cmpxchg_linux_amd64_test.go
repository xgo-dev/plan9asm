package plan9asm

import "testing"

// These strict mathematical oracles require real Linux/AMD64 execution.
// The unchanged shared fixtures preserve all six flags, complete aliases,
// MXCSR and canaries. Local Go/C equivalence never satisfies this ISA axis.
func TestCrossLinuxRuntimeMatrixX86CMPXCHGOriginalGoCompleteNumerical(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86CMPXCHGOriginalNumerical(t, x86FloatCompareExecutionTools(t))
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86CMPXCHGIndependentCOriginalOpcodeNumerical(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86CMPXCHGOriginalCNumerical(t, x86FloatCompareExecutionTools(t))
	x87IA32RequireNativeHost(t)
}

// This required native axis is selected by the existing CrossLinuxRuntimeMatrix
// CI prefix. Rosetta/QEMU equivalence does not satisfy its actual #GP assertion.
func TestCrossLinuxRuntimeMatrixX86CMPXCHGNativeFaultAndAccessWidth(t *testing.T) {
	x87IA32RequireNativeHost(t)
	x86CMPXCHGRunFaultCollector(t, x86FloatCompareExecutionTools(t), true)
	x87IA32RequireNativeHost(t)
}

func TestCrossLinuxRuntimeMatrixX86CMPXCHGNativeNumerical(t *testing.T) {
	x87IA32RequireNativeHost(t)
	execution := x86FloatCompareExecutionTools(t)
	t.Run("original-Go", func(t *testing.T) {
		x86CMPXCHGOriginalNumerical(t, execution)
	})
	t.Run("original-C-opcode", func(t *testing.T) {
		x86CMPXCHGOriginalCNumerical(t, execution)
	})
	t.Run("LLVM", func(t *testing.T) {
		x86CMPXCHGLLVMNumerical(t, execution)
	})
	t.Run("Go-C-actual-equivalence", func(t *testing.T) {
		x86CMPXCHGActualEquivalence(t, execution)
	})
	x87IA32RequireNativeHost(t)
}
