package plan9asm

import "testing"

func TestCrossLinuxRuntimeMatrixGoAMD64FixedLocalGPSIMD(t *testing.T) {
	var kernels []fixedLocalVEXRuntimeKernel
	for _, family := range fixedLocalGPSIMDNames {
		operations := []string{
			family.name + " AX,X1",
			family.name + " X0,BX\nMOVQ BX,72(BP)",
			family.name + " 65(BP),X1",
			family.name + " X0,65(BP)",
			family.name + " 1(SI),X1",
			family.name + " X0,1(SI)",
		}
		if family.bits == 64 {
			operations = append(operations, family.name+" X0,X1", family.name+" X1,X1")
		}
		for index, operation := range operations {
			// Observe the whole Y destination, all private canaries, native
			// input stores and dword GP zero-extension. SETCS observes the
			// original carry without an instruction which changes FLAGS.
			operations[index] = "MOVQ (SI),AX\nMOVQ $-1,BX\nSTC\n" + operation +
				"\nSETCS R8\nMOVBQZX R8,R8\nMOVQ R8,88(BP)"
		}
		kernels = append(kernels, fixedLocalVEXRuntimeKernel{family.name, operations})
	}
	if len(kernels) != 6 {
		t.Fatal("complete low-bank native transfer inventory changed", len(kernels))
	}
	// AVX2 is required for the independent driver to observe preserved upper
	// Y aliases. X31/EVEX objects have a separate hardware acceptance boundary.
	fixedLocalVectorRuntime(t, fixedLocalVEXNativeTools(t), true, kernels)
	if !t.Failed() {
		t.Log("GP_SIMD_NATIVE_COMPLETE families=6 inputs_per_family=16 APIs=3 LLVM_levels=O0,O2 original_observations=96 LLVM_comparisons=576")
	}
}
