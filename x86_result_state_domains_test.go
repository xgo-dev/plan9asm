package plan9asm

import (
	"fmt"
	"testing"
)

func TestX86ABI0ResultInitializationPrivateScalarPointerDomain(t *testing.T) {
	for _, arch := range []string{"386", "amd64"} {
		word := x86ResultPointerWord(arch)
		finish := fmt.Sprintf("MOVL $42,ret0+%d(FP)\nRET", word)
		for name, body := range x86ResultIncomingPointerIdentityBodies(arch) {
			t.Run(arch+"/"+name, func(t *testing.T) {
				_, file, sig, source := x86ResultInitializationFixture(t, arch,
					"func Value(x *[8]uint32) uint32", body+finish)
				goAssemblerOracleOutput(t, arch, source, "", true)
				if err := CheckX86ABI0ResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatalf("public opaque identity observation: %v", err)
				}
				if err := checkX86ScalarFPResultInitialization(file.Funcs[0], sig, arch); err != nil {
					t.Fatalf("opaque transport does not consume numerical pointer bytes: %v", err)
				}
			})
		}
	}
}

func TestX86ABI0ResultInitializationAllStateDomainJoins(t *testing.T) {
	left := x86ResultState{}
	right := x86ResultState{}
	for index := range left.gp {
		left.gp[index], right.gp[index] = 0xff, 0x0f
		left.canonicalGP[index], right.canonicalGP[index] = 0x55, 0x33
		left.pointerGP[index] = true
		right.pointerGP[index] = index%2 == 0
		left.callerAddressGP[index] = index%3 == 0
		right.callerAddressGP[index] = index%2 == 0
	}
	for index := range left.xmm {
		left.xmm[index], right.xmm[index] = 0xffff, 0x00ff
	}
	for index := range left.nativeMMX {
		left.nativeMMX[index], right.nativeMMX[index] = 0xff, 0x55
	}
	for index := range left.masks {
		left.masks[index] = true
		right.masks[index] = index%2 == 0
	}
	merged := left.intersect(right)
	for index := range merged.gp {
		if merged.gp[index] != 0x0f || merged.canonicalGP[index] != 0x11 || merged.pointerGP[index] != (index%2 == 0) || merged.callerAddressGP[index] != (index%6 == 0) {
			t.Errorf("GP/pointer join %d: %+v", index, merged)
		}
	}
	for index := range merged.xmm {
		if merged.xmm[index] != 0x00ff {
			t.Errorf("X%d bypassed the must-defined join: %#x", index, merged.xmm[index])
		}
	}
	for index := range merged.nativeMMX {
		if merged.nativeMMX[index] != 0x55 {
			t.Errorf("M%d bypassed the native-region must-defined join", index)
		}
	}
	for index := range merged.masks {
		if merged.masks[index] != (index%2 == 0) {
			t.Errorf("K%d bypassed the must-defined join", index)
		}
	}
}
