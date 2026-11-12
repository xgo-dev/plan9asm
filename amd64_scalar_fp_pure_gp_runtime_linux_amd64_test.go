//go:build linux && amd64

package plan9asm

import "testing"

// Rosetta does not advertise BMI2. This separate mandatory native owner must
// execute all eight BMI2 witnesses; an absent ISA/tool is a failure, not a skip.
func TestCrossLinuxRuntimeMatrixX86PureGPUnknownBMI2DeadOutputs(t *testing.T) {
	x86PureGPUnknownRuntime(t, true)
}
