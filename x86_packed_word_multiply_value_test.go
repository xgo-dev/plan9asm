package plan9asm

import "testing"

// Independent complete ymm/yxm_q4 and _yvandnpd inventory. The three legacy
// MMX opcodes have their own physical-state boundary, not an invented X input.
func x86WordMultiplyValueRows(arch string) []struct{ op, bank, mode string } {
	return x86FixedBinaryValueRows(arch, []string{
		"PMULLW", "PMULHW", "PMULHUW", "PMULHRSW",
		"VPMULLW", "VPMULHW", "VPMULHUW", "VPMULHRSW",
	})
}

func TestX86PackedWordMultiplyValueCompleteFamilyFiveTargetsThreeAPIs(t *testing.T) {
	x86FixedBinaryCompleteFamilyObjects(t, x86WordMultiplyValueRows, 40, 16)
}

func TestX86PackedWordMultiplyVoidCannotInventRegisterInputs(t *testing.T) {
	x86FixedBinaryVoidInputBoundaries(t, x86WordMultiplyValueRows)
}

func TestX86PackedWordMultiplyNativeInputsStayIndependent(t *testing.T) {
	x86FixedBinaryNativeInputBoundaries(t, x86WordMultiplyValueRows)
}
