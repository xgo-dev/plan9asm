package plan9asm

import "fmt"

type arm64RawRNDR struct {
	reseed bool
	reg    int
}

// RNDR and RNDRRS occupy the complete Rt x reseed space in the MRS system
// register encoding. Handle them before generic MRS because both write NZCV.
func decodeARM64RawRNDR(word uint32) (arm64RawRNDR, bool) {
	if word&0xffffffc0 != 0xd53b2400 {
		return arm64RawRNDR{}, false
	}
	return arm64RawRNDR{
		reseed: word&0x20 != 0,
		reg:    int(word & 31),
	}, true
}

func (c *arm64Ctx) lowerRawRNDR(form arm64RawRNDR) error {
	if form.reg < 0 || form.reg > 31 {
		return fmt.Errorf("arm64 invalid RNG destination %d", form.reg)
	}
	if !arm64ScalarConversionNativeTarget(c.targetTriple) {
		return fmt.Errorf("%w: ARM64 RNG requires an explicit native little-endian AArch64 target", ErrProbeNeedsContext)
	}
	if flow := c.machineAvailability; flow != nil && !flow.flagsOnly && (form.reg == 18 || form.reg == 28) {
		return arm64GoABIContext("RNG numerical output cannot replace a platform/g entry identity")
	}
	intrinsic := "rndr"
	if form.reseed {
		intrinsic = "rndrrs"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call { i64, i1 } @llvm.aarch64.%s()\n", result, intrinsic)
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i1 } %%%s, 0\n", value, result)
	failed := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue { i64, i1 } %%%s, 1\n", failed, result)

	// Arm sets NZCV to 0000 on success and 0100 on failure. The intrinsic's
	// second result is the failure/Z bit, as emitted by LLVM's ACLE frontend.
	c.flagsWritten = true
	c.storeFlag(c.flagsNSlot, "false")
	c.storeFlag(c.flagsZSlot, "%"+failed)
	c.storeFlag(c.flagsCSlot, "false")
	c.storeFlag(c.flagsVSlot, "false")
	if form.reg == 31 {
		return nil // XZR discards the value but not the status flags.
	}
	return c.storeReg(Reg(fmt.Sprintf("R%d", form.reg)), "%"+value)
}
