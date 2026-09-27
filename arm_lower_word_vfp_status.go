package plan9asm

import "fmt"

type armRawVFPStatusTransfer struct {
	toCore    bool
	toFlags   bool
	condition string
	core      int
}

// decodeARMRawVFPStatusTransfer covers VMRS Rt,FPSCR, VMSR FPSCR,Rt, and the
// VMRS APSR_nzcv,FPSCR form for every executable A32 condition. PC is reserved
// as a VMSR source and denotes APSR_nzcv only in the VMRS direction.
func decodeARMRawVFPStatusTransfer(word uint32) (armRawVFPStatusTransfer, bool) {
	const mask = uint32(0x0fff0fff)
	key := word & mask
	toCore := false
	switch key {
	case 0x0ee10a10:
	case 0x0ef10a10:
		toCore = true
	default:
		return armRawVFPStatusTransfer{}, false
	}
	condition, ok := armRawCondition(word >> 28)
	if !ok {
		return armRawVFPStatusTransfer{}, false
	}
	core := int(word>>12) & 15
	if !toCore && core == 15 {
		return armRawVFPStatusTransfer{}, false
	}
	return armRawVFPStatusTransfer{
		toCore:    toCore,
		toFlags:   toCore && core == 15,
		condition: condition,
		core:      core,
	}, true
}

func (c *armCtx) lowerRawVFPStatusTransfer(form armRawVFPStatusTransfer) error {
	if form.condition != "" && form.condition != "AL" {
		condition := form.condition
		form.condition = "AL"
		return c.emitConditionalEffect(condition, func() error {
			return c.lowerRawVFPStatusTransfer(form)
		})
	}
	if form.toFlags {
		if !c.flagsWritten {
			return fmt.Errorf("%w: raw VMRS has no preceding modeled VFP flag write", ErrProbeNeedsContext)
		}
		return nil
	}
	core := Reg(fmt.Sprintf("R%d", form.core))
	if form.toCore {
		status := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 asm sideeffect %q, %q()\n", status, "vmrs $0, fpscr", "=r,~{memory}")
		return c.storeReg(core, "%"+status)
	}
	status, err := c.loadReg(core)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(i32 %s)\n", "vmsr fpscr, $0", "r,~{memory}", status)
	return nil
}
