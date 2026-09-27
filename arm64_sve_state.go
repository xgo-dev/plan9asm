package plan9asm

import "fmt"

func (c *arm64Ctx) loadZReg(index int) (string, error) {
	slot := c.zRegSlot[index]
	if slot == "" {
		return "", fmt.Errorf("arm64 SVE Z%d was not allocated", index)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i8>, ptr %s\n", value, slot)
	return "%" + value, nil
}

func (c *arm64Ctx) storeZReg(index int, value string) error {
	slot := c.zRegSlot[index]
	if slot == "" {
		return fmt.Errorf("arm64 SVE Z%d was not allocated", index)
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i8> %s, ptr %s\n", value, slot)
	return nil
}

func (c *arm64Ctx) loadPReg(index int) (string, error) {
	slot := c.pRegSlot[index]
	if slot == "" {
		return "", fmt.Errorf("arm64 SVE P%d was not allocated", index)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load <vscale x 16 x i1>, ptr %s\n", value, slot)
	return "%" + value, nil
}

func (c *arm64Ctx) storePReg(index int, value string) error {
	slot := c.pRegSlot[index]
	if slot == "" {
		return fmt.Errorf("arm64 SVE P%d was not allocated", index)
	}
	fmt.Fprintf(c.b, "  store <vscale x 16 x i1> %s, ptr %s\n", value, slot)
	return nil
}

func (c *arm64Ctx) loadPNReg(index int) (string, error) {
	slot := c.pnRegSlot[index]
	if slot == "" {
		return "", fmt.Errorf("arm64 SVE PN%d was not allocated", index)
	}
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load target(\"aarch64.svcount\"), ptr %s\n", value, slot)
	return "%" + value, nil
}

func (c *arm64Ctx) storePNReg(index int, value string) error {
	slot := c.pnRegSlot[index]
	if slot == "" {
		return fmt.Errorf("arm64 SVE PN%d was not allocated", index)
	}
	fmt.Fprintf(c.b, "  store target(\"aarch64.svcount\") %s, ptr %s\n", value, slot)
	return nil
}

func (c *arm64Ctx) storePRegElements(index, elementBits int, value string) error {
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	if elementBits == 8 {
		return c.storePReg(index, value)
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <vscale x 16 x i1> @llvm.aarch64.sve.convert.to.svbool.nxv%di1(<vscale x %d x i1> %s)\n", converted, lanes, lanes, value)
	return c.storePReg(index, "%"+converted)
}

func arm64SVEVectorType(elementBits int) (string, int, error) {
	if elementBits != 8 && elementBits != 16 && elementBits != 32 && elementBits != 64 {
		return "", 0, fmt.Errorf("unsupported ARM64 SVE element width %d", elementBits)
	}
	lanes := 128 / elementBits
	return fmt.Sprintf("<vscale x %d x i%d>", lanes, elementBits), lanes, nil
}

func (c *arm64Ctx) loadZRegElements(index, elementBits int) (value, vectorType string, err error) {
	bytes, err := c.loadZReg(index)
	if err != nil {
		return "", "", err
	}
	vectorType, _, err = arm64SVEVectorType(elementBits)
	if err != nil {
		return "", "", err
	}
	if elementBits == 8 {
		return bytes, vectorType, nil
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <vscale x 16 x i8> %s to %s\n", converted, bytes, vectorType)
	return "%" + converted, vectorType, nil
}

func (c *arm64Ctx) storeZRegElements(index, elementBits int, value string) error {
	vectorType, _, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	if elementBits == 8 {
		return c.storeZReg(index, value)
	}
	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast %s %s to <vscale x 16 x i8>\n", bytes, vectorType, value)
	return c.storeZReg(index, "%"+bytes)
}

func (c *arm64Ctx) loadPRegElements(index, elementBits int) (value, predicateType string, err error) {
	predicate, err := c.loadPReg(index)
	if err != nil {
		return "", "", err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return "", "", err
	}
	predicateType = fmt.Sprintf("<vscale x %d x i1>", lanes)
	if elementBits == 8 {
		return predicate, predicateType, nil
	}
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.convert.from.svbool.nxv%di1(<vscale x 16 x i1> %s)\n",
		converted, predicateType, lanes, predicate)
	return "%" + converted, predicateType, nil
}

func (c *arm64Ctx) allTruePRegElements(elementBits int) (value, predicateType string, err error) {
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return "", "", err
	}
	predicateType = fmt.Sprintf("<vscale x %d x i1>", lanes)
	valueName := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.ptrue.nxv%di1(i32 31)\n", valueName, predicateType, lanes)
	return "%" + valueName, predicateType, nil
}

func (c *arm64Ctx) setSVEPredicateFlags(governing, result, predicateType string, lanes int) {
	c.setSVEPredicateSequenceFlags(governing, []string{result}, predicateType, lanes)
}

func (c *arm64Ctx) setSVEPredicateSequenceFlags(governing string, results []string, predicateType string, lanes int) {
	if len(results) == 0 {
		return
	}
	negative := c.newTmp()
	zero := c.newTmp()
	last := c.newTmp()
	carry := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.first.nxv%di1(%s %s, %s %s)\n", negative, lanes, predicateType, governing, predicateType, results[0])
	anyValues := make([]string, 0, len(results))
	for _, result := range results {
		any := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.any.nxv%di1(%s %s, %s %s)\n", any, lanes, predicateType, governing, predicateType, result)
		anyValues = append(anyValues, "%"+any)
	}
	anyValue := anyValues[0]
	for _, value := range anyValues[1:] {
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = or i1 %s, %s\n", combined, anyValue, value)
		anyValue = "%" + combined
	}
	fmt.Fprintf(c.b, "  %%%s = xor i1 %s, true\n", zero, anyValue)
	fmt.Fprintf(c.b, "  %%%s = call i1 @llvm.aarch64.sve.ptest.last.nxv%di1(%s %s, %s %s)\n", last, lanes, predicateType, governing, predicateType, results[len(results)-1])
	fmt.Fprintf(c.b, "  %%%s = xor i1 %%%s, true\n", carry, last)
	c.flagsWritten = true
	c.storeFlag(c.flagsNSlot, "%"+negative)
	c.storeFlag(c.flagsZSlot, "%"+zero)
	c.storeFlag(c.flagsCSlot, "%"+carry)
	c.storeFlag(c.flagsVSlot, "false")
}
