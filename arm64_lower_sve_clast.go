package plan9asm

import (
	"fmt"
	"strings"
)

type arm64SVECLastDestination uint8

const (
	arm64SVECLastGeneric arm64SVECLastDestination = iota
	arm64SVECLastGPR
	arm64SVECLastVReg
)

type arm64SVECLastSpec struct {
	intrinsic   string
	baseSize    int
	destination arm64SVECLastDestination
}

var arm64SVECLastSpecs = map[Op]arm64SVECLastSpec{
	"ZCLASTA":  {intrinsic: "clasta", destination: arm64SVECLastGeneric},
	"ZCLASTAW": {intrinsic: "clasta", destination: arm64SVECLastGPR},
	"ZCLASTAB": {intrinsic: "clasta", destination: arm64SVECLastVReg},
	"ZCLASTAH": {intrinsic: "clasta", baseSize: 1, destination: arm64SVECLastVReg},
	"ZCLASTAS": {intrinsic: "clasta", baseSize: 2, destination: arm64SVECLastVReg},
	"ZCLASTAD": {intrinsic: "clasta", baseSize: 3, destination: arm64SVECLastVReg},
	"ZCLASTB":  {intrinsic: "clastb", destination: arm64SVECLastGeneric},
	"ZCLASTBW": {intrinsic: "clastb", destination: arm64SVECLastGPR},
	"ZCLASTBB": {intrinsic: "clastb", destination: arm64SVECLastVReg},
	"ZCLASTBH": {intrinsic: "clastb", baseSize: 1, destination: arm64SVECLastVReg},
	"ZCLASTBS": {intrinsic: "clastb", baseSize: 2, destination: arm64SVECLastVReg},
	"ZCLASTBD": {intrinsic: "clastb", baseSize: 3, destination: arm64SVECLastVReg},
}

func (c *arm64Ctx) lowerARM64SVECLast(op Op, ins Instr) (ok bool, terminated bool, err error) {
	spec, ok := arm64SVECLastSpecs[op]
	if !ok {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 4 {
		return true, false, fmt.Errorf("arm64 %s expects source, old destination, Pg, destination without a suffix: %q", op, ins.Raw)
	}
	source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
	predicate, predicateOK := arm64ParseSVEPredicateBare(ins.Args[2], 7)
	if !sourceOK || !predicateOK {
		return true, false, fmt.Errorf("arm64 %s requires a Z source and P0..P7: %q", op, ins.Raw)
	}
	sourceSize := map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[sourceBits]

	destinationKind := spec.destination
	oldVector, oldBits, oldVectorOK := arm64ParseSVEZElementReg(ins.Args[1])
	newVector, newBits, newVectorOK := arm64ParseSVEZElementReg(ins.Args[3])
	if destinationKind == arm64SVECLastGeneric && oldVectorOK && newVectorOK {
		if oldVector != newVector {
			return true, false, fmt.Errorf("arm64 %s vector destination must be destructive: %q", op, ins.Raw)
		}
		elementBits := 8 << (sourceSize |
			map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[oldBits] |
			map[int]int{8: 0, 16: 1, 32: 2, 64: 3}[newBits])
		return true, false, c.lowerARM64SVECLastVector(spec.intrinsic, source, predicate, oldVector, elementBits)
	}
	if destinationKind == arm64SVECLastGeneric {
		destinationKind = arm64SVECLastGPR
		spec.baseSize = 3
	}
	elementBits := 8 << (spec.baseSize | sourceSize)
	if destinationKind == arm64SVECLastGPR {
		if !arm64SVEIndexScalarRegister(ins.Args[1]) || !arm64SVEIndexScalarRegister(ins.Args[3]) || ins.Args[1].Reg != ins.Args[3].Reg {
			return true, false, fmt.Errorf("arm64 %s GP destination must be the same R0..R30 or ZR operand twice: %q", op, ins.Raw)
		}
		return true, false, c.lowerARM64SVECLastScalar(spec.intrinsic, source, predicate, ins.Args[1].Reg, elementBits, false)
	}
	oldDestination, oldOK := arm64SVEInsertVRegister(ins.Args[1])
	newDestination, newOK := arm64SVEInsertVRegister(ins.Args[3])
	if !oldOK || !newOK || oldDestination != newDestination {
		return true, false, fmt.Errorf("arm64 %s SIMD destination must be the same V0..V31 operand twice: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64SVECLastScalar(spec.intrinsic, source, predicate, oldDestination, elementBits, true)
}

func (c *arm64Ctx) lowerARM64SVECLastVector(intrinsic string, source, predicate, destination, elementBits int) error {
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return err
	}
	oldValue, vectorType, err := c.loadZRegElements(destination, elementBits)
	if err != nil {
		return err
	}
	sourceValue, _, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.%s.nxv%di%d(%s %s, %s %s, %s %s)\n",
		result, vectorType, intrinsic, lanes, elementBits, predicateType, predicateValue, vectorType, oldValue, vectorType, sourceValue)
	return c.storeZRegElements(destination, elementBits, "%"+result)
}

func (c *arm64Ctx) lowerARM64SVECLastScalar(intrinsic string, source, predicate int, destination Reg, elementBits int, vectorDestination bool) error {
	predicateValue, predicateType, err := c.loadPRegElements(predicate, elementBits)
	if err != nil {
		return err
	}
	sourceValue, vectorType, err := c.loadZRegElements(source, elementBits)
	if err != nil {
		return err
	}
	var oldValue string
	if vectorDestination {
		oldValue, err = c.arm64SVEInsertVectorScalar(destination, elementBits)
	} else {
		oldValue, err = c.loadReg(destination)
		if err == nil && elementBits != 64 && oldValue != "0" {
			truncated := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", truncated, oldValue, elementBits)
			oldValue = "%" + truncated
		}
	}
	if err != nil {
		return err
	}
	_, lanes, err := arm64SVEVectorType(elementBits)
	if err != nil {
		return err
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call i%d @llvm.aarch64.sve.%s.n.nxv%di%d(%s %s, i%d %s, %s %s)\n",
		result, elementBits, intrinsic, lanes, elementBits, predicateType, predicateValue, elementBits, oldValue, vectorType, sourceValue)
	if vectorDestination {
		return c.storeARM64ScalarToVReg(destination, elementBits, "%"+result)
	}
	value := "%" + result
	if elementBits != 64 {
		extended := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = zext i%d %s to i64\n", extended, elementBits, value)
		value = "%" + extended
	}
	return c.storeReg(destination, value)
}
