package plan9asm

import (
	"fmt"
	"strings"
)

func (c *arm64Ctx) lowerARM64SVEFloatExponent(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "ZFEXPA" && op != "ZFLOGB" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) {
		return true, false, fmt.Errorf("arm64 %s does not accept a mnemonic suffix: %q", op, ins.Raw)
	}
	if op == "ZFEXPA" {
		if len(ins.Args) != 2 {
			return true, false, fmt.Errorf("arm64 ZFEXPA expects Zn.H|S|D, Zd.H|S|D: %q", ins.Raw)
		}
		source, sourceBits, sourceOK := arm64ParseSVEZElementReg(ins.Args[0])
		destination, destinationBits, destinationOK := arm64SVEFloatElementReg(ins.Args[1])
		if !sourceOK || !destinationOK || sourceBits == 8 || sourceBits != destinationBits {
			return true, false, fmt.Errorf("arm64 ZFEXPA requires matching H/S/D source and destination widths: %q", ins.Raw)
		}
		sourceValue, integerType, err := c.loadZRegElements(source, sourceBits)
		if err != nil {
			return true, false, err
		}
		_, floatingType, lanes, err := arm64SVEFloatType(sourceBits)
		if err != nil {
			return true, false, err
		}
		mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.fexpa.x.nxv%d%s(%s %s)\n", result, floatingType, lanes, mangle, integerType, sourceValue)
		return true, false, c.storeRawSVEFloatVector(destination, destinationBits, "%"+result, floatingType)
	}
	if len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 ZFLOGB expects Zn.H|S|D, Pg/M|Z, Zd.H|S|D: %q", ins.Raw)
	}
	source, sourceBits, sourceOK := arm64SVEFloatElementReg(ins.Args[0])
	mergePredicate, mergeOK := arm64ParseSVEPredicateMode(ins.Args[1], "M", 7)
	zeroPredicate, zeroOK := arm64ParseSVEPredicateMode(ins.Args[1], "Z", 7)
	destination, destinationBits, destinationOK := arm64ParseSVEZElementReg(ins.Args[2])
	if !sourceOK || (!mergeOK && !zeroOK) || !destinationOK || sourceBits != destinationBits {
		return true, false, fmt.Errorf("arm64 ZFLOGB requires matching H/S/D operands and P0..P7/M|Z: %q", ins.Raw)
	}
	predicate := mergePredicate
	if zeroOK {
		predicate = zeroPredicate
	}
	predicateValue, predicateType, err := c.loadPRegElements(predicate, sourceBits)
	if err != nil {
		return true, false, err
	}
	sourceValue, floatingType, err := c.loadRawSVEFloatVector(source, sourceBits)
	if err != nil {
		return true, false, err
	}
	passthrough := "zeroinitializer"
	integerType, lanes, err := arm64SVEVectorType(destinationBits)
	if err != nil {
		return true, false, err
	}
	if mergeOK {
		passthrough, _, err = c.loadZRegElements(destination, destinationBits)
		if err != nil {
			return true, false, err
		}
	}
	mangle := map[int]string{16: "f16", 32: "f32", 64: "f64"}[sourceBits]
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.sve.flogb.nxv%d%s(%s %s, %s %s, %s %s)\n", result, integerType, lanes, mangle, integerType, passthrough, predicateType, predicateValue, floatingType, sourceValue)
	return true, false, c.storeZRegElements(destination, destinationBits, "%"+result)
}
