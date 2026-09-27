package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedDoubleToSingleProperties struct {
	broadcast bool
	rounding  string
	zeroing   bool
}

func amd64PackedDoubleToSingleSuffixes(rawOp, baseOp string) (amd64PackedDoubleToSingleProperties, error) {
	var properties amd64PackedDoubleToSingleProperties
	dot := strings.IndexByte(rawOp, '.')
	if dot < 0 {
		return properties, nil
	}
	suffixes := strings.Split(rawOp[dot+1:], ".")
	for i, suffix := range suffixes {
		switch suffix {
		case "BCST":
			if properties.broadcast || properties.rounding != "" || properties.zeroing || i != 0 {
				return properties, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			properties.broadcast = true
		case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
			if properties.rounding != "" || properties.broadcast || properties.zeroing || i != 0 {
				return properties, fmt.Errorf("amd64 %s has invalid or duplicate .%s suffix", baseOp, suffix)
			}
			properties.rounding = suffix
		case "Z":
			if properties.zeroing || i != len(suffixes)-1 {
				return properties, fmt.Errorf("amd64 %s has invalid or duplicate .Z suffix", baseOp)
			}
			properties.zeroing = true
		default:
			return properties, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return properties, nil
}

// lowerPackedDoubleToSingle implements the complete Go 1.27 CVTPD2PS family:
// CVTPD2PS X/m128->X, VCVTPD2PSX X/m128->X, VCVTPD2PSY Y/m256->X,
// and VCVTPD2PS Z/m512->Y, including EVEX masks, broadcast, and rounding.
func (c *amd64Ctx) lowerPackedDoubleToSingle(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	if baseOp != "CVTPD2PS" && baseOp != "VCVTPD2PS" && baseOp != "VCVTPD2PSX" && baseOp != "VCVTPD2PSY" {
		return false, false, nil
	}

	properties, err := amd64PackedDoubleToSingleSuffixes(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	vectorForm := baseOp != "CVTPD2PS"
	if !vectorForm {
		if rawOp != baseOp || len(ins.Args) != 2 {
			return true, false, fmt.Errorf("amd64 CVTPD2PS expects X/m128 source and X destination: %q", ins.Raw)
		}
	} else if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects source, [K mask,] vector destination: %q", baseOp, ins.Raw)
	}

	masked := vectorForm && len(ins.Args) == 3
	if properties.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z form requires a K mask: %q", baseOp, ins.Raw)
	}
	if properties.broadcast && !isAMD64MemoryOperand(ins.Args[0]) {
		return true, false, fmt.Errorf("amd64 %s .BCST requires a memory source: %q", baseOp, ins.Raw)
	}
	if properties.rounding != "" && (baseOp != "VCVTPD2PS" || ins.Args[0].Kind != OpReg) {
		return true, false, fmt.Errorf("amd64 %s .%s requires a Z register source and Y destination: %q", baseOp, properties.rounding, ins.Raw)
	}

	dstArg := ins.Args[len(ins.Args)-1]
	if dstArg.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s expects a vector destination: %q", baseOp, ins.Raw)
	}
	inputBytes, convertedLanes, outputBytes := 0, 0, 0
	switch baseOp {
	case "CVTPD2PS", "VCVTPD2PSX":
		inputBytes, convertedLanes, outputBytes = 16, 2, 16
		if !isAMD64XReg(dstArg.Reg) {
			return true, false, fmt.Errorf("amd64 %s expects an X destination: %q", baseOp, ins.Raw)
		}
	case "VCVTPD2PSY":
		inputBytes, convertedLanes, outputBytes = 32, 4, 16
		if !isAMD64XReg(dstArg.Reg) {
			return true, false, fmt.Errorf("amd64 VCVTPD2PSY expects an X destination: %q", ins.Raw)
		}
	case "VCVTPD2PS":
		inputBytes, convertedLanes, outputBytes = 64, 8, 32
		if !isAMD64YReg(dstArg.Reg) {
			return true, false, fmt.Errorf("amd64 VCVTPD2PS expects a Y destination: %q", ins.Raw)
		}
	}
	if c.goarch == "386" && baseOp == "CVTPD2PS" {
		dstIndex, _ := amd64ParseXReg(dstArg.Reg)
		if dstIndex > 7 {
			return true, false, fmt.Errorf("386 CVTPD2PS destination is outside Go 1.27's X register class: %q", ins.Raw)
		}
	}

	sourceArg := ins.Args[0]
	if sourceArg.Kind == OpReg {
		if !amd64VectorRegisterHasWidth(sourceArg, inputBytes) {
			return true, false, fmt.Errorf("amd64 %s source width does not match its form: %q", baseOp, ins.Raw)
		}
		if c.goarch == "386" {
			switch baseOp {
			case "CVTPD2PS":
				index, _ := amd64ParseXReg(sourceArg.Reg)
				if index > 7 {
					return true, false, fmt.Errorf("386 CVTPD2PS source is outside Go 1.27's X register class: %q", ins.Raw)
				}
			case "VCVTPD2PS":
				index, _ := amd64ParseZReg(sourceArg.Reg)
				if index > 7 {
					return true, false, fmt.Errorf("386 VCVTPD2PS source is outside Go 1.27's Yzm register class: %q", ins.Raw)
				}
			}
		}
	} else if !isAMD64MemoryOperand(sourceArg) {
		return true, false, fmt.Errorf("amd64 %s expects a vector register or memory source: %q", baseOp, ins.Raw)
	}

	mask := ""
	if masked {
		maskArg := ins.Args[1]
		if maskArg.Kind != OpReg {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		maskIndex, ok := amd64ParseKReg(maskArg.Reg)
		if !ok || maskIndex == 0 {
			return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
		}
		mask, err = c.loadK(maskArg.Reg)
		if err != nil {
			return true, false, err
		}
	}

	var source string
	if properties.broadcast {
		scalar, err := c.evalF64(sourceArg)
		if err != nil {
			return true, false, err
		}
		seed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x double> poison, double %s, i32 0\n", seed, convertedLanes, scalar)
		splat := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x double> %%%s, <%d x double> poison, <%d x i32> zeroinitializer\n", splat, convertedLanes, seed, convertedLanes, convertedLanes)
		source = "%" + splat
	} else {
		bytesValue, err := c.loadPackedCompareBytes(sourceArg, inputBytes)
		if err != nil {
			return true, false, err
		}
		cast := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x double>\n", cast, inputBytes, bytesValue, convertedLanes)
		source = "%" + cast
	}

	converted := c.newTmp()
	if properties.rounding == "" {
		fmt.Fprintf(c.b, "  %%%s = fptrunc <%d x double> %s to <%d x float>\n", converted, convertedLanes, source, convertedLanes)
	} else {
		fmt.Fprintf(c.b, "  %%%s = call <%d x float> @llvm.experimental.constrained.fptrunc.v%df32.v%df64(<%d x double> %s, metadata !\"%s\", metadata !\"fpexcept.ignore\")\n", converted, convertedLanes, convertedLanes, convertedLanes, convertedLanes, source, amd64FMA3RoundingMetadata(properties.rounding))
	}
	result := "%" + converted

	if masked {
		computedBits := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x float> %s to <%d x i32>\n", computedBits, convertedLanes, result, convertedLanes)
		oldBytes, err := c.loadPackedCompareBytes(dstArg, outputBytes)
		if err != nil {
			return true, false, err
		}
		physicalLanes := outputBytes / 4
		oldAll := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x i32>\n", oldAll, outputBytes, oldBytes, physicalLanes)
		oldBits := "%" + oldAll
		if physicalLanes != convertedLanes {
			oldLow := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i32> %s, <%d x i32> poison, <%d x i32> <i32 0, i32 1>\n", oldLow, physicalLanes, oldBits, physicalLanes, convertedLanes)
			oldBits = "%" + oldLow
		}
		maskedBits := amd64ApplyIntegerLaneMask(c, convertedLanes, 32, "%"+computedBits, oldBits, mask, properties.zeroing)
		maskedValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x float>\n", maskedValue, convertedLanes, maskedBits, convertedLanes)
		result = "%" + maskedValue
	}

	if convertedLanes == 2 {
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <2 x float> %s, <2 x float> zeroinitializer, <4 x i32> <i32 0, i32 1, i32 2, i32 3>\n", widened, result)
		result = "%" + widened
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x float> %s to <%d x i8>\n", out, outputBytes/4, result, outputBytes)
	return true, false, c.storeVectorBytes(dstArg.Reg, outputBytes, "%"+out)
}
