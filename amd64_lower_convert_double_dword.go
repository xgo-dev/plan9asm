package plan9asm

import (
	"fmt"
	"strings"
)

type amd64PackedDoubleDwordMode uint8

const (
	amd64PackedDwordToDouble amd64PackedDoubleDwordMode = iota
	amd64PackedDoubleToDword
)

type amd64PackedDoubleDwordSpec struct {
	mode         amd64PackedDoubleDwordMode
	legacy       bool
	truncate     bool
	sourceBytes  int
	destBytes    int
	resultLanes  int
	explicitMode string
}

// This table is both the translation dispatch and the source of truth used by
// cmd/plan9asmll's supported-opcode extractor.
var amd64PackedDoubleDwordOps = map[string]amd64PackedDoubleDwordSpec{
	"CVTPD2PL":    {mode: amd64PackedDoubleToDword, legacy: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"CVTTPD2PL":   {mode: amd64PackedDoubleToDword, legacy: true, truncate: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTDQ2PD":   {mode: amd64PackedDwordToDouble},
	"VCVTPD2DQ":   {mode: amd64PackedDoubleToDword, sourceBytes: 64, destBytes: 32, resultLanes: 8, explicitMode: "rounding"},
	"VCVTPD2DQX":  {mode: amd64PackedDoubleToDword, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTPD2DQY":  {mode: amd64PackedDoubleToDword, sourceBytes: 32, destBytes: 16, resultLanes: 4},
	"VCVTTPD2DQ":  {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 64, destBytes: 32, resultLanes: 8, explicitMode: "sae"},
	"VCVTTPD2DQX": {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 16, destBytes: 16, resultLanes: 2},
	"VCVTTPD2DQY": {mode: amd64PackedDoubleToDword, truncate: true, sourceBytes: 32, destBytes: 16, resultLanes: 4},
}

type amd64PackedDoubleDwordSuffix struct {
	broadcast bool
	rounding  string
	sae       bool
	zeroing   bool
}

func parseAMD64PackedDoubleDwordSuffix(rawOp, baseOp string) (amd64PackedDoubleDwordSuffix, error) {
	var result amd64PackedDoubleDwordSuffix
	if rawOp == baseOp {
		return result, nil
	}
	suffixes := strings.Split(strings.TrimPrefix(rawOp, baseOp+"."), ".")
	for index, suffix := range suffixes {
		switch suffix {
		case "BCST":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .BCST suffix", baseOp)
			}
			result.broadcast = true
		case "RN_SAE", "RD_SAE", "RU_SAE", "RZ_SAE":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .%s suffix", baseOp, suffix)
			}
			result.rounding = suffix
		case "SAE":
			if result.broadcast || result.rounding != "" || result.sae || result.zeroing || index != 0 {
				return result, fmt.Errorf("amd64 %s has invalid or duplicate .SAE suffix", baseOp)
			}
			result.sae = true
		case "Z":
			if result.zeroing || index != len(suffixes)-1 {
				return result, fmt.Errorf("amd64 %s has invalid or misplaced .Z suffix", baseOp)
			}
			result.zeroing = true
		default:
			return result, fmt.Errorf("amd64 %s has unsupported suffix .%s", baseOp, suffix)
		}
	}
	return result, nil
}

// lowerPackedDoubleDword implements the complete Go 1.27 signed packed
// double/dword conversion family. The legacy yxcvm1 rows include X and MMX
// destinations; the VEX/EVEX rows cover masks, zeroing, scalar broadcast,
// embedded rounding, and SAE.
func (c *amd64Ctx) lowerPackedDoubleDword(op Op, ins Instr) (ok bool, terminated bool, err error) {
	rawOp := strings.ToUpper(string(op))
	baseOp := rawOp
	if dot := strings.IndexByte(rawOp, '.'); dot >= 0 {
		baseOp = rawOp[:dot]
	}
	spec, supported := amd64PackedDoubleDwordOps[baseOp]
	if !supported {
		return false, false, nil
	}
	suffixes, err := parseAMD64PackedDoubleDwordSuffix(rawOp, baseOp)
	if err != nil {
		return true, false, fmt.Errorf("%w: %q", err, ins.Raw)
	}
	if spec.legacy {
		return c.lowerLegacyPackedDoubleToDword(baseOp, spec, ins, suffixes)
	}
	if spec.mode == amd64PackedDwordToDouble {
		return c.lowerVectorPackedDwordToDouble(baseOp, ins, suffixes)
	}
	return c.lowerVectorPackedDoubleToDword(baseOp, spec, ins, suffixes)
}

func (c *amd64Ctx) lowerLegacyPackedDoubleToDword(baseOp string, spec amd64PackedDoubleDwordSpec, ins Instr, suffixes amd64PackedDoubleDwordSuffix) (bool, bool, error) {
	if suffixes != (amd64PackedDoubleDwordSuffix{}) || len(ins.Args) != 2 || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("%s %s expects X/m128 source and X or M destination: %q", c.goarch, baseOp, ins.Raw)
	}
	destination := ins.Args[1]
	_, mmx := amd64ParseMReg(destination.Reg)
	if !mmx && !c.isGoLegacyPackedAbsSignRegister(destination) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's X/M register classes: %q", c.goarch, baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if source.Kind == OpReg {
		if !c.isGoLegacyPackedAbsSignRegister(source) {
			return true, false, fmt.Errorf("%s %s source is outside Go 1.27's X register class: %q", c.goarch, baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("%s %s source must be X or memory: %q", c.goarch, baseOp, ins.Raw)
	}
	doubles, err := c.loadPackedDoubleValues(source, spec.sourceBytes, spec.resultLanes, false)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedDoubleToDword(doubles, spec.resultLanes, spec.truncate, "")
	if mmx {
		packed := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i32> %s to i64\n", packed, result)
		return true, false, c.storeReg(destination.Reg, "%"+packed)
	}
	return true, false, c.storePackedDwordConversionResult(destination.Reg, spec.destBytes, spec.resultLanes, result)
}

func (c *amd64Ctx) lowerVectorPackedDwordToDouble(baseOp string, ins Instr, suffixes amd64PackedDoubleDwordSuffix) (bool, bool, error) {
	if suffixes.rounding != "" || suffixes.sae {
		return true, false, fmt.Errorf("amd64 %s does not enable rounding or SAE suffixes: %q", baseOp, ins.Raw)
	}
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires K1-K7: %q", baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s destination must be X, Y, or Z: %q", baseOp, ins.Raw)
	}
	destBytes := amd64VectorByteWidth(destination.Reg)
	if (destBytes != 16 && destBytes != 32 && destBytes != 64) || !c.isGoEVEXVectorRegister(destination, destBytes) {
		return true, false, fmt.Errorf("%s %s destination is outside Go 1.27's vector class: %q", c.goarch, baseOp, ins.Raw)
	}
	resultLanes := destBytes / 8
	sourceRegisterBytes := 16
	if destBytes == 64 {
		sourceRegisterBytes = 32
	}
	source := ins.Args[0]
	if suffixes.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a scalar memory source: %q", baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, sourceRegisterBytes) {
			return true, false, fmt.Errorf("amd64 %s source width does not match its destination: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}

	var integers string
	if suffixes.broadcast {
		scalar, err := c.evalIntSized(source, I32)
		if err != nil {
			return true, false, err
		}
		integers = amd64SplatInteger(c, resultLanes, 32, scalar)
	} else {
		loaded, err := c.loadPackedExtendInputs(source, sourceRegisterBytes, resultLanes, 32)
		if err != nil {
			return true, false, err
		}
		integers = loaded
	}
	converted := c.newTmp()
	floats := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sitofp <%d x i32> %s to <%d x double>\n", converted, resultLanes, integers, resultLanes)
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x double> %%%s to <%d x i64>\n", floats, resultLanes, converted, resultLanes)
	result := "%" + floats
	if masked {
		mask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, destBytes)
		if err != nil {
			return true, false, err
		}
		old := c.bitcastVectorBytesToIntegerLanes(destBytes, resultLanes, 64, oldBytes)
		result = amd64ApplyIntegerLaneMask(c, resultLanes, 64, result, old, mask, suffixes.zeroing)
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i64> %s to <%d x i8>\n", out, resultLanes, result, destBytes)
	return true, false, c.storeVectorBytes(destination.Reg, destBytes, "%"+out)
}

func (c *amd64Ctx) lowerVectorPackedDoubleToDword(baseOp string, spec amd64PackedDoubleDwordSpec, ins Instr, suffixes amd64PackedDoubleDwordSuffix) (bool, bool, error) {
	if len(ins.Args) != 2 && len(ins.Args) != 3 {
		return true, false, fmt.Errorf("amd64 %s expects source, [K mask,] destination: %q", baseOp, ins.Raw)
	}
	masked := len(ins.Args) == 3
	if suffixes.zeroing && !masked {
		return true, false, fmt.Errorf("amd64 %s .Z requires K1-K7: %q", baseOp, ins.Raw)
	}
	if masked && !amd64NonzeroKOperand(ins.Args[1]) {
		return true, false, fmt.Errorf("amd64 %s masked form expects K1-K7: %q", baseOp, ins.Raw)
	}
	if suffixes.rounding != "" && spec.explicitMode != "rounding" {
		return true, false, fmt.Errorf("amd64 %s does not enable explicit rounding: %q", baseOp, ins.Raw)
	}
	if suffixes.sae && spec.explicitMode != "sae" {
		return true, false, fmt.Errorf("amd64 %s does not enable SAE: %q", baseOp, ins.Raw)
	}
	destination := ins.Args[len(ins.Args)-1]
	if destination.Kind != OpReg || amd64VectorByteWidth(destination.Reg) != spec.destBytes || !c.isGoEVEXVectorRegister(destination, spec.destBytes) {
		return true, false, fmt.Errorf("amd64 %s destination does not match its X/Y result class: %q", baseOp, ins.Raw)
	}
	source := ins.Args[0]
	if suffixes.broadcast {
		if !isAMD64MemoryOperand(source) {
			return true, false, fmt.Errorf("amd64 %s.BCST requires a scalar memory source: %q", baseOp, ins.Raw)
		}
	} else if source.Kind == OpReg {
		if !c.isGoEVEXVectorRegister(source, spec.sourceBytes) {
			return true, false, fmt.Errorf("amd64 %s source width does not match its form: %q", baseOp, ins.Raw)
		}
	} else if !isAMD64MemoryOperand(source) {
		return true, false, fmt.Errorf("amd64 %s source must be a matching vector register or memory: %q", baseOp, ins.Raw)
	}
	if (suffixes.rounding != "" || suffixes.sae) && source.Kind != OpReg {
		return true, false, fmt.Errorf("amd64 %s explicit rounding/SAE requires a register source: %q", baseOp, ins.Raw)
	}

	doubles, err := c.loadPackedDoubleValues(source, spec.sourceBytes, spec.resultLanes, suffixes.broadcast)
	if err != nil {
		return true, false, err
	}
	result := c.emitPackedDoubleToDword(doubles, spec.resultLanes, spec.truncate, suffixes.rounding)
	if masked {
		mask, err := c.loadK(ins.Args[1].Reg)
		if err != nil {
			return true, false, err
		}
		oldBytes, err := c.loadPackedCompareBytes(destination, spec.destBytes)
		if err != nil {
			return true, false, err
		}
		physicalLanes := spec.destBytes / 4
		old := c.bitcastVectorBytesToIntegerLanes(spec.destBytes, physicalLanes, 32, oldBytes)
		if physicalLanes != spec.resultLanes {
			old = c.lowIntegerLanes(old, physicalLanes, spec.resultLanes, 32)
		}
		result = amd64ApplyIntegerLaneMask(c, spec.resultLanes, 32, result, old, mask, suffixes.zeroing)
	}
	return true, false, c.storePackedDwordConversionResult(destination.Reg, spec.destBytes, spec.resultLanes, result)
}

func (c *amd64Ctx) loadPackedDoubleValues(source Operand, sourceBytes, lanes int, broadcast bool) (string, error) {
	if broadcast {
		scalar, err := c.evalF64(source)
		if err != nil {
			return "", err
		}
		seed := c.newTmp()
		splat := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x double> poison, double %s, i32 0\n", seed, lanes, scalar)
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x double> %%%s, <%d x double> poison, <%d x i32> zeroinitializer\n", splat, lanes, seed, lanes, lanes)
		return "%" + splat, nil
	}
	bytes, err := c.loadPackedCompareBytes(source, sourceBytes)
	if err != nil {
		return "", err
	}
	cast := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i8> %s to <%d x double>\n", cast, sourceBytes, bytes, lanes)
	return "%" + cast, nil
}

func (c *amd64Ctx) emitPackedDoubleToDword(doubles string, lanes int, truncate bool, rounding string) string {
	result := "poison"
	for lane := 0; lane < lanes; lane++ {
		value := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x double> %s, i32 %d\n", value, lanes, doubles, lane)
		rounded := c.newTmp()
		switch {
		case truncate || rounding == "RZ_SAE":
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.trunc.f64(double %%%s)\n", rounded, value)
		case rounding == "RN_SAE":
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.roundeven.f64(double %%%s)\n", rounded, value)
		case rounding == "RD_SAE":
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.floor.f64(double %%%s)\n", rounded, value)
		case rounding == "RU_SAE":
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.ceil.f64(double %%%s)\n", rounded, value)
		default:
			fmt.Fprintf(c.b, "  %%%s = call double @llvm.rint.f64(double %%%s)\n", rounded, value)
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call i32 @llvm.fptosi.sat.i32.f64(double %%%s)\n", converted, rounded)
		lower := c.newTmp()
		upper := c.newTmp()
		valid := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fcmp oge double %%%s, -2.147483648000000e+09\n", lower, rounded)
		fmt.Fprintf(c.b, "  %%%s = fcmp olt double %%%s, 2.147483648000000e+09\n", upper, rounded)
		fmt.Fprintf(c.b, "  %%%s = and i1 %%%s, %%%s\n", valid, lower, upper)
		selected := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i32 %%%s, i32 -2147483648\n", selected, valid, converted)
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i32> %s, i32 %%%s, i32 %d\n", inserted, lanes, result, selected, lane)
		result = "%" + inserted
	}
	return result
}

func (c *amd64Ctx) lowIntegerLanes(value string, physicalLanes, resultLanes, laneBits int) string {
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %s, <%d x i%d> poison, <%d x i32> <", low, physicalLanes, laneBits, value, physicalLanes, laneBits, resultLanes)
	for lane := 0; lane < resultLanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", lane)
	}
	c.b.WriteString(">\n")
	return "%" + low
}

func (c *amd64Ctx) storePackedDwordConversionResult(destination Reg, destBytes, resultLanes int, result string) error {
	physicalLanes := destBytes / 4
	if physicalLanes != resultLanes {
		widened := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i32> %s, <%d x i32> zeroinitializer, <%d x i32> <", widened, resultLanes, result, resultLanes, physicalLanes)
		for lane := 0; lane < physicalLanes; lane++ {
			if lane != 0 {
				c.b.WriteString(", ")
			}
			fmt.Fprintf(c.b, "i32 %d", lane)
		}
		c.b.WriteString(">\n")
		result = "%" + widened
	}
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i32> %s to <%d x i8>\n", out, physicalLanes, result, destBytes)
	return c.storeVectorBytes(destination, destBytes, "%"+out)
}
