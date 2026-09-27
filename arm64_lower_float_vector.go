package plan9asm

import (
	"fmt"
	"strconv"
	"strings"
)

type arm64VectorArrangement struct {
	elementBits int
	lanes       int
}

func parseARM64VectorArrangement(reg Reg) (arm64VectorArrangement, bool) {
	s := strings.ToUpper(strings.TrimSpace(string(reg)))
	dot := strings.IndexByte(s, '.')
	if dot < 2 || dot+2 >= len(s) {
		return arm64VectorArrangement{}, false
	}
	if _, ok := arm64ParseVReg(reg); !ok {
		return arm64VectorArrangement{}, false
	}
	kind := s[dot+1]
	lanes, err := strconv.Atoi(s[dot+2:])
	if err != nil {
		return arm64VectorArrangement{}, false
	}
	elementBits := 0
	switch kind {
	case 'B':
		elementBits = 8
	case 'H':
		elementBits = 16
	case 'S':
		elementBits = 32
	case 'D':
		elementBits = 64
	default:
		return arm64VectorArrangement{}, false
	}
	if lanes*elementBits != 64 && lanes*elementBits != 128 {
		return arm64VectorArrangement{}, false
	}
	return arm64VectorArrangement{elementBits: elementBits, lanes: lanes}, true
}

func (c *arm64Ctx) loadARM64VectorFloat(reg Reg, arrangement arm64VectorArrangement) (string, error) {
	bytesValue, err := c.loadVReg(reg)
	if err != nil {
		return "", err
	}
	physicalLanes := 128 / arrangement.elementBits
	floatType := "float"
	if arrangement.elementBits == 16 {
		floatType = "half"
	} else if arrangement.elementBits == 64 {
		floatType = "double"
	}
	all := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", all, bytesValue, physicalLanes, floatType)
	if arrangement.lanes == physicalLanes {
		return "%" + all, nil
	}
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> <", low, physicalLanes, floatType, all, physicalLanes, floatType, arrangement.lanes)
	for i := 0; i < arrangement.lanes; i++ {
		if i != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", i)
	}
	c.b.WriteString(">\n")
	return "%" + low, nil
}

func (c *arm64Ctx) storeARM64VectorFloat(reg Reg, arrangement arm64VectorArrangement, value string) error {
	floatType := "float"
	if arrangement.elementBits == 16 {
		floatType = "half"
	} else if arrangement.elementBits == 64 {
		floatType = "double"
	}
	activeBytes := arrangement.lanes * arrangement.elementBits / 8
	if activeBytes == 16 {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %s to <16 x i8>\n", out, arrangement.lanes, floatType, value)
		return c.storeVReg(reg, "%"+out)
	}
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x %s> %s to i64\n", low, arrangement.lanes, floatType, value)
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %%%s, i32 0\n", wide, low)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, wide)
	return c.storeVReg(reg, "%"+out)
}

func (c *arm64Ctx) loadARM64VectorInteger(reg Reg, arrangement arm64VectorArrangement) (string, error) {
	bytesValue, err := c.loadVReg(reg)
	if err != nil {
		return "", err
	}
	physicalLanes := 128 / arrangement.elementBits
	all := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x i%d>\n", all, bytesValue, physicalLanes, arrangement.elementBits)
	if arrangement.lanes == physicalLanes {
		return "%" + all, nil
	}
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x i%d> %%%s, <%d x i%d> poison, <%d x i32> <", low, physicalLanes, arrangement.elementBits, all, physicalLanes, arrangement.elementBits, arrangement.lanes)
	for i := 0; i < arrangement.lanes; i++ {
		if i != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", i)
	}
	c.b.WriteString(">\n")
	return "%" + low, nil
}

func (c *arm64Ctx) storeARM64VectorInteger(reg Reg, arrangement arm64VectorArrangement, value string) error {
	activeBytes := arrangement.lanes * arrangement.elementBits / 8
	if activeBytes == 16 {
		out := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to <16 x i8>\n", out, arrangement.lanes, arrangement.elementBits, value)
		return c.storeVReg(reg, "%"+out)
	}
	low := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %s to i64\n", low, arrangement.lanes, arrangement.elementBits, value)
	wide := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %%%s, i32 0\n", wide, low)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, wide)
	return c.storeVReg(reg, "%"+out)
}

func (c *arm64Ctx) lowerARM64VectorIntegerAddSub(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VADD" && op != "VSUB" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || (len(ins.Args) != 2 && len(ins.Args) != 3) {
		return true, false, fmt.Errorf("arm64 %s expects two bare V registers or three same-arrangement vector registers: %q", op, ins.Raw)
	}

	arranged := strings.Contains(string(ins.Args[0].Reg), ".")
	if arranged {
		if len(ins.Args) != 3 {
			return true, false, fmt.Errorf("arm64 %s arranged form requires three operands: %q", op, ins.Raw)
		}
		allowed := func(a arm64VectorArrangement) bool {
			return (a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)) ||
				(a.elementBits == 16 && (a.lanes == 4 || a.lanes == 8)) ||
				(a.elementBits == 32 && (a.lanes == 2 || a.lanes == 4)) ||
				(a.elementBits == 64 && a.lanes == 2)
		}
		var arrangement arm64VectorArrangement
		for i, arg := range ins.Args {
			if arg.Kind != OpReg {
				return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
			}
			parsed, valid := parseARM64VectorArrangement(arg.Reg)
			if !valid || !allowed(parsed) {
				return true, false, fmt.Errorf("arm64 %s has an invalid vector arrangement: %q", op, ins.Raw)
			}
			if i == 0 {
				arrangement = parsed
			} else if parsed != arrangement {
				return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
			}
		}
		source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		base, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		operation := "add"
		if op == "VSUB" {
			operation = "sub"
		}
		fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %s, %s\n", result, operation, arrangement.lanes, arrangement.elementBits, base, source)
		return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+result)
	}

	for _, arg := range ins.Args {
		if arg.Kind != OpReg || strings.Contains(string(arg.Reg), ".") {
			return true, false, fmt.Errorf("arm64 %s scalar SIMD form requires bare V registers: %q", op, ins.Raw)
		}
		if _, valid := arm64ParseVReg(arg.Reg); !valid {
			return true, false, fmt.Errorf("arm64 %s scalar SIMD form requires bare V registers: %q", op, ins.Raw)
		}
	}
	sourceBytes, err := c.loadVReg(ins.Args[0].Reg)
	if err != nil {
		return true, false, err
	}
	baseIndex := 1
	destinationIndex := 1
	if len(ins.Args) == 3 {
		destinationIndex = 2
	}
	baseBytes, err := c.loadVReg(ins.Args[baseIndex].Reg)
	if err != nil {
		return true, false, err
	}
	sourceWords := c.newTmp()
	baseWords := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", sourceWords, sourceBytes)
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", baseWords, baseBytes)
	sourceLow := c.newTmp()
	baseLow := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", sourceLow, sourceWords)
	fmt.Fprintf(c.b, "  %%%s = extractelement <2 x i64> %%%s, i32 0\n", baseLow, baseWords)
	resultLow := c.newTmp()
	operation := "add"
	if op == "VSUB" {
		operation = "sub"
	}
	fmt.Fprintf(c.b, "  %%%s = %s i64 %%%s, %%%s\n", resultLow, operation, baseLow, sourceLow)
	resultWords := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <2 x i64> zeroinitializer, i64 %%%s, i32 0\n", resultWords, resultLow)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %%%s to <16 x i8>\n", out, resultWords)
	return true, false, c.storeVReg(ins.Args[destinationIndex].Reg, "%"+out)
}

func (c *arm64Ctx) lowerARM64AddAcross(op Op, ins Instr) (ok bool, terminated bool, err error) {
	switch op {
	case "VADDV":
		// handled below
	default:
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 VADDV expects arranged vector source and bare V destination: %q", ins.Raw)
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[0].Reg)
	if !valid || !((arrangement.elementBits == 8 && (arrangement.lanes == 8 || arrangement.lanes == 16)) ||
		(arrangement.elementBits == 16 && (arrangement.lanes == 4 || arrangement.lanes == 8)) ||
		(arrangement.elementBits == 32 && arrangement.lanes == 4)) {
		return true, false, fmt.Errorf("arm64 VADDV accepts only B8, B16, H4, H8, or S4 source: %q", ins.Raw)
	}
	if strings.Contains(string(ins.Args[1].Reg), ".") {
		return true, false, fmt.Errorf("arm64 VADDV destination must be a bare V register: %q", ins.Raw)
	}
	if _, ok := arm64ParseVReg(ins.Args[1].Reg); !ok {
		return true, false, fmt.Errorf("arm64 VADDV destination must be a bare V register: %q", ins.Raw)
	}

	lanes, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	sum := "0"
	for lane := 0; lane < arrangement.lanes; lane++ {
		element := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <%d x i%d> %s, i32 %d\n", element, arrangement.lanes, arrangement.elementBits, lanes, lane)
		added := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add i%d %s, %%%s\n", added, arrangement.elementBits, sum, element)
		sum = "%" + added
	}
	physicalLanes := 128 / arrangement.elementBits
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertelement <%d x i%d> zeroinitializer, i%d %s, i32 0\n", result, physicalLanes, arrangement.elementBits, arrangement.elementBits, sum)
	out := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <%d x i%d> %%%s to <16 x i8>\n", out, physicalLanes, arrangement.elementBits, result)
	return true, false, c.storeVReg(ins.Args[1].Reg, "%"+out)
}

func (c *arm64Ctx) lowerARM64VectorFloatArithmetic(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerARM64VectorFloatArithmeticForm(op, ins, false)
}

func (c *arm64Ctx) lowerARM64VectorFloatArithmeticForm(op Op, ins Instr, allowRawHalf bool) (ok bool, terminated bool, err error) {
	type operationSpec struct {
		operation string
		pairwise  bool
	}
	specs := map[Op]operationSpec{
		"VFADD":    {operation: "add"},
		"VFSUB":    {operation: "sub"},
		"VFMUL":    {operation: "mul"},
		"VFDIV":    {operation: "div"},
		"VFMAX":    {operation: "maximum"},
		"VFMAXNM":  {operation: "maxnum"},
		"VFMIN":    {operation: "minimum"},
		"VFMINNM":  {operation: "minnum"},
		"VFABD":    {operation: "fabd"},
		"VFMULX":   {operation: "fmulx"},
		"VFADDP":   {operation: "add", pairwise: true},
		"VFMAXP":   {operation: "maximum", pairwise: true},
		"VFMAXNMP": {operation: "maxnum", pairwise: true},
		"VFMINP":   {operation: "minimum", pairwise: true},
		"VFMINNMP": {operation: "minnum", pairwise: true},
	}
	spec, handled := specs[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || !((allowRawHalf && parsed.elementBits == 16 && (parsed.lanes == 4 || parsed.lanes == 8)) ||
			(parsed.elementBits == 32 && (parsed.lanes == 2 || parsed.lanes == 4)) ||
			(parsed.elementBits == 64 && parsed.lanes == 2)) {
			return true, false, fmt.Errorf("arm64 %s has an unsupported vector arrangement: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	first, err := c.loadARM64VectorFloat(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorFloat(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	floatType, intrinsicSuffix, _ := arm64ScalarFloatType(arrangement.elementBits)
	result := ""
	if !spec.pairwise {
		computed := c.newTmp()
		switch spec.operation {
		case "add", "sub", "mul", "div":
			fmt.Fprintf(c.b, "  %%%s = f%s <%d x %s> %s, %s\n", computed, spec.operation, arrangement.lanes, floatType, second, first)
		case "fabd", "fmulx":
			fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.aarch64.neon.%s.v%d%s(<%d x %s> %s, <%d x %s> %s)\n",
				computed, arrangement.lanes, floatType, spec.operation, arrangement.lanes, intrinsicSuffix,
				arrangement.lanes, floatType, second, arrangement.lanes, floatType, first)
		default:
			fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.v%d%s(<%d x %s> %s, <%d x %s> %s)\n",
				computed, arrangement.lanes, floatType, spec.operation, arrangement.lanes, intrinsicSuffix,
				arrangement.lanes, floatType, second, arrangement.lanes, floatType, first)
		}
		result = "%" + computed
	} else {
		result = "poison"
		half := arrangement.lanes / 2
		for lane := 0; lane < arrangement.lanes; lane++ {
			source := second
			if lane >= half {
				source = first
			}
			pair := (lane % half) * 2
			left := c.newTmp()
			right := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", left, arrangement.lanes, floatType, source, pair)
			fmt.Fprintf(c.b, "  %%%s = extractelement <%d x %s> %s, i32 %d\n", right, arrangement.lanes, floatType, source, pair+1)
			combined := c.newTmp()
			if spec.operation == "add" {
				fmt.Fprintf(c.b, "  %%%s = fadd %s %%%s, %%%s\n", combined, floatType, left, right)
			} else {
				fmt.Fprintf(c.b, "  %%%s = call %s @llvm.%s.%s(%s %%%s, %s %%%s)\n", combined, floatType, spec.operation, intrinsicSuffix, floatType, left, floatType, right)
			}
			inserted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = insertelement <%d x %s> %s, %s %%%s, i32 %d\n", inserted, arrangement.lanes, floatType, result, floatType, combined, lane)
			result = "%" + inserted
		}
	}
	return true, false, c.storeARM64VectorFloat(ins.Args[2].Reg, arrangement, result)
}

func (c *arm64Ctx) lowerARM64VectorFloatUnary(op Op, ins Instr) (ok bool, terminated bool, err error) {
	operations := map[Op]string{
		"VFABS":   "fabs",
		"VFNEG":   "neg",
		"VFSQRT":  "sqrt",
		"VFRINTN": "roundeven",
		"VFRINTP": "ceil",
		"VFRINTM": "floor",
		"VFRINTZ": "trunc",
		"VFCVTZS": "fptosi.sat",
		"VFCVTZU": "fptoui.sat",
		"VFCVTNS": "fptosi.roundeven.sat",
		"VFCVTNU": "fptoui.roundeven.sat",
		"VFCVTMS": "fptosi.floor.sat",
		"VFCVTMU": "fptoui.floor.sat",
		"VFCVTAS": "fptosi.round.sat",
		"VFCVTAU": "fptoui.round.sat",
		"VFCVTPS": "fptosi.ceil.sat",
		"VFCVTPU": "fptoui.ceil.sat",
		"VSCVTF":  "sitofp",
		"VUCVTF":  "uitofp",
	}
	operation, handled := operations[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects two same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	sourceArrangement, sourceValid := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationValid := parseARM64VectorArrangement(ins.Args[1].Reg)
	if !sourceValid || !destinationValid || sourceArrangement != destinationArrangement ||
		!((sourceArrangement.elementBits == 32 && (sourceArrangement.lanes == 2 || sourceArrangement.lanes == 4)) ||
			(sourceArrangement.elementBits == 64 && sourceArrangement.lanes == 2)) {
		return true, false, fmt.Errorf("arm64 %s requires matching S2, S4, or D2 arrangements: %q", op, ins.Raw)
	}
	arrangement := sourceArrangement
	floatType := "float"
	floatSuffix := "f32"
	if arrangement.elementBits == 64 {
		floatType, floatSuffix = "double", "f64"
	}
	vectorFloatSuffix := fmt.Sprintf("v%d%s", arrangement.lanes, floatSuffix)
	vectorIntegerSuffix := fmt.Sprintf("v%di%d", arrangement.lanes, arrangement.elementBits)

	switch operation {
	case "sitofp", "uitofp":
		source, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s <%d x i%d> %s to <%d x %s>\n", converted, operation, arrangement.lanes, arrangement.elementBits, source, arrangement.lanes, floatType)
		return true, false, c.storeARM64VectorFloat(ins.Args[1].Reg, arrangement, "%"+converted)
	case "fptosi.sat", "fptoui.sat",
		"fptosi.roundeven.sat", "fptoui.roundeven.sat",
		"fptosi.floor.sat", "fptoui.floor.sat",
		"fptosi.round.sat", "fptoui.round.sat",
		"fptosi.ceil.sat", "fptoui.ceil.sat":
		source, err := c.loadARM64VectorFloat(ins.Args[0].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		roundingIntrinsic := ""
		switch {
		case strings.Contains(operation, ".roundeven."):
			roundingIntrinsic = "roundeven"
		case strings.Contains(operation, ".floor."):
			roundingIntrinsic = "floor"
		case strings.Contains(operation, ".round."):
			roundingIntrinsic = "round"
		case strings.Contains(operation, ".ceil."):
			roundingIntrinsic = "ceil"
		}
		if roundingIntrinsic != "" {
			rounded := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.%s(<%d x %s> %s)\n",
				rounded, arrangement.lanes, floatType, roundingIntrinsic, vectorFloatSuffix,
				arrangement.lanes, floatType, source)
			source = "%" + rounded
		}
		conversionIntrinsic := "fptosi.sat"
		if strings.HasPrefix(operation, "fptoui") {
			conversionIntrinsic = "fptoui.sat"
		}
		converted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = call <%d x i%d> @llvm.%s.%s.%s(<%d x %s> %s)\n",
			converted, arrangement.lanes, arrangement.elementBits, conversionIntrinsic, vectorIntegerSuffix, vectorFloatSuffix,
			arrangement.lanes, floatType, source)
		return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, arrangement, "%"+converted)
	default:
		source, err := c.loadARM64VectorFloat(ins.Args[0].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		result := c.newTmp()
		if operation == "neg" {
			fmt.Fprintf(c.b, "  %%%s = fneg <%d x %s> %s\n", result, arrangement.lanes, floatType, source)
		} else {
			fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.%s.%s(<%d x %s> %s)\n", result, arrangement.lanes, floatType, operation, vectorFloatSuffix, arrangement.lanes, floatType, source)
		}
		return true, false, c.storeARM64VectorFloat(ins.Args[1].Reg, arrangement, "%"+result)
	}
}

func (c *arm64Ctx) lowerARM64VectorShiftRight(op Op, ins Instr) (ok bool, terminated bool, err error) {
	type shiftRightSpec struct {
		signed     bool
		rounding   bool
		accumulate bool
	}
	spec, handled := map[Op]shiftRightSpec{
		"VSSHR":  {signed: true},
		"VSSRA":  {signed: true, accumulate: true},
		"VSRSHR": {signed: true, rounding: true},
		"VSRSRA": {signed: true, rounding: true, accumulate: true},
		"VUSHR":  {},
		"VUSRA":  {accumulate: true},
		"VURSHR": {rounding: true},
		"VURSRA": {rounding: true, accumulate: true},
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 || ins.Args[0].Kind != OpImm || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects $shift, Vsrc.<T>, Vdst.<T> and no suffix: %q", op, ins.Raw)
	}
	scalar := !strings.Contains(string(ins.Args[1].Reg), ".") && !strings.Contains(string(ins.Args[2].Reg), ".")
	sourceArrangement, sourceValid := parseARM64VectorArrangement(ins.Args[1].Reg)
	destinationArrangement, destinationValid := parseARM64VectorArrangement(ins.Args[2].Reg)
	if scalar {
		_, sourceValid = arm64ParseVReg(ins.Args[1].Reg)
		_, destinationValid = arm64ParseVReg(ins.Args[2].Reg)
		sourceArrangement = arm64VectorArrangement{elementBits: 64, lanes: 1}
		destinationArrangement = sourceArrangement
	}
	allowed := func(a arm64VectorArrangement) bool {
		return (a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)) ||
			(a.elementBits == 16 && (a.lanes == 4 || a.lanes == 8)) ||
			(a.elementBits == 32 && (a.lanes == 2 || a.lanes == 4)) ||
			(a.elementBits == 64 && a.lanes == 2)
	}
	if !sourceValid || !destinationValid || sourceArrangement != destinationArrangement || !scalar && !allowed(sourceArrangement) {
		return true, false, fmt.Errorf("arm64 %s requires a matching bare scalar D form or B8/B16/H4/H8/S2/S4/D2 vector arrangements: %q", op, ins.Raw)
	}
	if ins.Args[0].Imm < 1 || ins.Args[0].Imm > int64(sourceArrangement.elementBits) {
		return true, false, fmt.Errorf("arm64 %s shift must be in [1,%d]: %q", op, sourceArrangement.elementBits, ins.Raw)
	}
	source, err := c.loadARM64VectorInteger(ins.Args[1].Reg, sourceArrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i%d>", sourceArrangement.lanes, sourceArrangement.elementBits)
	if scalar {
		extracted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i64> %s, i32 0\n", extracted, source)
		source = "%" + extracted
		vectorType = "i64"
	}
	shiftValue := func(amount int64) string {
		if scalar {
			return fmt.Sprintf("%d", amount)
		}
		return arm64VectorIntegerSplat(sourceArrangement, amount)
	}
	zero := "zeroinitializer"
	if scalar {
		zero = "0"
	}
	emitShift := func(value string, amount int64, signed bool) string {
		if amount >= int64(sourceArrangement.elementBits) && !signed {
			return zero
		}
		if amount >= int64(sourceArrangement.elementBits) {
			amount = int64(sourceArrangement.elementBits - 1) // ASR by the element width is the replicated sign bit.
		}
		result := c.newTmp()
		operation := "lshr"
		if signed {
			operation = "ashr"
		}
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", result, operation, vectorType, value, shiftValue(amount))
		return "%" + result
	}
	result := emitShift(source, ins.Args[0].Imm, spec.signed)
	if spec.rounding {
		roundingBit := emitShift(source, ins.Args[0].Imm-1, false)
		maskedBit := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", maskedBit, vectorType, roundingBit, shiftValue(1))
		rounded := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %%%s\n", rounded, vectorType, result, maskedBit)
		result = "%" + rounded
	}
	if spec.accumulate {
		destination, err := c.loadARM64VectorInteger(ins.Args[2].Reg, destinationArrangement)
		if err != nil {
			return true, false, err
		}
		if scalar {
			extracted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i64> %s, i32 0\n", extracted, destination)
			destination = "%" + extracted
		}
		accumulated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = add %s %s, %s\n", accumulated, vectorType, destination, result)
		result = "%" + accumulated
	}
	if scalar {
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i64> zeroinitializer, i64 %s, i32 0\n", inserted, result)
		result = "%" + inserted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, sourceArrangement, result)
}

func (c *arm64Ctx) lowerARM64VectorIntegerCompare(op Op, ins Instr) (ok bool, terminated bool, err error) {
	predicates := map[Op]string{
		"VCMEQ": "eq",
		"VCMGE": "sge",
		"VCMGT": "sgt",
		"VCMLE": "sle",
		"VCMLT": "slt",
		"VCMHI": "ugt",
		"VCMHS": "uge",
	}
	predicate, handled := predicates[op]
	testBits := op == "VCMTST"
	if !handled && !testBits {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects register compare or $0 compare form and no suffix: %q", op, ins.Raw)
	}
	zeroForm := ins.Args[0].Kind == OpImm
	if testBits && (zeroForm || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg) {
		return true, false, fmt.Errorf("arm64 VCMTST requires three vector registers: %q", ins.Raw)
	}
	if zeroForm {
		if op == "VCMHI" || op == "VCMHS" || ins.Args[0].Imm != 0 || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s immediate compare requires exactly $0, Vsrc.<T>, Vdst.<T>: %q", op, ins.Raw)
		}
	} else {
		if op == "VCMLE" || op == "VCMLT" || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg || ins.Args[2].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s register compare form is absent from Go 1.27's optab: %q", op, ins.Raw)
		}
	}

	sourceIndex := 1
	if !zeroForm {
		sourceIndex = 0
	}
	arrangement, valid := parseARM64VectorArrangement(ins.Args[sourceIndex].Reg)
	allowed := func(a arm64VectorArrangement) bool {
		return (a.elementBits == 8 && (a.lanes == 8 || a.lanes == 16)) ||
			(a.elementBits == 16 && (a.lanes == 4 || a.lanes == 8)) ||
			(a.elementBits == 32 && (a.lanes == 2 || a.lanes == 4)) ||
			(a.elementBits == 64 && a.lanes == 2)
	}
	if !valid || !allowed(arrangement) {
		return true, false, fmt.Errorf("arm64 %s has invalid vector arrangement: %q", op, ins.Raw)
	}
	start := 1
	if !zeroForm {
		start = 0
	}
	for i := start; i < len(ins.Args); i++ {
		parsed, ok := parseARM64VectorArrangement(ins.Args[i].Reg)
		if !ok || parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	left, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	right := "zeroinitializer"
	if !zeroForm {
		right, err = c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
	}
	compared := c.newTmp()
	if testBits {
		vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
		masked := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = and %s %s, %s\n", masked, vectorType, left, right)
		fmt.Fprintf(c.b, "  %%%s = icmp ne %s %%%s, zeroinitializer\n", compared, vectorType, masked)
	} else {
		fmt.Fprintf(c.b, "  %%%s = icmp %s <%d x i%d> %s, %s\n", compared, predicate, arrangement.lanes, arrangement.elementBits, left, right)
	}
	allBits := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = sext <%d x i1> %%%s to <%d x i%d>\n", allBits, arrangement.lanes, compared, arrangement.lanes, arrangement.elementBits)
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, "%"+allBits)
}

func (c *arm64Ctx) lowerARM64VectorLogical(op Op, ins Instr) (ok bool, terminated bool, err error) {
	handled := false
	for _, candidate := range []Op{"VAND", "VORR", "VEOR", "VBIC", "VORN", "VBSL", "VBIT", "VBIF", "VNOT"} {
		if op == candidate {
			handled = true
			break
		}
	}
	if !handled {
		return false, false, nil
	}
	if op == "VNOT" {
		if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
			return true, false, fmt.Errorf("arm64 VNOT expects source and destination B8/B16 vector registers and no suffix: %q", ins.Raw)
		}
		source, sourceValid := parseARM64VectorArrangement(ins.Args[0].Reg)
		destination, destinationValid := parseARM64VectorArrangement(ins.Args[1].Reg)
		if !sourceValid || !destinationValid || source != destination || source.elementBits != 8 || (source.lanes != 8 && source.lanes != 16) {
			return true, false, fmt.Errorf("arm64 VNOT accepts matching B8 or B16 arrangements: %q", ins.Raw)
		}
		value, err := c.loadARM64VectorInteger(ins.Args[0].Reg, source)
		if err != nil {
			return true, false, err
		}
		vectorType := fmt.Sprintf("<%d x i8>", source.lanes)
		ones := "<" + strings.TrimSuffix(strings.Repeat("i8 -1, ", source.lanes), ", ") + ">"
		result := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor %s %s, %s\n", result, vectorType, value, ones)
		return true, false, c.storeARM64VectorInteger(ins.Args[1].Reg, destination, "%"+result)
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three matching B8/B16 vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || parsed.elementBits != 8 || (parsed.lanes != 8 && parsed.lanes != 16) {
			return true, false, fmt.Errorf("arm64 %s accepts only B8 or B16 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	first, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	vectorType := fmt.Sprintf("<%d x i8>", arrangement.lanes)
	result := ""
	emitBinary := func(operation, left, right string) string {
		name := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = %s %s %s, %s\n", name, operation, vectorType, left, right)
		return "%" + name
	}
	emitNot := func(value string) string {
		return emitBinary("xor", value, "<"+strings.TrimSuffix(strings.Repeat("i8 -1, ", arrangement.lanes), ", ")+">")
	}
	switch op {
	case "VAND":
		result = emitBinary("and", second, first)
	case "VORR":
		result = emitBinary("or", second, first)
	case "VEOR":
		result = emitBinary("xor", second, first)
	case "VBIC":
		result = emitBinary("and", second, emitNot(first))
	case "VORN":
		result = emitBinary("or", second, emitNot(first))
	case "VBSL", "VBIT", "VBIF":
		old, err := c.loadARM64VectorInteger(ins.Args[2].Reg, arrangement)
		if err != nil {
			return true, false, err
		}
		var mask, whenTrue, whenFalse string
		switch op {
		case "VBSL":
			mask, whenTrue, whenFalse = old, second, first
		case "VBIT":
			mask, whenTrue, whenFalse = first, second, old
		case "VBIF":
			mask, whenTrue, whenFalse = first, old, second
		}
		selected := emitBinary("and", mask, whenTrue)
		unselected := emitBinary("and", emitNot(mask), whenFalse)
		result = emitBinary("or", selected, unselected)
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, result)
}

func (c *arm64Ctx) lowerARM64VectorFloatWiden(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VFCVTL" && op != "VFCVTL2" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 2 || ins.Args[0].Kind != OpReg || ins.Args[1].Kind != OpReg {
		return true, false, fmt.Errorf("arm64 %s expects Vsrc.S%d, Vdst.D2 and no suffix: %q", op, map[bool]int{false: 2, true: 4}[op == "VFCVTL2"], ins.Raw)
	}
	sourceArrangement, sourceValid := parseARM64VectorArrangement(ins.Args[0].Reg)
	destinationArrangement, destinationValid := parseARM64VectorArrangement(ins.Args[1].Reg)
	wantSourceLanes := 2
	if op == "VFCVTL2" {
		wantSourceLanes = 4
	}
	if !sourceValid || sourceArrangement.elementBits != 32 || sourceArrangement.lanes != wantSourceLanes ||
		!destinationValid || destinationArrangement.elementBits != 64 || destinationArrangement.lanes != 2 {
		return true, false, fmt.Errorf("arm64 %s operand arrangements are outside Go 1.27's widening optab: %q", op, ins.Raw)
	}
	return true, false, c.lowerARM64VectorFloatWidenForm(32, op == "VFCVTL2", ins.Args[0].Reg, ins.Args[1].Reg)
}

func (c *arm64Ctx) lowerARM64VectorFloatWidenForm(sourceBits int, upper bool, sourceReg, destinationReg Reg) error {
	sourceBytes, err := c.loadVReg(sourceReg)
	if err != nil {
		return err
	}
	physicalLanes := 128 / sourceBits
	selectedLanes := physicalLanes / 2
	sourceType, destinationType := "half", "float"
	if sourceBits == 32 {
		sourceType, destinationType = "float", "double"
	}
	all := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <%d x %s>\n", all, sourceBytes, physicalLanes, sourceType)
	firstLane := 0
	if upper {
		firstLane = selectedLanes
	}
	selected := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = shufflevector <%d x %s> %%%s, <%d x %s> poison, <%d x i32> <",
		selected, physicalLanes, sourceType, all, physicalLanes, sourceType, selectedLanes)
	for lane := 0; lane < selectedLanes; lane++ {
		if lane != 0 {
			c.b.WriteString(", ")
		}
		fmt.Fprintf(c.b, "i32 %d", firstLane+lane)
	}
	c.b.WriteString(">\n")
	converted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = fpext <%d x %s> %%%s to <%d x %s>\n",
		converted, selectedLanes, sourceType, selected, selectedLanes, destinationType)
	return c.storeARM64VectorFloat(destinationReg,
		arm64VectorArrangement{elementBits: sourceBits * 2, lanes: selectedLanes}, "%"+converted)
}

func (c *arm64Ctx) lowerARM64VectorFMA(op Op, ins Instr) (ok bool, terminated bool, err error) {
	if op != "VFMLA" && op != "VFMLS" {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects three same-arrangement vector registers and no suffix: %q", op, ins.Raw)
	}
	var arrangement arm64VectorArrangement
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		parsed, ok := parseARM64VectorArrangement(arg.Reg)
		if !ok || !((parsed.elementBits == 32 && (parsed.lanes == 2 || parsed.lanes == 4)) || (parsed.elementBits == 64 && parsed.lanes == 2)) {
			return true, false, fmt.Errorf("arm64 %s accepts only S2, S4, or D2 arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}

	first, err := c.loadARM64VectorFloat(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	second, err := c.loadARM64VectorFloat(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	addend, err := c.loadARM64VectorFloat(ins.Args[2].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	floatType := "float"
	if arrangement.elementBits == 64 {
		floatType = "double"
	}
	if op == "VFMLS" {
		negated := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = fneg <%d x %s> %s\n", negated, arrangement.lanes, floatType, first)
		first = "%" + negated
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call <%d x %s> @llvm.fma.v%d%s(<%d x %s> %s, <%d x %s> %s, <%d x %s> %s)\n",
		result, arrangement.lanes, floatType, arrangement.lanes, map[int]string{32: "f32", 64: "f64"}[arrangement.elementBits],
		arrangement.lanes, floatType, first, arrangement.lanes, floatType, second, arrangement.lanes, floatType, addend)
	return true, false, c.storeARM64VectorFloat(ins.Args[2].Reg, arrangement, "%"+result)
}
