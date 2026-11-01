package plan9asm

import (
	"fmt"
	"strings"
)

type x86X87ValueKind uint8

const (
	x86X87FloatMove x86X87ValueKind = iota
	x86X87Constant
	x86X87Unary
	x86X87Exchange
	x86X87Arithmetic
	x86X87Compare
	x86X87Test
	x86X87Status
	x86X87IntegerMove
	x86X87Round
	x86X87ConditionalMove
)

type x86X87ValueSpec struct {
	kind        x86X87ValueKind
	width       byte // W/L/V signed integer memory, F/D floating memory, B/X ten-byte format.
	stem        string
	pop         uint8
	reverse     bool
	directFlags bool
	flags       uint8 // Required integer predicates; FCMOV preserves those flags.
}

// These are value-availability forms, not a physical x87 entry/control-word,
// native-memory or caller-state contract. The Go rows are shared by both x86
// modes. BCD/extended forms retain input obligations but no numerical value
// permission. Environment and transcendental state remain independent.
var x86X87ValueSpecs = func() map[Op]x86X87ValueSpec {
	forms := map[Op]x86X87ValueSpec{
		"FMOVD":   {kind: x86X87FloatMove, width: 'D'},
		"FMOVDP":  {kind: x86X87FloatMove, width: 'D', pop: 1},
		"FMOVF":   {kind: x86X87FloatMove, width: 'F'},
		"FMOVFP":  {kind: x86X87FloatMove, width: 'F', pop: 1},
		"FMOVB":   {kind: x86X87FloatMove, width: 'B'},
		"FMOVBP":  {kind: x86X87FloatMove, width: 'B', pop: 1},
		"FMOVX":   {kind: x86X87FloatMove, width: 'X'},
		"FMOVXP":  {kind: x86X87FloatMove, width: 'X', pop: 1},
		"FXCHD":   {kind: x86X87Exchange},
		"FTST":    {kind: x86X87Test},
		"FSTSW":   {kind: x86X87Status},
		"FMOVW":   {kind: x86X87IntegerMove, width: 'W'},
		"FMOVWP":  {kind: x86X87IntegerMove, width: 'W', pop: 1},
		"FMOVL":   {kind: x86X87IntegerMove, width: 'L'},
		"FMOVLP":  {kind: x86X87IntegerMove, width: 'L', pop: 1},
		"FMOVV":   {kind: x86X87IntegerMove, width: 'V'},
		"FMOVVP":  {kind: x86X87IntegerMove, width: 'V', pop: 1},
		"FRNDINT": {kind: x86X87Round},
	}
	for _, op := range []Op{"FLD1", "FLDL2E", "FLDL2T", "FLDLG2", "FLDLN2", "FLDPI", "FLDZ"} {
		forms[op] = x86X87ValueSpec{kind: x86X87Constant}
	}
	for _, op := range []Op{"FABS", "FCHS", "FSQRT"} {
		forms[op] = x86X87ValueSpec{kind: x86X87Unary}
	}
	for _, row := range []struct {
		ops   []Op
		flags uint8
	}{
		{[]Op{"FCMOVCC", "FCMOVCS", "FCMOVB", "FCMOVNB"}, x86ByteFlagCF},
		{[]Op{"FCMOVEQ", "FCMOVE", "FCMOVNE"}, x86ByteFlagZF},
		{[]Op{"FCMOVHI", "FCMOVLS", "FCMOVBE", "FCMOVNBE"}, x86ByteFlagCF | x86ByteFlagZF},
		{[]Op{"FCMOVNU", "FCMOVU", "FCMOVUN"}, x86ByteFlagPF},
	} {
		for _, op := range row.ops {
			forms[op] = x86X87ValueSpec{kind: x86X87ConditionalMove, flags: row.flags}
		}
	}
	for _, stem := range []string{"FADD", "FMUL", "FSUB", "FSUBR", "FDIV", "FDIVR"} {
		for _, suffix := range []string{"W", "L", "F", "D", "DP"} {
			spec := x86X87ValueSpec{kind: x86X87Arithmetic, width: suffix[0], stem: stem,
				reverse: stem == "FSUBR" || stem == "FDIVR"}
			if suffix == "DP" {
				spec.pop = 1
			}
			forms[Op(stem+suffix)] = spec
		}
	}
	for _, row := range []struct {
		op    Op
		width byte
		pop   uint8
	}{
		{"FCOMW", 'W', 0}, {"FCOMWP", 'W', 1},
		{"FCOML", 'L', 0}, {"FCOMLP", 'L', 1},
		{"FCOMF", 'F', 0}, {"FCOMFP", 'F', 1},
		{"FCOMD", 'D', 0}, {"FCOMDP", 'D', 1}, {"FCOMDPP", 'D', 2},
		{"FCOMI", 'D', 0}, {"FCOMIP", 'D', 1},
		{"FUCOM", 'D', 0}, {"FUCOMP", 'D', 1}, {"FUCOMPP", 'D', 2},
		{"FUCOMI", 'D', 0}, {"FUCOMIP", 'D', 1},
	} {
		forms[row.op] = x86X87ValueSpec{kind: x86X87Compare, width: row.width, pop: row.pop,
			directFlags: row.op == "FCOMI" || row.op == "FCOMIP" || row.op == "FUCOMI" || row.op == "FUCOMIP"}
	}
	return forms
}()

// Decoder spellings share the original BCD format. This projection neither
// rewrites the instruction nor grants a raw source or numerical entry role.
func x86X87ValueSpecForName(name Op) (x86X87ValueSpec, bool) {
	switch name {
	case "FBLD":
		name = "FMOVB"
	case "FBSTP":
		name = "FMOVBP"
	}
	spec, known := x86X87ValueSpecs[name]
	return spec, known
}

type x86X87ValueForm struct {
	spec                x86X87ValueSpec
	source, destination Operand
	left, right         Operand // Ordered comparison dependencies, independent of spelling.
	push                bool
	unprovedEncoding    bool // Go's documented botch row is not a NUM/effect witness.
}

func (form x86X87ValueForm) memoryBytes() int64 {
	switch form.spec.width {
	case 'W':
		return 2
	case 'L', 'F':
		return 4
	case 'D', 'V':
		return 8
	case 'B', 'X':
		return 10
	}
	return 0
}

// One actual instruction head selects the complete Go form. Source FLOAT
// rewrites are validated separately from the underlying memory encoding; a
// resolved integer immediate is not an x87 memory value.
func x86X87ValueProperties(ins Instr, arch string) (x86X87ValueForm, bool, error) {
	name, suffix, dotted := strings.Cut(strings.ToUpper(string(ins.Op)), ".")
	spec, known := x86X87ValueSpecForName(Op(name))
	if !known {
		return x86X87ValueForm{}, false, nil
	}
	form := x86X87ValueForm{spec: spec}
	fail := func(reason string) (x86X87ValueForm, bool, error) {
		return form, true, fmt.Errorf("%s %s %s: %q", arch, ins.Op, reason, ins.Raw)
	}
	if arch != "386" && arch != "amd64" || dotted || suffix != "" {
		return fail("is outside the Go x87 value mode/suffix grammar")
	}
	for _, operand := range ins.Args {
		// Ym's scalar address grammar is independent of MUL's numerical
		// effects or conditional native-read role.
		if err := x86NamedMultiplyMemoryError(operand, arch); err != nil {
			return fail(err.Error())
		}
	}
	memory := func(operand Operand) bool {
		if !isX87MemoryOperand(operand) {
			return false
		}
		if operand.Kind == OpSym {
			symbol := strings.TrimSpace(operand.Sym)
			_, integer := parseInt(symbol)
			return !strings.HasPrefix(symbol, "$") && (strings.HasSuffix(symbol, "(SB)") || integer == nil)
		}
		return true
	}
	constant := func(operand Operand) bool {
		return operand.Kind == OpImm && (spec.width == 'F' || spec.width == 'D') &&
			x86FloatArithmeticLiteral(ins, true, true)
	}
	register := func(operand Operand) bool {
		_, valid := x87OperandReg(operand)
		return valid
	}
	if spec.kind == x86X87Constant || spec.kind == x86X87Unary || spec.kind == x86X87Test || spec.kind == x86X87Round {
		if len(ins.Args) != 0 {
			return fail("takes no operands")
		}
		return form, true, nil
	}
	if spec.kind == x86X87Status {
		word, _, err := x86X87WordProperties(ins, arch)
		form.destination = word.operand
		return form, true, err
	}
	operands := ins.Args
	decoderMemoryAlias := name == "FBLD" || name == "FBSTP"
	if decoderMemoryAlias {
		if len(operands) != 1 {
			return fail("expects its original decoder memory operand")
		}
		f0 := Operand{Kind: OpReg, Reg: "F0"}
		if spec.pop != 0 {
			operands = []Operand{f0, operands[0]}
		} else {
			operands = []Operand{operands[0], f0}
		}
	}
	if len(operands) != 2 {
		switch spec.kind {
		case x86X87Compare:
			return fail("expects lhs, rhs")
		case x86X87Exchange:
			return fail("expects Fsrc, Fdst")
		case x86X87FloatMove:
			if spec.pop != 0 {
				return fail("expects F0 source and memory or x87-register destination")
			}
		}
		return fail("expects src, dst")
	}
	first, last := operands[0], operands[1]
	form.source, form.destination = first, last
	switch spec.kind {
	case x86X87ConditionalMove:
		if !register(first) || !isX87F0(last) {
			return fail("expects x87-register source and F0 destination")
		}
	case x86X87IntegerMove:
		if spec.pop != 0 {
			if !isX87F0(first) || !memory(last) {
				return fail("expects F0 source and signed integer memory destination")
			}
			return form, true, nil
		}
		if memory(first) && isX87F0(last) {
			form.push = true
			return form, true, nil
		}
		// yfmvx has only the m64 load row; Go has no non-pop FIST m64.
		if spec.width != 'V' && isX87F0(first) && memory(last) {
			return form, true, nil
		}
		return fail("expects signed integer memory,F0 or the registered F0,memory store row")
	case x86X87FloatMove:
		loadShape := "memory,F0, Freg,F0, F0,memory, or F0,Freg"
		storeShape := "F0 source and memory or x87-register destination"
		if form.memoryBytes() == 10 {
			loadShape, storeShape = "memory source and F0 destination", "F0 source and memory destination"
			if decoderMemoryAlias {
				loadShape, storeShape = "memory source", "memory destination"
			}
		}
		if spec.pop != 0 {
			if !isX87F0(first) || !(memory(last) || spec.width == 'D' && register(last)) {
				return fail("expects " + storeShape)
			}
			return form, true, nil
		}
		if isX87F0(last) && (memory(first) || constant(first) || spec.width == 'D' && register(first)) {
			// yfmvd's Yrf,Yf0 row is FLD ST(i), before its overlapping
			// Yf0,Yrf store row. F0,F0 therefore pushes as well.
			form.push = true
			return form, true, nil
		}
		if (spec.width == 'F' || spec.width == 'D') && isX87F0(first) && (memory(last) || spec.width == 'D' && register(last)) {
			return form, true, nil
		}
		return fail("expects " + loadShape)
	case x86X87Exchange:
		if !register(first) || !register(last) || !isX87F0(first) && !isX87F0(last) {
			return fail("expects x87 registers with one F0 operand")
		}
	case x86X87Arithmetic:
		if spec.pop != 0 {
			if !isX87F0(first) || !register(last) {
				return fail("expects F0 source and x87-register destination")
			}
		} else if spec.width == 'D' {
			if !(isX87F0(last) && (memory(first) || constant(first) || register(first)) || isX87F0(first) && register(last)) {
				return fail("expects memory,F0, Freg,F0, or F0,Freg")
			}
		} else if !isX87F0(last) || !(memory(first) || spec.width == 'F' && constant(first)) {
			return fail("expects memory source and F0 destination")
		}
	case x86X87Compare:
		switch {
		case name == "FCOMI" || name == "FCOMIP":
			if !register(first) || !isX87F0(last) {
				return fail("expects x87-register source and F0 destination")
			}
			form.left, form.right = last, first
		case strings.HasPrefix(name, "FUCOM") || name == "FCOMDPP":
			if !isX87F0(first) || !register(last) {
				return fail("expects F0 source and x87-register destination")
			}
			form.left, form.right = first, last
		default:
			if isX87F0(last) && (memory(first) || constant(first) || spec.width == 'D' && register(first)) {
				form.left, form.right = last, first
			} else if spec.width == 'D' && isX87F0(first) && register(last) {
				// Retain Go's complete reverse FCOMD/DP grammar without
				// interpreting its undocumented DC /2,/3 register encoding
				// as a new logical compare proof.
				form.left, form.right, form.unprovedEncoding = last, first, true
			} else {
				return fail("expects memory source or x87-register source and F0 destination")
			}
		}
		if spec.pop == 2 && form.right.Reg != "F1" {
			// ycompp's Go table explicitly notes that its two-pop row is
			// really F0,F1. Recognizing another encoded row is not a proof
			// that the legacy mathematical spelling matches that opcode.
			form.unprovedEncoding = true
		}
	}
	return form, true, nil
}
