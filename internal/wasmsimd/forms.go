// Package wasmsimd describes the typed WebAssembly SIMD instruction forms
// shared by lowering, stack inference and the opcode inventory.
package wasmsimd

import "fmt"

type Emission uint8

const (
	Core Emission = iota
	Instruction
	Intrinsic
	Compare
	FloatSelect
)

type Shape struct {
	LaneType      string
	PredicateType string
	MaskType      string
	Comparator    string
	overload      string
}

type Form struct {
	Inputs   int
	Emission Emission
	Operator string
	Shape    Shape
}

func (f Form) IntrinsicName() string {
	return "llvm." + f.Operator + "." + f.Shape.overload
}

var forms = buildForms()

func Lookup(opcode string) (Form, bool) {
	f, ok := forms[opcode]
	return f, ok
}

func AddNamed(names map[string]struct{}) {
	for name := range forms {
		names[name] = struct{}{}
	}
}

func buildForms() map[string]Form {
	result := map[string]Form{
		"V128CONST":     {Operator: "const"},
		"V128NOT":       {Inputs: 1, Operator: "not"},
		"V128AND":       {Inputs: 2, Operator: "and"},
		"V128ANDNOT":    {Inputs: 2, Operator: "andnot"},
		"V128OR":        {Inputs: 2, Operator: "or"},
		"V128XOR":       {Inputs: 2, Operator: "xor"},
		"V128BITSELECT": {Inputs: 3, Operator: "bitselect"},
		"V128ANYTRUE":   {Inputs: 1, Operator: "anytrue"},
	}
	type operation struct {
		suffix, operator string
		inputs           int
		emission         Emission
	}
	add := func(prefix string, shape Shape, op operation) {
		result[prefix+op.suffix] = Form{Inputs: op.inputs, Emission: op.emission, Operator: op.operator, Shape: shape}
	}

	for _, lane := range []struct {
		prefix string
		bits   int
	}{{"I8X16", 8}, {"I16X8", 16}, {"I32X4", 32}, {"I64X2", 64}} {
		count := 128 / lane.bits
		laneType := fmt.Sprintf("<%d x i%d>", count, lane.bits)
		shape := Shape{
			LaneType:      laneType,
			PredicateType: fmt.Sprintf("<%d x i1>", count),
			MaskType:      laneType,
			Comparator:    "icmp",
			overload:      fmt.Sprintf("v%di%d", count, lane.bits),
		}
		add(lane.prefix, shape, operation{"ADD", "add", 2, Instruction})
		add(lane.prefix, shape, operation{"SUB", "sub", 2, Instruction})
		if lane.bits >= 16 {
			add(lane.prefix, shape, operation{"MUL", "mul", 2, Instruction})
		}
		if lane.bits <= 16 {
			add(lane.prefix, shape, operation{"ADDSATS", "sadd.sat", 2, Intrinsic})
			add(lane.prefix, shape, operation{"ADDSATU", "uadd.sat", 2, Intrinsic})
			add(lane.prefix, shape, operation{"SUBSATS", "ssub.sat", 2, Intrinsic})
			add(lane.prefix, shape, operation{"SUBSATU", "usub.sat", 2, Intrinsic})
		}
		add(lane.prefix, shape, operation{"EQ", "eq", 2, Compare})
		add(lane.prefix, shape, operation{"NE", "ne", 2, Compare})
		for _, relation := range []struct{ suffix, predicate string }{
			{"LT", "lt"}, {"GT", "gt"}, {"LE", "le"}, {"GE", "ge"},
		} {
			add(lane.prefix, shape, operation{relation.suffix + "S", "s" + relation.predicate, 2, Compare})
			if lane.bits < 64 {
				add(lane.prefix, shape, operation{relation.suffix + "U", "u" + relation.predicate, 2, Compare})
			}
		}
		if lane.bits < 64 {
			add(lane.prefix, shape, operation{"MINS", "smin", 2, Intrinsic})
			add(lane.prefix, shape, operation{"MINU", "umin", 2, Intrinsic})
			add(lane.prefix, shape, operation{"MAXS", "smax", 2, Intrinsic})
			add(lane.prefix, shape, operation{"MAXU", "umax", 2, Intrinsic})
		}
	}

	floatOperations := []operation{
		{"ABS", "fabs", 1, Intrinsic},
		{"NEG", "fneg", 1, Instruction},
		{"SQRT", "sqrt", 1, Intrinsic},
		{"CEIL", "ceil", 1, Intrinsic},
		{"FLOOR", "floor", 1, Intrinsic},
		{"TRUNC", "trunc", 1, Intrinsic},
		{"NEAREST", "roundeven", 1, Intrinsic},
		{"ADD", "fadd", 2, Instruction},
		{"SUB", "fsub", 2, Instruction},
		{"MUL", "fmul", 2, Instruction},
		{"DIV", "fdiv", 2, Instruction},
		{"MIN", "minimum", 2, Intrinsic},
		{"MAX", "maximum", 2, Intrinsic},
		{"PMIN", "ogt", 2, FloatSelect},
		{"PMAX", "olt", 2, FloatSelect},
		{"EQ", "oeq", 2, Compare},
		{"NE", "une", 2, Compare},
		{"LT", "olt", 2, Compare},
		{"GT", "ogt", 2, Compare},
		{"LE", "ole", 2, Compare},
		{"GE", "oge", 2, Compare},
	}
	for _, lane := range []struct {
		prefix, element string
		bits            int
	}{{"F32X4", "float", 32}, {"F64X2", "double", 64}} {
		count := 128 / lane.bits
		shape := Shape{
			LaneType:      fmt.Sprintf("<%d x %s>", count, lane.element),
			PredicateType: fmt.Sprintf("<%d x i1>", count),
			MaskType:      fmt.Sprintf("<%d x i%d>", count, lane.bits),
			Comparator:    "fcmp",
			overload:      fmt.Sprintf("v%df%d", count, lane.bits),
		}
		for _, op := range floatOperations {
			add(lane.prefix, shape, op)
		}
	}
	return result
}
