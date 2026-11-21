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
	IntegerAbs
	IntegerNeg
	Shift
	AllTrue
	Bitmask
)

type ValueType string

const (
	V128 ValueType = "<4 x i32>"
	I32  ValueType = "i32"
)

type stackSignature struct {
	inputs []ValueType
	result ValueType
}

type Shape struct {
	LaneType      string
	LaneBits      int
	PredicateType string
	MaskType      string
	Comparator    string
	overload      string
}

type Form struct {
	stack    stackSignature
	Emission Emission
	Operator string
	Shape    Shape
}

func (f Form) Arity() int { return len(f.stack.inputs) }

func (f Form) InputType(index int) ValueType { return f.stack.inputs[index] }

func (f Form) ResultType() ValueType { return f.stack.result }

func (f Form) HasIntrinsic() bool {
	return f.Emission == Intrinsic || f.Emission == IntegerAbs
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
	constant := stackSignature{result: V128}
	unary := stackSignature{[]ValueType{V128}, V128}
	binary := stackSignature{[]ValueType{V128, V128}, V128}
	ternary := stackSignature{[]ValueType{V128, V128, V128}, V128}
	shift := stackSignature{[]ValueType{V128, I32}, V128}
	reduce := stackSignature{[]ValueType{V128}, I32}
	result := map[string]Form{
		"V128CONST":     {stack: constant, Operator: "const"},
		"V128NOT":       {stack: unary, Operator: "not"},
		"V128AND":       {stack: binary, Operator: "and"},
		"V128ANDNOT":    {stack: binary, Operator: "andnot"},
		"V128OR":        {stack: binary, Operator: "or"},
		"V128XOR":       {stack: binary, Operator: "xor"},
		"V128BITSELECT": {stack: ternary, Operator: "bitselect"},
		"V128ANYTRUE":   {stack: reduce, Operator: "anytrue"},
	}
	type operation struct {
		suffix, operator string
		stack            stackSignature
		emission         Emission
	}
	add := func(prefix string, shape Shape, op operation) {
		result[prefix+op.suffix] = Form{stack: op.stack, Emission: op.emission, Operator: op.operator, Shape: shape}
	}

	for _, lane := range []struct {
		prefix string
		bits   int
	}{{"I8X16", 8}, {"I16X8", 16}, {"I32X4", 32}, {"I64X2", 64}} {
		count := 128 / lane.bits
		laneType := fmt.Sprintf("<%d x i%d>", count, lane.bits)
		shape := Shape{
			LaneType:      laneType,
			LaneBits:      lane.bits,
			PredicateType: fmt.Sprintf("<%d x i1>", count),
			MaskType:      laneType,
			Comparator:    "icmp",
			overload:      fmt.Sprintf("v%di%d", count, lane.bits),
		}
		add(lane.prefix, shape, operation{"ADD", "add", binary, Instruction})
		add(lane.prefix, shape, operation{"SUB", "sub", binary, Instruction})
		if lane.bits >= 16 {
			add(lane.prefix, shape, operation{"MUL", "mul", binary, Instruction})
		}
		if lane.bits <= 16 {
			add(lane.prefix, shape, operation{"ADDSATS", "sadd.sat", binary, Intrinsic})
			add(lane.prefix, shape, operation{"ADDSATU", "uadd.sat", binary, Intrinsic})
			add(lane.prefix, shape, operation{"SUBSATS", "ssub.sat", binary, Intrinsic})
			add(lane.prefix, shape, operation{"SUBSATU", "usub.sat", binary, Intrinsic})
		}
		add(lane.prefix, shape, operation{"EQ", "eq", binary, Compare})
		add(lane.prefix, shape, operation{"NE", "ne", binary, Compare})
		for _, relation := range []struct{ suffix, predicate string }{
			{"LT", "lt"}, {"GT", "gt"}, {"LE", "le"}, {"GE", "ge"},
		} {
			add(lane.prefix, shape, operation{relation.suffix + "S", "s" + relation.predicate, binary, Compare})
			if lane.bits < 64 {
				add(lane.prefix, shape, operation{relation.suffix + "U", "u" + relation.predicate, binary, Compare})
			}
		}
		if lane.bits < 64 {
			add(lane.prefix, shape, operation{"MINS", "smin", binary, Intrinsic})
			add(lane.prefix, shape, operation{"MINU", "umin", binary, Intrinsic})
			add(lane.prefix, shape, operation{"MAXS", "smax", binary, Intrinsic})
			add(lane.prefix, shape, operation{"MAXU", "umax", binary, Intrinsic})
		}
		add(lane.prefix, shape, operation{"ABS", "abs", unary, IntegerAbs})
		add(lane.prefix, shape, operation{"NEG", "", unary, IntegerNeg})
		if lane.bits == 8 {
			add(lane.prefix, shape, operation{"POPCNT", "ctpop", unary, Intrinsic})
		}
		add(lane.prefix, shape, operation{"SHL", "shl", shift, Shift})
		add(lane.prefix, shape, operation{"SHRS", "ashr", shift, Shift})
		add(lane.prefix, shape, operation{"SHRU", "lshr", shift, Shift})
		add(lane.prefix, shape, operation{"ALLTRUE", "ne", reduce, AllTrue})
		add(lane.prefix, shape, operation{"BITMASK", "slt", reduce, Bitmask})
	}

	floatOperations := []operation{
		{"ABS", "fabs", unary, Intrinsic},
		{"NEG", "fneg", unary, Instruction},
		{"SQRT", "sqrt", unary, Intrinsic},
		{"CEIL", "ceil", unary, Intrinsic},
		{"FLOOR", "floor", unary, Intrinsic},
		{"TRUNC", "trunc", unary, Intrinsic},
		{"NEAREST", "roundeven", unary, Intrinsic},
		{"ADD", "fadd", binary, Instruction},
		{"SUB", "fsub", binary, Instruction},
		{"MUL", "fmul", binary, Instruction},
		{"DIV", "fdiv", binary, Instruction},
		{"MIN", "minimum", binary, Intrinsic},
		{"MAX", "maximum", binary, Intrinsic},
		{"PMIN", "ogt", binary, FloatSelect},
		{"PMAX", "olt", binary, FloatSelect},
		{"EQ", "oeq", binary, Compare},
		{"NE", "une", binary, Compare},
		{"LT", "olt", binary, Compare},
		{"GT", "ogt", binary, Compare},
		{"LE", "ole", binary, Compare},
		{"GE", "oge", binary, Compare},
	}
	for _, lane := range []struct {
		prefix, element string
		bits            int
	}{{"F32X4", "float", 32}, {"F64X2", "double", 64}} {
		count := 128 / lane.bits
		shape := Shape{
			LaneType:      fmt.Sprintf("<%d x %s>", count, lane.element),
			LaneBits:      lane.bits,
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
