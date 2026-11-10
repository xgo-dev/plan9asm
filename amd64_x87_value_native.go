package plan9asm

import (
	"fmt"
	"strings"
)

// Native evaluation uses private copies, and leaves the physical x87 stack
// balanced. Logical stack movement remains the responsibility of the caller.
// All scratch is allocated once at function entry, including loop bodies.
type x87NativeOperand struct {
	pointer string
	typ     string
}

func (c *amd64Ctx) emitX87NativeAsm(code string, outputs, inputs []x87NativeOperand) {
	constraints := make([]string, 0, len(outputs)+len(inputs)+1)
	arguments := make([]string, 0, len(outputs)+len(inputs))
	for index, operand := range append(append([]x87NativeOperand(nil), outputs...), inputs...) {
		constraint := "*m"
		if index < len(outputs) {
			constraint = "=*m"
		}
		constraints = append(constraints, constraint)
		arguments = append(arguments, fmt.Sprintf("ptr elementtype(%s) %s", operand.typ, operand.pointer))
	}
	constraints = append(constraints, "~{st},~{st(1)},~{st(2)},~{st(3)},~{st(4)},~{st(5)},~{st(6)},~{st(7)},~{fpsr},~{memory}")
	if strings.Contains(code, "btw ") {
		constraints = append(constraints, "~{flags}")
	}
	fmt.Fprintf(c.b, "  call void asm sideeffect %q, %q(%s)\n", code, strings.Join(constraints, ","), strings.Join(arguments, ", "))
}

func (c *amd64Ctx) saveX87NativeInput(slot int, value x87Value) x87NativeOperand {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, value, c.x87ValueScratch[slot])
	return x87NativeOperand{c.x87ValueScratch[slot], x87ValueType}
}

func (c *amd64Ctx) readX87NativeOutput(slot int) x87Value {
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", value, x87ValueType, c.x87ValueScratch[slot])
	return x87Value("%" + value)
}

// Inputs are in logical F0,F1 order; the last load becomes physical ST(0).
// remaining counts the physical values after instruction, including operands
// retained by non-popping binary operations. Only requested results escape.
func (c *amd64Ctx) evaluateX87Native(instruction string, values []x87Value, results, remaining int) (x87Value, x87Value, string) {
	outputs := []x87NativeOperand{
		{c.x87ValueScratch[0], x87ValueType},
		{c.x87ValueScratch[1], x87ValueType},
		{c.x87NativeStatus, "i16"},
	}
	inputs := make([]x87NativeOperand, len(values))
	for index, value := range values {
		inputs[index] = c.saveX87NativeInput(index+1, value)
	}
	var code strings.Builder
	for index := len(inputs) - 1; index >= 0; index-- {
		fmt.Fprintf(&code, "fldt $%d; ", len(outputs)+index)
	}
	code.WriteString(instruction)
	code.WriteString("; fnstsw $2")
	conditionalPair := len(values) == 1 && results == 2 && (instruction == "fptan" || instruction == "fsincos")
	if conditionalPair {
		// These instructions leave one physical value when C2 reports an
		// out-of-range input. Never pop a nonexistent second value.
		code.WriteString("; btw $$10, $2; jnc 1f; fstpt $0; fldz; fstpt $1; jmp 2f; 1: fstpt $0; fstpt $1; 2:")
		c.emitX87NativeAsm(code.String(), outputs, inputs)
	} else {
		for index := 0; index < results; index++ {
			fmt.Fprintf(&code, "; fstpt $%d", index)
		}
		for index := results; index < remaining; index++ {
			code.WriteString("; fstp %st(0)")
		}
		c.emitX87NativeAsm(code.String(), outputs, inputs)
	}
	first, second := x87ZeroValue, x87ZeroValue
	if results > 0 {
		first = c.readX87NativeOutput(0)
	}
	if results > 1 {
		second = c.readX87NativeOutput(1)
	}
	status := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", status, c.x87NativeStatus)
	return first, second, "%" + status
}

func (c *amd64Ctx) x87NativeFromScalar(value, typ, instruction string) x87Value {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", typ, value, c.x87ScalarScratch)
	c.emitX87NativeAsm(instruction+" $1; fstpt $0",
		[]x87NativeOperand{{c.x87ValueScratch[0], x87ValueType}},
		[]x87NativeOperand{{c.x87ScalarScratch, typ}})
	return c.readX87NativeOutput(0)
}

func (c *amd64Ctx) x87NativeToScalar(value x87Value, typ, instruction string) string {
	input := c.saveX87NativeInput(1, value)
	c.emitX87NativeAsm("fldt $1; "+instruction+" $0",
		[]x87NativeOperand{{c.x87ScalarScratch, typ}}, []x87NativeOperand{input})
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", result, typ, c.x87ScalarScratch)
	return "%" + result
}

func (c *amd64Ctx) x87NativeFromFloat(value string, bits int) x87Value {
	if bits == 32 {
		return c.x87NativeFromScalar(value, "float", "flds")
	}
	return c.x87NativeFromScalar(value, "double", "fldl")
}

func (c *amd64Ctx) x87NativeFromSigned(value string, bits int) x87Value {
	instruction := "fildll"
	if bits == 16 {
		instruction = "filds"
	} else if bits == 32 {
		instruction = "fildl"
	}
	return c.x87NativeFromScalar(value, string(amd64IntegerTypeForBits(bits)), instruction)
}

func (c *amd64Ctx) x87NativeToFloat(value x87Value, bits int) string {
	if bits == 32 {
		return c.x87NativeToScalar(value, "float", "fstps")
	}
	return c.x87NativeToScalar(value, "double", "fstpl")
}

func (c *amd64Ctx) x87NativeToSigned(value x87Value, bits int) string {
	instruction := "fistpll"
	if bits == 16 {
		instruction = "fistps"
	} else if bits == 32 {
		instruction = "fistpl"
	}
	return c.x87NativeToScalar(value, string(amd64IntegerTypeForBits(bits)), instruction)
}

func (c *amd64Ctx) projectX87Status(status string, mask int) {
	previous, kept, changed, merged := c.newTmp(), c.newTmp(), c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load i16, ptr %s\n", previous, c.x87StatusSlot)
	fmt.Fprintf(c.b, "  %%%s = and i16 %%%s, %d\n", kept, previous, ^uint16(mask))
	fmt.Fprintf(c.b, "  %%%s = and i16 %s, %d\n", changed, status, mask)
	fmt.Fprintf(c.b, "  %%%s = or i16 %%%s, %%%s\n", merged, kept, changed)
	fmt.Fprintf(c.b, "  store i16 %%%s, ptr %s\n", merged, c.x87StatusSlot)
}
