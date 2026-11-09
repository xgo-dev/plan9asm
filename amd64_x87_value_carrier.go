package plan9asm

import "fmt"

// x87Value is one private LLVM aggregate, never a Go/C memory or source role.
// Its low field includes the explicit integer bit of the binary80 significand.
type x87Value string

const x87ValueType = "{ i64, i16 }"

const x87ZeroValue x87Value = "zeroinitializer"

func (c *amd64Ctx) packX87(significand, signExponent string) x87Value {
	low, value := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = insertvalue %s zeroinitializer, i64 %s, 0\n", low, x87ValueType, significand)
	fmt.Fprintf(c.b, "  %%%s = insertvalue %s %%%s, i16 %s, 1\n", value, x87ValueType, low, signExponent)
	return x87Value("%" + value)
}

func (c *amd64Ctx) partsX87(value x87Value) (significand, signExponent string) {
	low, high := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, 0\n", low, x87ValueType, value)
	fmt.Fprintf(c.b, "  %%%s = extractvalue %s %s, 1\n", high, x87ValueType, value)
	return "%" + low, "%" + high
}

func (c *amd64Ctx) loadX87Value(index int) x87Value {
	value := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = load %s, ptr %s\n", value, x87ValueType, c.x87Slot[index])
	return x87Value("%" + value)
}

func (c *amd64Ctx) storeX87Value(index int, value x87Value) {
	fmt.Fprintf(c.b, "  store %s %s, ptr %s\n", x87ValueType, value, c.x87Slot[index])
}

func (c *amd64Ctx) pushX87Value(value x87Value) error {
	for index := len(c.x87Slot) - 1; index > 0; index-- {
		c.storeX87Value(index, c.loadX87Value(index-1))
	}
	c.storeX87Value(0, value)
	return nil
}

func (c *amd64Ctx) popX87Value() {
	for index := 0; index < len(c.x87Slot)-1; index++ {
		c.storeX87Value(index, c.loadX87Value(index+1))
	}
	c.storeX87Value(len(c.x87Slot)-1, x87ZeroValue)
}

func (c *amd64Ctx) rotateX87Values(increment bool) {
	var values [8]x87Value
	for index := range values {
		values[index] = c.loadX87Value(index)
	}
	for index := range values {
		source := (index + len(values) - 1) % len(values)
		if increment {
			source = (index + 1) % len(values)
		}
		c.storeX87Value(index, values[source])
	}
}
