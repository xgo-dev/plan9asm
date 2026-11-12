package plan9asm

import "fmt"

type arm64RawSHA3Kind uint8

const (
	arm64RawSHA3EOR3 arm64RawSHA3Kind = iota
	arm64RawSHA3BCAX
	arm64RawSHA3RAX1
	arm64RawSHA3XAR
)

type arm64RawSHA3 struct {
	kind        arm64RawSHA3Kind
	destination int
	first       int
	second      int
	third       int
	rotate      int
}

func decodeARM64RawSHA3(word uint32) (arm64RawSHA3, bool) {
	const (
		destination = uint32(31)
		first       = uint32(31 << 5)
		third       = uint32(31 << 10)
		rotate      = uint32(63 << 10)
		second      = uint32(31 << 16)
	)

	form := arm64RawSHA3{
		destination: int(word) & 31,
		first:       int(word>>5) & 31,
		second:      int(word>>16) & 31,
	}
	switch word &^ (destination | first | third | second) {
	case 0xce000000:
		form.kind = arm64RawSHA3EOR3
		form.third = int(word>>10) & 31
		return form, true
	case 0xce200000:
		form.kind = arm64RawSHA3BCAX
		form.third = int(word>>10) & 31
		return form, true
	}
	if word&^(destination|first|second) == 0xce608c00 {
		form.kind = arm64RawSHA3RAX1
		return form, true
	}
	if word&^(destination|first|rotate|second) == 0xce800000 {
		form.kind = arm64RawSHA3XAR
		form.rotate = int(word>>10) & 63
		return form, true
	}
	return arm64RawSHA3{}, false
}

func (c *arm64Ctx) lowerRawSHA3(form arm64RawSHA3) error {
	first, err := c.loadARM64RawSHA3Vector(form.first)
	if err != nil {
		return err
	}
	second, err := c.loadARM64RawSHA3Vector(form.second)
	if err != nil {
		return err
	}

	result := ""
	switch form.kind {
	case arm64RawSHA3EOR3, arm64RawSHA3BCAX:
		third, err := c.loadARM64RawSHA3Vector(form.third)
		if err != nil {
			return err
		}
		combined := c.newTmp()
		if form.kind == arm64RawSHA3EOR3 {
			fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %s\n", combined, second, third)
		} else {
			inverted := c.newTmp()
			fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, <i64 -1, i64 -1>\n", inverted, third)
			fmt.Fprintf(c.b, "  %%%s = and <2 x i64> %s, %%%s\n", combined, second, inverted)
		}
		resultName := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %%%s\n", resultName, first, combined)
		result = "%" + resultName
	case arm64RawSHA3RAX1:
		rotated := c.rotateARM64RawSHA3VectorRight(second, 1)
		resultName := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %s\n", resultName, first, rotated)
		result = "%" + resultName
	case arm64RawSHA3XAR:
		combined := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = xor <2 x i64> %s, %s\n", combined, first, second)
		result = c.rotateARM64RawSHA3VectorRight("%"+combined, form.rotate)
	default:
		return fmt.Errorf("arm64 unsupported raw SHA3 kind %d", form.kind)
	}

	bytes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <2 x i64> %s to <16 x i8>\n", bytes, result)
	return c.storeVReg(Reg(fmt.Sprintf("V%d", form.destination)), "%"+bytes)
}

func (c *arm64Ctx) loadARM64RawSHA3Vector(register int) (string, error) {
	value, err := c.loadVReg(Reg(fmt.Sprintf("V%d", register)))
	if err != nil {
		return "", err
	}
	lanes := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = bitcast <16 x i8> %s to <2 x i64>\n", lanes, value)
	return "%" + lanes, nil
}

func (c *arm64Ctx) rotateARM64RawSHA3VectorRight(value string, amount int) string {
	if amount == 0 {
		return value
	}
	right := c.newTmp()
	left := c.newTmp()
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = lshr <2 x i64> %s, <i64 %d, i64 %d>\n", right, value, amount, amount)
	fmt.Fprintf(c.b, "  %%%s = shl <2 x i64> %s, <i64 %d, i64 %d>\n", left, value, 64-amount, 64-amount)
	fmt.Fprintf(c.b, "  %%%s = or <2 x i64> %%%s, %%%s\n", result, right, left)
	return "%" + result
}
