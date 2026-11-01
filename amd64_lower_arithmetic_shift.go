package plan9asm

import "fmt"

// The complete uniform arithmetic family shares yps/_yvpslld operand shapes
// with logical shifts. VPSRAQ has only the unsigned-immediate EVEX rows.
// These descriptors grant no register input, native backing or caller role.
var amd64PackedArithmeticShiftSpecs = map[Op]amd64PackedLogicalShiftSpec{
	"PSRAW":  {laneBits: 16},
	"PSRAL":  {laneBits: 32},
	"VPSRAW": {laneBits: 16, vector: true},
	"VPSRAD": {laneBits: 32, vector: true},
	"VPSRAQ": {laneBits: 64, vector: true},
}

func (c *amd64Ctx) lowerPackedArithmeticRightShift(op Op, ins Instr) (bool, bool, error) {
	return c.lowerX86PackedShift(op, ins)
}

func (c *amd64Ctx) emitPackedArithmeticRightShift(lanes, laneBits int, data, count64 string) string {
	valid, safe := c.newTmp(), c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult i64 %s, %d\n", valid, count64, laneBits)
	fmt.Fprintf(c.b, "  %%%s = select i1 %%%s, i64 %s, i64 %d\n", safe, valid, count64, laneBits-1)
	count := "%" + safe
	if laneBits < 64 {
		narrow := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = trunc i64 %s to i%d\n", narrow, count, laneBits)
		count = "%" + narrow
	}
	counts := amd64SplatInteger(c, lanes, laneBits, count)
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = ashr <%d x i%d> %s, %s\n", result, lanes, laneBits, data, counts)
	return "%" + result
}
