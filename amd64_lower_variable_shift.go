package plan9asm

import "fmt"

type amd64PerLaneVariableShiftSpec struct {
	laneBits   int
	operation  string
	arithmetic bool
	// Shared raw grammar: 66.0F38 opcode and optional VEX generation.
	// W is fixed: W0 for dwords, W1 for words/qwords.
	opcode byte
	vex    bool
}

var amd64PerLaneVariableShiftSpecs = map[string]amd64PerLaneVariableShiftSpec{
	"VPSLLVW": {laneBits: 16, operation: "shl", opcode: 0x12},
	"VPSLLVD": {laneBits: 32, operation: "shl", opcode: 0x47, vex: true},
	"VPSLLVQ": {laneBits: 64, operation: "shl", opcode: 0x47, vex: true},
	"VPSRLVW": {laneBits: 16, operation: "lshr", opcode: 0x10},
	"VPSRLVD": {laneBits: 32, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRLVQ": {laneBits: 64, operation: "lshr", opcode: 0x45, vex: true},
	"VPSRAVW": {laneBits: 16, operation: "ashr", arithmetic: true, opcode: 0x11},
	"VPSRAVD": {laneBits: 32, operation: "ashr", arithmetic: true, opcode: 0x46, vex: true},
	"VPSRAVQ": {laneBits: 64, operation: "ashr", arithmetic: true, opcode: 0x46},
}

// lowerPerLaneVariableShift implements the full Go 1.27 per-lane packed
// variable-shift family. The first Plan 9 source supplies one count per lane.
func (c *amd64Ctx) lowerPerLaneVariableShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	return c.lowerX86PackedShift(op, ins)
}

func (c *amd64Ctx) emitPerLaneVariableShift(spec amd64PerLaneVariableShiftSpec, lanes int, counts, data string) string {
	typeName := fmt.Sprintf("<%d x i%d>", lanes, spec.laneBits)
	limit := amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits))
	inRange := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = icmp ult %s %s, %s\n", inRange, typeName, counts, limit)
	fallbackCount := "zeroinitializer"
	if spec.arithmetic {
		fallbackCount = amd64SplatInteger(c, lanes, spec.laneBits, fmt.Sprintf("%d", spec.laneBits-1))
	}
	safeCounts := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %s, %s %s\n", safeCounts, lanes, inRange, typeName, counts, typeName, fallbackCount)
	shifted := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = %s %s %s, %%%s\n", shifted, spec.operation, typeName, data, safeCounts)
	if spec.arithmetic {
		return "%" + shifted
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = select <%d x i1> %%%s, %s %%%s, %s zeroinitializer\n", result, lanes, inRange, typeName, shifted, typeName)
	return "%" + result
}
