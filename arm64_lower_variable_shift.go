package plan9asm

import (
	"fmt"
	"strings"
)

// lowerARM64VectorVariableShift implements the complete AdvSIMD signed-count
// variable-shift family. The first Go-syntax operand supplies signed per-lane
// shift counts; the second is the value to shift. VSRSHL/VURSHL round right
// shifts, while VSSHL/VUSHL do not.
func (c *arm64Ctx) lowerARM64VectorVariableShift(op Op, ins Instr) (ok bool, terminated bool, err error) {
	intrinsic, handled := map[Op]string{
		"VSSHL": "sshl", "VSRSHL": "srshl",
		"VUSHL": "ushl", "VURSHL": "urshl",
	}[op]
	if !handled {
		return false, false, nil
	}
	if strings.ToUpper(string(ins.Op)) != string(op) || len(ins.Args) != 3 {
		return true, false, fmt.Errorf("arm64 %s expects Vshifts.T, Vvalue.T, Vdst.T with no suffix: %q", op, ins.Raw)
	}
	scalar := true
	for _, arg := range ins.Args {
		if arg.Kind != OpReg || strings.Contains(string(arg.Reg), ".") {
			scalar = false
			break
		}
		if _, ok := arm64ParseVReg(arg.Reg); !ok {
			scalar = false
			break
		}
	}
	arrangement := arm64VectorArrangement{elementBits: 64, lanes: 1}
	for i, arg := range ins.Args {
		if arg.Kind != OpReg {
			return true, false, fmt.Errorf("arm64 %s accepts only vector registers: %q", op, ins.Raw)
		}
		if scalar {
			continue
		}
		parsed, valid := parseARM64VectorArrangement(arg.Reg)
		if !valid || !arm64VDUPArrangementAllowed(parsed) {
			return true, false, fmt.Errorf("arm64 %s accepts a bare scalar D form or B8/B16/H4/H8/S2/S4/D2 vector arrangements: %q", op, ins.Raw)
		}
		if i == 0 {
			arrangement = parsed
		} else if parsed != arrangement {
			return true, false, fmt.Errorf("arm64 %s arrangements must match: %q", op, ins.Raw)
		}
	}
	shifts, err := c.loadARM64VectorInteger(ins.Args[0].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	value, err := c.loadARM64VectorInteger(ins.Args[1].Reg, arrangement)
	if err != nil {
		return true, false, err
	}
	if scalar {
		scalarShifts := c.newTmp()
		scalarValue := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i64> %s, i32 0\n", scalarShifts, shifts)
		fmt.Fprintf(c.b, "  %%%s = extractelement <1 x i64> %s, i32 0\n", scalarValue, value)
		shifts = "%" + scalarShifts
		value = "%" + scalarValue
	}
	vectorType := fmt.Sprintf("<%d x i%d>", arrangement.lanes, arrangement.elementBits)
	typeName := fmt.Sprintf("v%di%d", arrangement.lanes, arrangement.elementBits)
	if scalar {
		vectorType = "i64"
		typeName = "i64"
	}
	result := c.newTmp()
	fmt.Fprintf(c.b, "  %%%s = call %s @llvm.aarch64.neon.%s.%s(%s %s, %s %s)\n", result, vectorType, intrinsic, typeName, vectorType, value, vectorType, shifts)
	storedResult := "%" + result
	if scalar {
		inserted := c.newTmp()
		fmt.Fprintf(c.b, "  %%%s = insertelement <1 x i64> zeroinitializer, i64 %%%s, i32 0\n", inserted, result)
		storedResult = "%" + inserted
	}
	return true, false, c.storeARM64VectorInteger(ins.Args[2].Reg, arrangement, storedResult)
}
