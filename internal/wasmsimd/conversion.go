package wasmsimd

import "fmt"

// LaneConversion describes the active lanes on either side of a conversion.
// The full stack operand and result are always V128.
type LaneConversion struct {
	Lanes                 int
	InputType, ResultType string
	Intrinsic             string
}

func addConversions(forms map[string]Form, unary stackSignature) {
	i32, f32, f64 := integerShape(32), floatShape(32, F32), floatShape(64, F64)
	add := func(name, op string, input, result Shape, lanes int, saturate string, canonicalNaN bool) {
		var intrinsic string
		if saturate != "" {
			intrinsic = fmt.Sprintf("llvm.%s.sat.v%di%d.v%df%d", saturate, lanes, result.LaneBits, lanes, input.LaneBits)
		}
		forms[name] = Form{
			stack: unary, inputLanes: input.LaneType, Emission: Convert,
			Operator: op, Shape: result, CanonicalNaN: canonicalNaN,
			Conversion: &LaneConversion{
				Lanes: lanes, InputType: vectorType(lanes, input.Element),
				ResultType: vectorType(lanes, result.Element), Intrinsic: intrinsic,
			},
		}
	}
	for _, sign := range []struct{ suffix, toFloat, toInteger string }{
		{"S", "sitofp", "fptosi"}, {"U", "uitofp", "fptoui"},
	} {
		add("F32X4CONVERTI32X4"+sign.suffix, sign.toFloat, i32, f32, 4, "", false)
		add("F64X2CONVERTLOWI32X4"+sign.suffix, sign.toFloat, i32, f64, 2, "", false)
		trunc32 := "I32X4TRUNCSATF32X4" + sign.suffix
		trunc64 := "I32X4TRUNCSATF64X2" + sign.suffix + "ZERO"
		add(trunc32, "", f32, i32, 4, sign.toInteger, false)
		add(trunc64, "", f64, i32, 2, sign.toInteger, false)
		// Relaxed truncation's deterministic profile saturates. The double
		// forms retain the same mandatory upper-lane zeroing.
		forms["I32X4RELAXEDTRUNCF32X4"+sign.suffix] = forms[trunc32]
		forms["I32X4RELAXEDTRUNCF64X2"+sign.suffix] = forms[trunc64]
	}
	add("F32X4DEMOTEF64X2ZERO", "fptrunc", f64, f32, 2, "", true)
	add("F64X2PROMOTELOWF32X4", "fpext", f32, f64, 2, "", true)
}
