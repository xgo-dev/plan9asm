package plan9asm

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestWASMV128FloatAliasedInputsPreserveNaNSemantics(t *testing.T) {
	var source, wrappers strings.Builder
	sigs := make(map[string]FuncSig)
	var rows []wasmFloatBinaryRuntimeRow
	for _, opcode := range wasmV128CoreNames() {
		if _, ok := wasmV128ConversionTestLookup(opcode); ok {
			continue
		}
		bits, operation := wasmV128FloatParts(opcode)
		if bits == 0 {
			continue
		}
		name := "alias" + opcode
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%s%s\nReturn\n",
			name, strings.Repeat("Get V0\n", wasmV128CoreInputs(opcode)), opcode)
		sigs[name] = FuncSig{
			Name: name, Ret: "<4 x i32>", Args: []LLVMType{"<4 x i32>"}, ArgRegs: []Reg{"V0"},
		}
		fmt.Fprintf(&wrappers, "define i64 @probe_%s(i64 %%bits, i64 %%unused) {\n", name)
		if bits == 32 {
			wrappers.WriteString("  %lane = trunc i64 %bits to i32\n")
			wrappers.WriteString("  %arg = insertelement <4 x i32> zeroinitializer, i32 %lane, i32 0\n")
			fmt.Fprintf(&wrappers, "  %%out = call <4 x i32> @%s(<4 x i32> %%arg)\n", name)
			wrappers.WriteString("  %element = extractelement <4 x i32> %out, i32 0\n")
			wrappers.WriteString("  %answer = zext i32 %element to i64\n")
		} else {
			wrappers.WriteString("  %vector = insertelement <2 x i64> zeroinitializer, i64 %bits, i32 0\n")
			wrappers.WriteString("  %arg = bitcast <2 x i64> %vector to <4 x i32>\n")
			fmt.Fprintf(&wrappers, "  %%out = call <4 x i32> @%s(<4 x i32> %%arg)\n", name)
			wrappers.WriteString("  %raw = bitcast <4 x i32> %out to <2 x i64>\n")
			wrappers.WriteString("  %answer = extractelement <2 x i64> %raw, i32 0\n")
		}
		wrappers.WriteString("  ret i64 %answer\n}\n")
		row := wasmFloatBinaryRuntimeRow{Name: name, Bits: bits}
		for _, input := range wasmFloatBinarySamples(bits) {
			value, nan := wasmV128FloatLaneReference(bits, operation, input, input, uint64(1)<<(bits-1))
			row.Cases = append(row.Cases, wasmFloatBinaryReference{
				A: strconv.FormatUint(input, 10), B: "0", Want: strconv.FormatUint(value, 10), NaN: nan,
			})
		}
		rows = append(rows, row)
	}
	if len(rows) != 42 {
		t.Fatal("incomplete dynamic floating SIMD inventory", len(rows))
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	wasmFloatRunLLVM(t, source.String(), sigs, wrappers.String(), data, 840)
}

func wasmV128FloatParts(name string) (int, string) {
	if op, ok := strings.CutPrefix(name, "F32x4"); ok {
		return 32, op
	}
	if op, ok := strings.CutPrefix(name, "F64x2"); ok {
		return 64, op
	}
	return 0, ""
}

func wasmV128FloatPatterns(bits int) [][3][2]uint64 {
	samples := wasmFloatBinarySamples(bits)
	raw := math.Float64bits
	if bits == 32 {
		raw = func(value float64) uint64 { return uint64(math.Float32bits(float32(value))) }
	}
	pairs := [][2]uint64{
		{samples[0], samples[1]}, {samples[1], samples[0]},
		{samples[16], raw(3.0)}, {raw(3.0), samples[17]}, {samples[16], samples[17]},
		{samples[12], samples[13]}, {samples[13], samples[12]},
		{samples[18], raw(-2.0)}, {raw(2.0), samples[19]},
		{samples[3], samples[2]}, {samples[10], raw(2.0)},
		{raw(-0.5), raw(0.5)}, {raw(-1.5), raw(1.5)}, {raw(2.5), raw(-2.5)},
		{raw(-4.0), raw(2.0)}, {raw(9.0), raw(-3.0)},
	}
	patterns := make([][3][2]uint64, len(pairs))
	for i := range patterns {
		for lane := 0; lane < 128/bits; lane++ {
			values := pairs[(i+3*lane)%len(pairs)]
			half, shift := lane*bits/64, lane*bits%64
			patterns[i][0][half] |= values[0] << shift
			patterns[i][1][half] |= values[1] << shift
		}
	}
	return patterns
}

func wasmV128FloatReference(bits int, op string, a, b [2]uint64) (want, mask [2]uint64) {
	all := uint64(1)<<uint(bits) - 1
	sign, exponent, quiet := uint64(1)<<63, uint64(0x7ff0000000000000), uint64(1)<<51
	if bits == 32 {
		sign, exponent, quiet = 1<<31, 0x7f800000, 1<<22
	}
	for i := range want {
		for shift := 0; shift < 64; shift += bits {
			x, y := a[i]>>shift&all, b[i]>>shift&all
			value, nan := wasmV128FloatLaneReference(bits, op, x, y, sign)
			comparisonMask := all
			if nan != 0 {
				value = exponent | quiet
				comparisonMask = all &^ sign
				if nan == 2 {
					comparisonMask = value
				}
			}
			want[i] |= value << shift
			mask[i] |= comparisonMask << shift
		}
	}
	return want, mask
}

func wasmV128FloatLaneReference(bits int, op string, a, b, sign uint64) (uint64, int) {
	name := "F" + strconv.Itoa(bits) + op
	switch op {
	case "Add", "Sub", "Mul", "Div":
		return wasmFloatArithmeticReference(name, a, b)
	case "Min", "Max":
		return wasmFloatBinaryReferenceValue(name, a, b)
	case "Eq", "Ne", "Lt", "Gt", "Le", "Ge":
		predicate, _ := wasmFloatBinaryReferenceValue(name, a, b)
		return (uint64(1)<<uint(bits) - 1) * predicate, 0
	case "Abs":
		return a &^ sign, 0
	case "Neg":
		return a ^ sign, 0
	}
	x, y := math.Float64frombits(a), math.Float64frombits(b)
	if bits == 32 {
		x, y = float64(math.Float32frombits(uint32(a))), float64(math.Float32frombits(uint32(b)))
	}
	var value float64
	switch op {
	case "Pmin", "Pmax":
		if op == "Pmin" && y < x || op == "Pmax" && x < y {
			return b, 0
		}
		return a, 0
	case "Sqrt":
		value = math.Sqrt(x)
	case "Ceil":
		value = math.Ceil(x)
	case "Floor":
		value = math.Floor(x)
	case "Trunc":
		value = math.Trunc(x)
	case "Nearest":
		value = math.RoundToEven(x)
	default:
		panic("unknown floating vector operation: " + op)
	}
	if math.IsNaN(value) {
		return 0, 2
	}
	if bits == 32 {
		return uint64(math.Float32bits(float32(value))), 0
	}
	return math.Float64bits(value), 0
}
