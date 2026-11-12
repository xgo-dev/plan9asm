package plan9asm

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func wasmFloatArithmeticSamples(bits int) []uint64 {
	values := append([]uint64(nil), wasmFloatBinarySamples(bits)...)
	if bits == 32 {
		return append(values, 0x3f000000, 0xbf000000, 0x33800000, 0xb3800000,
			0x3f800001, 0xbf800001, 0x40000000, 0xc0000000)
	}
	return append(values, 0x3fe0000000000000, 0xbfe0000000000000,
		0x3ca0000000000000, 0xbca0000000000000, 0x3ff0000000000001,
		0xbff0000000000001, 0x4000000000000000, 0xc000000000000000)
}

// Use ordinary Go arithmetic at the declared precision, independently of the
// lowerer. Each expression performs only one operation, with explicit float32
// rounding where required. NaN signs/payloads follow the permitted Wasm set,
// not the host's particular NaN choice:
// https://webassembly.github.io/spec/core/exec/numerics.html#nan-propagation
func wasmFloatArithmeticReference(name string, a, b uint64) (uint64, int) {
	exponent, quiet := uint64(0x7ff0000000000000), uint64(1)<<51
	if strings.HasPrefix(name, "F32") {
		exponent, quiet = 0x7f800000, 1<<22
	}
	isNaN := func(value uint64) bool {
		return value&exponent == exponent && value&(quiet*2-1) != 0
	}
	if isNaN(a) || isNaN(b) {
		kind := 1
		if isNaN(a) && a&(quiet*2-1) != quiet || isNaN(b) && b&(quiet*2-1) != quiet {
			kind = 2
		}
		return exponent | quiet, kind
	}

	operation := name[3:]
	var result uint64
	if strings.HasPrefix(name, "F32") {
		x, y := math.Float32frombits(uint32(a)), math.Float32frombits(uint32(b))
		var value float32
		switch operation {
		case "Add":
			value = x + y
		case "Sub":
			value = x - y
		case "Mul":
			value = x * y
		case "Div":
			value = x / y
		default:
			panic("unknown independent Wasm arithmetic " + name)
		}
		result = uint64(math.Float32bits(value))
	} else {
		x, y := math.Float64frombits(a), math.Float64frombits(b)
		var value float64
		switch operation {
		case "Add":
			value = x + y
		case "Sub":
			value = x - y
		case "Mul":
			value = x * y
		case "Div":
			value = x / y
		default:
			panic("unknown independent Wasm arithmetic " + name)
		}
		result = math.Float64bits(value)
	}
	if isNaN(result) {
		// Invalid operations such as 0/0, Inf-Inf and Inf*0 have no NaN
		// input; Wasm permits either sign of the canonical NaN only.
		return exponent | quiet, 1
	}
	return result, 0
}

const wasmFloatArithmeticRuntimeCases = 8 * 2 * 2 * 28 * 28

func wasmFloatArithmeticRuntimeFixture(t *testing.T) (string, string, map[string]FuncSig, string, string, []byte) {
	t.Helper()
	return wasmFloatRuntimeFixture(t, wasmFloatArithmeticGoNames(t), wasmFloatArithmeticTypes,
		wasmFloatArithmeticSamples, wasmFloatArithmeticReference)
}

func TestWASMFloatArithmeticReferenceBoundaryControls(t *testing.T) {
	for _, row := range []struct {
		name    string
		a, b    uint64
		want    uint64
		nanKind int
	}{
		{"F32Add", 0x80000000, 0x80000000, 0x80000000, 0},
		{"F32Sub", 0x80000000, 0, 0x80000000, 0},
		{"F32Mul", 0x80000000, 0x3f800000, 0x80000000, 0},
		{"F32Div", 0x3f800000, 0x80000000, 0xff800000, 0},
		{"F32Add", 0x3f800000, 0x33800000, 0x3f800000, 0},
		{"F32Add", 0x3f800001, 0x33800000, 0x3f800002, 0},
		{"F32Mul", 0x7f7fffff, 0x40000000, 0x7f800000, 0},
		{"F32Div", 1, 0x40000000, 0, 0},
		{"F32Div", 3, 0x40000000, 2, 0},
		{"F32Div", 0, 0, 0x7fc00000, 1},
		{"F32Add", 0xffc00000, 0x3f800000, 0x7fc00000, 1},
		{"F32Sub", 0x7f800001, 0x3f800000, 0x7fc00000, 2},
		{"F64Add", 0x8000000000000000, 0x8000000000000000, 0x8000000000000000, 0},
		{"F64Sub", 0x8000000000000000, 0, 0x8000000000000000, 0},
		{"F64Mul", 0x8000000000000000, 0x3ff0000000000000, 0x8000000000000000, 0},
		{"F64Div", 0x3ff0000000000000, 0x8000000000000000, 0xfff0000000000000, 0},
		{"F64Add", 0x3ff0000000000000, 0x3ca0000000000000, 0x3ff0000000000000, 0},
		{"F64Add", 0x3ff0000000000001, 0x3ca0000000000000, 0x3ff0000000000002, 0},
		{"F64Mul", 0x7fefffffffffffff, 0x4000000000000000, 0x7ff0000000000000, 0},
		{"F64Div", 1, 0x4000000000000000, 0, 0},
		{"F64Div", 3, 0x4000000000000000, 2, 0},
		{"F64Sub", 0x7ff0000000000000, 0x7ff0000000000000, 0x7ff8000000000000, 1},
		{"F64Add", 0xfff8000000000000, 0x3ff0000000000000, 0x7ff8000000000000, 1},
		{"F64Div", 0x7ff8123456789abc, 0x3ff0000000000000, 0x7ff8000000000000, 2},
	} {
		got, nan := wasmFloatArithmeticReference(row.name, row.a, row.b)
		if got != row.want || nan != row.nanKind {
			t.Errorf("%s(%x,%x)=%x/NaN%d want=%x/NaN%d",
				row.name, row.a, row.b, got, nan, row.want, row.nanKind)
		}
	}
}

func TestWASMFloatArithmeticCompleteRuntimeUnion(t *testing.T) {
	for _, bits := range []int{32, 64} {
		seen := make(map[uint64]bool)
		for _, value := range wasmFloatArithmeticSamples(bits) {
			if seen[value] {
				t.Fatal("duplicate input shrinks the independent finite/NaN boundary matrix", bits, value)
			}
			seen[value] = true
		}
		if len(seen) != 28 {
			t.Fatal("incomplete precision-specific runtime sample axis", bits, len(seen))
		}
	}
	source, original, sigs, _, _, data := wasmFloatArithmeticRuntimeFixture(t)
	var rows []wasmFloatBinaryRuntimeRow
	if err := json.Unmarshal(data, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 32 || len(sigs) != 32 || strings.Count(source, "TEXT ") != 32 || strings.Count(original, "TEXT ") != 32 {
		t.Fatal("missing whole arithmetic/alias/dead source member", len(rows), len(sigs))
	}
	count := 0
	for _, row := range rows {
		if len(row.Cases) != 28*28 {
			t.Fatal("cropped independent arithmetic input matrix", row.Name, len(row.Cases))
		}
		count += len(row.Cases)
	}
	if count != wasmFloatArithmeticRuntimeCases {
		t.Fatal("incomplete arithmetic runtime denominator", count)
	}
}

func TestWASMFloatArithmeticOriginalGoRuntime(t *testing.T) {
	_, original, _, _, goSource, _ := wasmFloatArithmeticRuntimeFixture(t)
	wasmFloatRunOriginal(t, original, goSource, wasmFloatArithmeticRuntimeCases)
}

func TestWASMFloatArithmeticThreeAPIsFourOptimizationAxesRuntime(t *testing.T) {
	source, _, sigs, wrappers, _, inputs := wasmFloatArithmeticRuntimeFixture(t)
	wasmFloatRunLLVM(t, source, sigs, wrappers, inputs, wasmFloatArithmeticRuntimeCases)
}
