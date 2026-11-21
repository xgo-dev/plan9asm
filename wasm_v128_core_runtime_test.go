package plan9asm

import (
	"encoding/json"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wasmV128CoreObservation struct {
	Name string
	Want uint32
}

const wasmV128CoreObservations = 3100

var wasmV128CorePass = fmt.Sprintf("V128 core PASS %d", wasmV128CoreObservations)

func wasmV128CoreScalarResult(name string) bool {
	_, op := wasmV128IntegerParts(name)
	return name == "V128AnyTrue" || op == "AllTrue" || op == "Bitmask"
}

// Whole-bit Wasm relations, independent of the translator's representation.
// Observation uses XOR/AnyTrue so it requires no vector store or extraction.
func wasmV128CoreReference(name string, a, b, mask [2]uint64) [2]uint64 {
	if bits, op := wasmV128IntegerParts(name); bits != 0 {
		if strings.HasPrefix(op, "Ext") {
			return wasmV128IntegerWideningReference(op, bits, a, b)
		}
		if strings.HasPrefix(op, "Narrow") {
			return wasmV128IntegerNarrowingReference(op, bits, a, b)
		}
		return wasmV128IntegerReference(op, bits, a, b)
	}
	var result [2]uint64
	for half := range result {
		switch name {
		case "V128Const":
			result[half] = a[half]
		case "V128Not":
			result[half] = ^a[half]
		case "V128And":
			result[half] = a[half] & b[half]
		case "V128Andnot":
			result[half] = a[half] &^ b[half]
		case "V128Or":
			result[half] = a[half] | b[half]
		case "V128Xor":
			result[half] = a[half] ^ b[half]
		case "V128Bitselect":
			result[half] = a[half]&mask[half] | b[half]&^mask[half]
		default:
			panic("not a vector-result core reference: " + name)
		}
	}
	return result
}

func wasmV128IntegerReference(op string, width uint, a, b [2]uint64) [2]uint64 {
	mask := uint64(1)<<width - 1
	signExtend := func(x uint64) int64 { return int64(x<<(64-width)) >> (64 - width) }
	shift := uint(b[0]) % width
	var result [2]uint64
	for half := range result {
		for offset := uint(0); offset < 64; offset += width {
			x, y := a[half]>>offset&mask, b[half]>>offset&mask
			var lane uint64
			switch op {
			case "Abs":
				lane = x
				if signExtend(x) < 0 {
					lane = -x
				}
			case "Neg":
				lane = -x
			case "Popcnt":
				lane = uint64(bits.OnesCount64(x))
			case "Shl":
				lane = x << shift
			case "ShrS":
				lane = uint64(signExtend(x) >> shift)
			case "ShrU":
				lane = x >> shift
			case "Add":
				lane = x + y
			case "Sub":
				lane = x - y
			case "Mul":
				lane = x * y
			case "AddSatU":
				lane = x + y
				if lane > mask {
					lane = mask
				}
			case "SubSatU":
				if x > y {
					lane = x - y
				}
			case "AddSatS", "SubSatS":
				delta := signExtend(y)
				if op == "SubSatS" {
					delta = -delta
				}
				value := signExtend(x) + delta
				limit := int64(1) << (width - 1)
				if value < -limit {
					value = -limit
				} else if value >= limit {
					value = limit - 1
				}
				lane = uint64(value)
			default:
				lane = wasmV128IntegerOrderingReference(op, width, x, y)
			}
			result[half] |= (lane & mask) << offset
		}
	}
	return result
}

func wasmV128CoreRuntimeFixture(t *testing.T) (string, string, string, map[string]FuncSig, []byte) {
	t.Helper()
	patterns := [][3][2]uint64{
		{{0, 0}, {0, 0}, {0, 0}},
		{{^uint64(0), ^uint64(0)}, {0, 0}, {^uint64(0), 0}},
		{{0, 1 << 63}, {1 << 63, 0}, {0, ^uint64(0)}},
		{{1, 0}, {0, ^uint64(0)}, {0x5555555555555555, 0xaaaaaaaaaaaaaaaa}},
		{{0x0123456789abcdef, 0xfedcba9876543210}, {0x89abcdef01234567, 0x76543210fedcba98}, {0xf0f00f0ff0f00f0f, 0x0f0ff0f00f0ff0f0}},
		{{0x8000000000000000, 0x7fffffffffffffff}, {0x7fffffffffffffff, 0x8000000000000000}, {^uint64(0), ^uint64(0)}},
		{{0x7f7f7f7f7f7f7f7f, 0x7fff7fff7fff7fff}, {0x0101010101010101, 0x0001000100010001}, {0, 0}},
		{{0x8080808080808080, 0x8000800080008000}, {^uint64(0), ^uint64(0)}, {0, 0}},
		{{0x8080808080808080, 0x7fff7fff7fff7fff}, {0x0101010101010101, ^uint64(0)}, {0, 0}},
		{{^uint64(0), 0}, {0x0101010101010101, ^uint64(0)}, {0, 0}},
	}
	var source, original, program strings.Builder
	program.WriteString("package main\nimport \"fmt\"\n")
	sigs := make(map[string]FuncSig)
	var rows []wasmV128CoreObservation
	add := func(body string, want uint32) {
		function := fmt.Sprintf("core%d", len(rows))
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", function, body)
		fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-4\nGet SP\n%sI32Store ret+0(FP)\nRET\n", function, body)
		fmt.Fprintf(&program, "func %s() uint32\n", function)
		sigs[function] = FuncSig{Name: function, Ret: I32}
		rows = append(rows, wasmV128CoreObservation{Name: function, Want: want})
	}
	for _, name := range wasmV128CoreNames() {
		if form, ok := wasmV128ConversionTestLookup(name); ok {
			if strings.Contains(name, "RelaxedTrunc") {
				// The relaxed forms have a separate original-machine oracle.
				continue
			}
			for _, input := range form.inputs() {
				add(form.comparisonBody(input), 0)
			}
			continue
		}
		inputs := patterns
		if bits, _ := wasmV128FloatParts(name); bits != 0 {
			inputs = wasmV128FloatPatterns(bits)
		} else if bits, op := wasmV128IntegerParts(name); op != "" {
			switch {
			case wasmV128IntegerOrdering(op):
				inputs = wasmV128IntegerOrderingPatterns(bits)
			case strings.HasPrefix(op, "Ext"):
				inputs = wasmV128IntegerOrderingPatterns(bits / 2)
			case strings.HasPrefix(op, "Narrow"):
				inputs = wasmV128IntegerNarrowingPatterns(op, bits)
			}
		}
		for index, pattern := range inputs {
			a, b, mask := pattern[0], pattern[1], pattern[2]
			integerWidth, integerOp := wasmV128IntegerParts(name)
			if wasmV128IntegerShift(integerOp) {
				width := uint64(integerWidth)
				counts := [...]uint64{0, 1, width - 1, width, width + 1, 2 * width, 2*width + 1, 1 << 31, 0xfffffffe, 0xffffffff}
				a = [2]uint64{0x80ff00bd017e42f1, 0x7fff80000001ea42}
				b[0] = counts[index]
			}
			body, want := wasmV128CoreBody(name, a, b, mask), uint32(0)
			if name == "V128AnyTrue" {
				if a[0] != 0 || a[1] != 0 {
					want = 1
				}
			} else if wasmV128CoreScalarResult(name) {
				want = wasmV128IntegerReductionReference(integerOp, integerWidth, a)
			} else if bits, op := wasmV128FloatParts(name); op != "" {
				expected, comparisonMask := wasmV128FloatReference(bits, op, a, b)
				body += wasmV128CoreConstant(comparisonMask) + "V128And\n" + wasmV128CoreConstant(expected) + "V128Xor\nV128AnyTrue\n"
			} else {
				body += wasmV128CoreConstant(wasmV128CoreReference(name, a, b, mask)) + "V128Xor\nV128AnyTrue\n"
			}
			add(body, want)
		}
	}
	for _, form := range wasmV128LaneTestForms() {
		for _, datum := range []struct {
			vector [2]uint64
			scalar uint64
		}{
			{[2]uint64{0, 0}, 0},
			{[2]uint64{0xffffffffffffffff, 0xffffffffffffffff}, 0xffffffffffffffff},
			{[2]uint64{0x80007f80ff018001, 0x807ff1e0d0c0b0a0}, 0x80c4ff7fbb00f981},
			{[2]uint64{0x8000000080000000, 0x8000000000000000}, 0x8000000080000000},
			{[2]uint64{0x7fa543217fc54321, 0x7ff0000000000021}, 0x7ff000017fa54321},
			{[2]uint64{0xfff8123456789abc, 0x7ff01234ffa12345}, 0xfff81234ffc12345},
		} {
			add(form.numericRuntimeBody(datum.vector, datum.scalar), 0)
		}
	}
	if len(rows) != wasmV128CoreObservations {
		t.Fatal("complete vector observation inventory changed", len(rows))
	}
	program.WriteString("func main() {\n")
	for _, row := range rows {
		fmt.Fprintf(&program, "if got := %s(); got != %d { panic(fmt.Sprintf(\"%s: %%d\", got)) }\n", row.Name, row.Want, row.Name)
	}
	fmt.Fprintf(&program, "fmt.Println(%q)\n}\n", wasmV128CorePass)
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return source.String(), original.String(), program.String(), sigs, data
}

func TestWASMV128CoreThreeAPIsLLVMRuntime(t *testing.T) {
	source, _, _, sigs, rows := wasmV128CoreRuntimeFixture(t)
	wasmV128CompareLLVMRuntime(t, source, sigs, rows, wasmV128CorePass)
}

func wasmV128CompareLLVMRuntime(t *testing.T, source string, sigs map[string]FuncSig, rows []byte, pass string) {
	t.Helper()
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
		if err != nil {
			t.Fatal(err)
		}
		for _, optimize := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/IR-O2=%t", route, optimize), func(t *testing.T) {
				dir := t.TempDir()
				input, object, binary := filepath.Join(dir, "input.ll"), filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
				if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				if optimize {
					optimized := filepath.Join(dir, "optimized.ll")
					wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
					input = optimized
				}
				wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-filetype=obj", input, "-o", object)
				wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", object, "-o", binary)
				inputs := filepath.Join(dir, "inputs.json")
				if err := os.WriteFile(inputs, rows, 0600); err != nil {
					t.Fatal(err)
				}
				output := wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", wasmV128CoreNodeCheck, binary, inputs)
				if strings.TrimSpace(output) != pass {
					t.Fatal("incomplete V128 core execution", output)
				}
			})
		}
	}
}

const wasmV128CoreNodeCheck = `
const fs = require('fs');
WebAssembly.instantiate(fs.readFileSync(process.argv[1]), {}).then(({instance:{exports:e}}) => {
  const rows = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  let count = 0;
  for (const row of rows) {
    const got = e[row.Name]();
    if (got !== row.Want) throw Error(row.Name + ': ' + got + ' want ' + row.Want);
    count++;
  }
  console.log('V128 core PASS ' + count);
}).catch(error => { console.error(error); process.exit(1); });
`
