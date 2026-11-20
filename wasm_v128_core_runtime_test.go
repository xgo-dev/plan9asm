package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wasmV128CoreObservation struct {
	Name string
	Want uint32
}

// Whole-bit Wasm relations, independent of the translator's representation.
// Core-only observation uses XOR/AnyTrue, not new memory/extraction opcodes.
func wasmV128CoreReference(name string, a, b, mask [2]uint64) [2]uint64 {
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

func wasmV128CoreRuntimeFixture(t *testing.T) (string, string, string, map[string]FuncSig, []byte) {
	t.Helper()
	patterns := [][3][2]uint64{
		{{0, 0}, {0, 0}, {0, 0}},
		{{^uint64(0), ^uint64(0)}, {0, 0}, {^uint64(0), 0}},
		{{0, 1 << 63}, {1 << 63, 0}, {0, ^uint64(0)}},
		{{1, 0}, {0, ^uint64(0)}, {0x5555555555555555, 0xaaaaaaaaaaaaaaaa}},
		{{0x0123456789abcdef, 0xfedcba9876543210}, {0x89abcdef01234567, 0x76543210fedcba98}, {0xf0f00f0ff0f00f0f, 0x0f0ff0f00f0ff0f0}},
		{{0x8000000000000000, 0x7fffffffffffffff}, {0x7fffffffffffffff, 0x8000000000000000}, {^uint64(0), ^uint64(0)}},
	}
	var source, original, program strings.Builder
	program.WriteString("package main\nimport \"fmt\"\n")
	sigs := make(map[string]FuncSig)
	var rows []wasmV128CoreObservation
	for _, name := range wasmV128CoreNames() {
		for _, pattern := range patterns {
			a, b, mask := pattern[0], pattern[1], pattern[2]
			function := fmt.Sprintf("core%d", len(rows))
			body, want := wasmV128CoreBody(name, a, b, mask), uint32(0)
			if name == "V128AnyTrue" {
				if a[0] != 0 || a[1] != 0 {
					want = 1
				}
			} else {
				body += wasmV128CoreConstant(wasmV128CoreReference(name, a, b, mask)) + "V128Xor\nV128AnyTrue\n"
			}
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", function, body)
			fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-4\nGet SP\n%sI32Store ret+0(FP)\nRET\n", function, body)
			fmt.Fprintf(&program, "func %s() uint32\n", function)
			sigs[function] = FuncSig{Name: function, Ret: I32}
			rows = append(rows, wasmV128CoreObservation{Name: function, Want: want})
		}
	}
	if len(rows) != 48 {
		t.Fatal("complete eight-member, six-pattern observation inventory changed", len(rows))
	}
	program.WriteString("func main() {\n")
	for _, row := range rows {
		fmt.Fprintf(&program, "if got := %s(); got != %d { panic(fmt.Sprintf(\"%s: %%d\", got)) }\n", row.Name, row.Want, row.Name)
	}
	program.WriteString("fmt.Println(\"V128 core PASS 48\")\n}\n")
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	return source.String(), original.String(), program.String(), sigs, data
}

func TestWASMV128CoreThreeAPIsLLVMRuntime(t *testing.T) {
	source, _, _, sigs, rows := wasmV128CoreRuntimeFixture(t)
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
				if strings.TrimSpace(output) != "V128 core PASS 48" {
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
