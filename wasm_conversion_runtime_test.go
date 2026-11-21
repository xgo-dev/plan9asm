package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWASMScalarConversionNativeDifferential(t *testing.T) {
	type conversion struct {
		Name, Source, Result string
		Encoding             []int
	}
	var rows []conversion
	var assembly strings.Builder
	sigs := make(map[string]FuncSig)
	fromBits := map[string]string{
		"I32": "I32WrapI64\n",
		"F32": "I32WrapI64\nF32ReinterpretI32\n",
		"F64": "F64ReinterpretI64\n",
	}
	toBits := map[string]string{
		"I32": "I64ExtendI32U\n",
		"F32": "I32ReinterpretF32\nI64ExtendI32U\n",
		"F64": "I64ReinterpretF64\n",
	}
	for index, name := range wasmConversionGoNames(t) {
		kinds := wasmConversionWidth.FindAllString(name, -1)
		input, output := kinds[len(kinds)-1], kinds[0]
		// Go's core conversion opcodes occupy 0xa7..0xc4. Saturating
		// conversions have the 0xfc prefix and a separate 0..7 range.
		encoding := []int{0xa7 + index}
		if index >= 30 {
			encoding = []int{0xfc, index - 30}
		}
		rows = append(rows, conversion{name, input, output, encoding})
		fmt.Fprintf(&assembly, "TEXT %s(SB),4,$0-0\nGet R0\n%s%s\n%sReturn\n", name, fromBits[input], name, toBits[output])
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: I64}
	}
	file, err := Parse(ArchWASM, assembly.String())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	matrix := filepath.Join(root, "conversions.json")
	if err := os.WriteFile(matrix, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	for _, triple := range []string{"wasm32-wasi", ""} {
		options := wasmPackedOptions(sigs, WASMABIDirect)
		options.TargetTriple = triple
		ir, err := Translate(file, options)
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"0", "2"} {
			t.Run(fmt.Sprintf("target=%s/O%s", triple, level), func(t *testing.T) {
				dir := t.TempDir()
				input, object, binary := filepath.Join(dir, "input.ll"), filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
				if err := os.WriteFile(input, []byte(ir), 0600); err != nil {
					t.Fatal(err)
				}
				if level == "2" {
					optimized := filepath.Join(dir, "optimized.ll")
					wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
					input = optimized
				}
				wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-mtriple=wasm32-unknown-unknown", "-O"+level, "-filetype=obj", input, "-o", object)
				wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", object, "-o", binary)
				wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", wasmScalarConversionDifferential, binary, matrix)
			})
		}
	}
}

const wasmScalarConversionDifferential = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const before = {I32: [0xa7], I64: [], F32: [0xa7, 0xbe], F64: [0xbf]};
const after = {I32: [0xad], I64: [], F32: [0xbc, 0xad], F64: [0xbd]};
const native = instantiate(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, [1, 0x60, 1, 0x7e, 1, 0x7e]),
  ...section(3, vector(rows.map(() => 0))),
  ...section(7, vector(rows.map(({Name}, i) => [
    ...vector([...Buffer.from(Name)]), 0, ...uleb(i),
  ]))),
  ...section(10, vector(rows.map(({Source, Result, Encoding}) => vector([
    0, 0x20, 0, ...before[Source], ...Encoding, ...after[Result], 0x0b,
  ])))),
]));
const inputs = new Set([
  0n, 1n, 0x7fn, 0x80n, 0xffn, 0x7fffn, 0x8000n, 0xffffn,
  0x7fffffffn, 0x80000000n, 0xffffffffn, 0x100000000n,
  0x7fffffffffffffffn, 0x8000000000000000n, 0xffffffffffffffffn,
  0x7f800001n, 0xffc12345n, 0x7ff0000000000001n, 0xfff8aaaa00000001n,
]);
const bits = new DataView(new ArrayBuffer(8));
for (const value of [0, -0, 0.5, -0.5, -0.999, -1, 1.75, NaN, Infinity, -Infinity,
                     2 ** -149, 2 ** -150, -(2 ** -150), 2 ** -126,
                     -(2 ** 31) - 0.75, -(2 ** 31) - 1, 2 ** 31 - 1, 2 ** 31,
                     2 ** 32 - 1, 2 ** 32, -(2 ** 63), 2 ** 63, 2 ** 64]) {
  bits.setFloat32(0, value);
  inputs.add(BigInt(bits.getUint32(0)));
  bits.setFloat64(0, value);
  inputs.add(bits.getBigUint64(0));
}
for (const input of [...inputs]) {
  inputs.add(input - 1n);
  inputs.add(input + 1n);
}
function outcome(func, input) {
  try { return BigInt.asUintN(64, func(input)); }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return 'trap';
  }
}
function quietNaN(bits, type) {
  if (bits === 'trap') return false;
  return type === 'F32' ? (bits & 0x7fc00000n) === 0x7fc00000n
                        : (bits & 0x7ff8000000000000n) === 0x7ff8000000000000n;
}
for (const {Name, Result} of rows) {
  for (const input of inputs) {
    const want = outcome(native[Name], input);
    const got = outcome(translated[Name], input);
    // For arithmetic conversions Wasm allows multiple quiet NaN payloads.
    // Reinterpret has to preserve the original bits, including signaling NaNs.
    if (got !== want && !(/Demote|Promote/.test(Name) && quietNaN(want, Result) && quietNaN(got, Result))) {
      throw Error(Name + '/' + input.toString(16) + ': got ' + got + ', want ' + want);
    }
  }
}
`

const wasmTestSectionJS = `
function uleb(value) {
  const bytes = [];
  for (; value >= 0x80; value >>>= 7) bytes.push((value & 0x7f) | 0x80);
  return [...bytes, value];
}
const vector = items => [...uleb(items.length), ...items.flat()];
const section = (id, body) => [id, ...uleb(body.length), ...body];
`
