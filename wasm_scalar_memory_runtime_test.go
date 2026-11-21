package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWASMScalarMemoryNativeDifferential(t *testing.T) {
	type memoryCase struct {
		Name, Type      string
		Width, Encoding int
		Store           bool
	}
	fromBits := map[LLVMType]string{
		I32:      "I32WrapI64\n",
		"float":  "I32WrapI64\nF32ReinterpretI32\n",
		"double": "F64ReinterpretI64\n",
	}
	toBits := map[LLVMType]string{
		I32:      "I64ExtendI32U\n",
		"float":  "I32ReinterpretF32\nI64ExtendI32U\n",
		"double": "I64ReinterpretF64\n",
	}
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	var rows []memoryCase
	for index, row := range wasmScalarMemoryCases(t) {
		// The Go assembler encodes this contiguous range at 0x28..0x3e.
		rows = append(rows, memoryCase{row.name, string(row.typ), row.width, 0x28 + index, row.store})
		body := "Get R0\n"
		if row.store {
			body += "Get R1\n" + fromBits[row.typ]
		}
		body += row.name + " $3\n"
		if row.store {
			body += "I64Const $42\n"
		} else {
			body += toBits[row.typ]
		}
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", row.name, body)
		sigs[row.name] = FuncSig{Name: row.name, Args: []LLVMType{I32, I64}, ArgRegs: []Reg{"R0", "R1"}, Ret: I64}
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	matrix := filepath.Join(t.TempDir(), "cases.json")
	if err := os.WriteFile(matrix, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
		if err != nil {
			t.Fatal(err)
		}
		for _, level := range []string{"0", "2"} {
			t.Run(route+"/O"+level, func(t *testing.T) {
				runLLVMWASMObject(t, ir, level, wasmScalarMemoryDifferential, matrix)
			})
		}
	}
}

const wasmScalarMemoryDifferential = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const before = {i32: [0xa7], i64: [], float: [0xa7, 0xbe], double: [0xbf]};
const after = {i32: [0xad], i64: [], float: [0xbc, 0xad], double: [0xbd]};
const names = rows.map(({Name}, index) => [...vector([...Buffer.from(Name)]), 0, index]);
names.push([...vector([...Buffer.from('memory')]), 2, 0]);
const pages = translated.memory.buffer.byteLength / 65536;
const native = instantiate(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, [1, 0x60, 2, 0x7f, 0x7e, 1, 0x7e]),
  ...section(3, vector(rows.map(() => 0))),
  ...section(5, [1, 0, ...uleb(pages)]),
  ...section(7, vector(names)),
  ...section(10, vector(rows.map(({Type, Width, Encoding, Store}) => vector([
    0, 0x20, 0, ...(Store ? [0x20, 1, ...before[Type]] : []),
    Encoding, Math.log2(Width), 3, ...(Store ? [0x42, 42] : after[Type]), 0x0b,
  ])))),
]));
const input = new Uint8Array(native.memory.buffer);
const output = new Uint8Array(translated.memory.buffer);
function outcome(fn, address, bits) {
  try { return fn(address, bits); }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return 'trap';
  }
}
for (const {Name, Width} of rows) {
  const last = input.length - Width - 3;
  for (const address of [0, 3584, 3585, last, last + 1, input.length, 0xffffffff]) {
    for (const bits of [0n, 0xffffffffffffffffn, 0x987654328090a0b0n, 0x7f800001n, 0x7ff0000000000001n]) {
      const begin = Math.max(0, Math.min(input.length, address + 2));
      const end = Math.min(input.length, begin + Width + 2);
      for (let i = begin; i < end; i++) {
        input[i] = output[i] = 0x80 + i - begin;
      }
      const want = outcome(native[Name], address, bits);
      const got = outcome(translated[Name], address, bits);
      if (got !== want) throw Error(Name + '/' + address + ': got ' + got + ', want ' + want);
      for (let i = begin; i < end; i++) {
        if (input[i] !== output[i]) throw Error(Name + '/' + address + ': byte ' + i);
      }
    }
  }
}
`
