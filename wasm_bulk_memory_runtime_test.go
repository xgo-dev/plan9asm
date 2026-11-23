package plan9asm

import (
	"strings"
	"testing"
)

func TestWASMBulkMemoryNativeDifferential(t *testing.T) {
	file, err := Parse(ArchWASM, `
TEXT Copy(SB),4,$0-0
Get R0
Get R1
Get R2
MemoryCopy
Return

TEXT Fill(SB),4,$0-0
Get R0
Get R1
Get R2
MemoryFill
Return

TEXT CopyZero(SB),4,$0-0
Get R0
Get R1
I32Const $0
MemoryCopy
Return

TEXT FillZero(SB),4,$0-0
Get R0
Get R1
I32Const $0
MemoryFill
Return

TEXT CopyFixed(SB),4,$0-0
Get R0
Get R1
I32Const $8
MemoryCopy
Return

TEXT FillFixed(SB),4,$0-0
Get R0
Get R1
I32Const $8
MemoryFill
Return

TEXT FillAtZero(SB),4,$0-0
I32Const $0
Get R1
I32Const $8
MemoryFill
Return

TEXT Size(SB),4,$0-0
CurrentMemory
Return

TEXT Grow(SB),4,$0-0
Get R0
GrowMemory
Return
`)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		sigs[fn.Sym] = FuncSig{
			Name: fn.Sym, Args: []LLVMType{I32, I32, I32}, ArgRegs: []Reg{"R0", "R1", "R2"}, Ret: Void,
		}
	}
	sigs["Size"] = FuncSig{Name: "Size", Ret: I32}
	sigs["Grow"] = FuncSig{Name: "Grow", Args: []LLVMType{I32}, ArgRegs: []Reg{"R0"}, Ret: I32}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(ir, "blockaddress") {
			t.Fatal("WebAssembly IR contains blockaddress")
		}
		for _, level := range []string{"0", "2"} {
			t.Run(route+"/O"+level, func(t *testing.T) {
				runLLVMWASMObject(t, ir, level, wasmBulkMemoryDifferential)
			})
		}
	}
}

const wasmBulkMemoryDifferential = `
const fs = require('fs');
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const names = ['Copy', 'Fill', 'CopyZero', 'FillZero', 'CopyFixed', 'FillFixed', 'FillAtZero'];
const allNames = [...names, 'Size', 'Grow'];
const isCopy = name => name.startsWith('Copy');
const pages = translated.memory.buffer.byteLength / 65536;
const bodies = names.map((name, i) => vector([
  0, ...(name === 'FillAtZero' ? [0x41, 0] : [0x20, 0]), 0x20, 1,
  ...(i < 2 ? [0x20, 2] : [0x41, i < 4 ? 0 : 8]),
  0xfc, ...(isCopy(name) ? [10, 0, 0] : [11, 0]), 0x0b,
]));
bodies.push(vector([0, 0x3f, 0, 0x0b]), vector([0, 0x20, 0, 0x40, 0, 0x0b]));
const native = instantiate(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, vector([[0x60, 3, 0x7f, 0x7f, 0x7f, 0], [0x60, 0, 1, 0x7f], [0x60, 1, 0x7f, 1, 0x7f]])),
  ...section(3, vector([...names.map(() => 0), 1, 2])),
  ...section(5, [1, 0, ...uleb(pages)]),
  ...section(7, vector([
    ...allNames.map((name, i) => [...vector([...Buffer.from(name)]), 0, i]),
    [...vector([...Buffer.from('memory')]), 2, 0],
  ])),
  ...section(10, vector(bodies)),
]));
const output = new Uint8Array(translated.memory.buffer);
const expected = new Uint8Array(native.memory.buffer);
const end = output.length;
function outcome(fn, args) {
  try { fn(...args); return 'returned'; }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return 'trap';
  }
}
const copy = [
  [3500, 3505, 12], [3505, 3500, 12], [0, 3500, 8], [3500, 0, 8],
  [end - 4, 3500, 4], [3500, end - 4, 4],
  [end - 4, 3500, 5], [3500, end - 4, 5], [3500, 3501, 0xffffffff],
  [end, end, 0], [end + 1, end, 0], [end, end + 1, 0], [0xffffffff, 3500, 0],
];
const fill = [
  [3500, 0x123, 12], [0, 0x123, 8], [end - 4, -1, 4], [end - 4, 0x55, 5], [3500, 0x123, 0xffffffff],
  [end, 23, 0], [end + 1, 23, 0], [0xffffffff, 23, 0],
];
for (const name of names) {
  for (const args of (isCopy(name) ? copy : fill)) {
    for (let offset = 0; offset < end; offset++) {
      output[offset] = expected[offset] = offset & 255;
    }
    const want = outcome(native[name], args);
    const got = outcome(translated[name], args);
    if (got !== want) throw Error(name + '/' + args + ': got ' + got + ', want ' + want);
    if (!Buffer.from(output).equals(Buffer.from(expected))) {
      throw Error(name + '/' + args + ': different memory contents');
    }
  }
}
if (translated.Size() !== pages) throw Error('incorrect initial memory size');
for (const delta of [0, 1, -1, 2]) {
  const result = translated.Grow(delta);
  const want = native.Grow(delta);
  if (result !== want || translated.Size() !== native.Size()) {
    throw Error('incorrect memory growth by ' + delta + ': got ' + result + ', want ' + want);
  }
  if (!Buffer.from(translated.memory.buffer).equals(Buffer.from(native.memory.buffer))) {
    throw Error('different memory after growth by ' + delta);
  }
}
`
