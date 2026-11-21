package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wasmV128SpecializedMemoryCase struct {
	Opcode string
	Name   string
	Width  int
	Code   int
	Lane   int
	Store  bool
}

func wasmV128SpecializedMemoryCases() []wasmV128SpecializedMemoryCase {
	// Keep code numbers and access widths independent of the lowerer.
	rows := []wasmV128SpecializedMemoryCase{
		{Opcode: "V128Load8x8S", Width: 8, Code: 1, Lane: -1},
		{Opcode: "V128Load8x8U", Width: 8, Code: 2, Lane: -1},
		{Opcode: "V128Load16x4S", Width: 8, Code: 3, Lane: -1},
		{Opcode: "V128Load16x4U", Width: 8, Code: 4, Lane: -1},
		{Opcode: "V128Load32x2S", Width: 8, Code: 5, Lane: -1},
		{Opcode: "V128Load32x2U", Width: 8, Code: 6, Lane: -1},
		{Opcode: "V128Load8Splat", Width: 1, Code: 7, Lane: -1},
		{Opcode: "V128Load16Splat", Width: 2, Code: 8, Lane: -1},
		{Opcode: "V128Load32Splat", Width: 4, Code: 9, Lane: -1},
		{Opcode: "V128Load64Splat", Width: 8, Code: 10, Lane: -1},
		{Opcode: "V128Load32Zero", Width: 4, Code: 0x5c, Lane: -1},
		{Opcode: "V128Load64Zero", Width: 8, Code: 0x5d, Lane: -1},
	}
	for i, width := range []int{1, 2, 4, 8} {
		for lane := 0; lane < 16/width; lane++ {
			rows = append(rows,
				wasmV128SpecializedMemoryCase{Opcode: fmt.Sprintf("V128Load%dLane", width*8), Width: width, Code: 0x54 + i, Lane: lane},
				wasmV128SpecializedMemoryCase{Opcode: fmt.Sprintf("V128Store%dLane", width*8), Width: width, Code: 0x58 + i, Lane: lane, Store: true},
			)
		}
	}
	for i := range rows {
		rows[i].Name = fmt.Sprintf("specialized%d", i)
	}
	return rows
}

func wasmV128SpecializedMemorySource(rows []wasmV128SpecializedMemoryCase) string {
	var source strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", row.Name)
		if !row.Store {
			source.WriteString("Get R1\nI32WrapI64\n")
		}
		source.WriteString("Get R0\nI32WrapI64\n")
		if row.Lane >= 0 {
			source.WriteString("V128Const $0x2726252423222120,$0x2f2e2d2c2b2a2928\n")
		}
		fmt.Fprintf(&source, "%s $13", row.Opcode)
		if row.Lane >= 0 {
			fmt.Fprintf(&source, ",$%d", row.Lane)
		}
		source.WriteByte('\n')
		if !row.Store {
			source.WriteString("V128Store\n")
		}
		source.WriteString("Return\n")
	}
	return source.String()
}

func TestWASMV128SpecializedMemoryDifferential(t *testing.T) {
	rows := wasmV128SpecializedMemoryCases()
	if len(rows) != 72 {
		t.Fatal("incomplete specialized vector memory inventory", len(rows))
	}
	file, err := Parse(ArchWASM, wasmV128SpecializedMemorySource(rows))
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for index, fn := range file.Funcs {
		row := rows[index]
		sig, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil {
			t.Fatal(row.Opcode, err)
		}
		want := 2
		if row.Store {
			want = 1
		}
		if sig.Ret != Void || len(sig.Args) != want {
			t.Fatalf("%s inference %+v, want %d address inputs and void", row.Opcode, sig, want)
		}
		for i, reg := range sig.ArgRegs {
			if sig.Args[i] != I64 || reg != Reg(fmt.Sprintf("R%d", i)) {
				t.Fatalf("%s inference supplied the wrong register type: %+v", row.Opcode, sig)
			}
		}
		sigs[fn.Sym] = sig
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
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			t.Run(route+"/"+triple, func(t *testing.T) {
				options := wasmPackedOptions(sigs, WASMABIDirect)
				options.TargetTriple = triple
				ir, err := wasmPackedTranslate(t, file, options, route)
				if err != nil || ir == "" || strings.Contains(ir, "blockaddress") {
					t.Fatal("specialized vector memory translation rejected", err)
				}
				for _, level := range []string{"0", "2"} {
					t.Run("O"+level, func(t *testing.T) {
						runLLVMWASMObject(t, ir, level, wasmV128SpecializedMemoryOracle, matrix)
					})
				}
			})
		}
	}
}

func TestWASMV128SpecializedMemoryRejectsMalformedSource(t *testing.T) {
	for _, body := range []string{
		"RET\nV128Load16Splat",
		"RET\nV128Load8x8U $4294967296",
		"RET\nV128Load32Zero $-1",
		"RET\nV128Load64Zero.invalid $0",
		"RET\nV128Load8Lane $0,$16",
		"RET\nV128Load16Lane $0,$-1",
		"RET\nV128Load32Lane $0,$1.5",
		"RET\nV128Store64Lane $0",
		"RET\nV128Store64Lane $0,$1,$1",
		"RET\nV128Store8Lane 0(R0),$1",
		"I32Const $0\nI32Const $0\nV128Load16Lane $0,$0",
		"I32Const $0\nV128Store64Lane $0,$0",
		"I64Const $0\nV128Load64Splat $0",
	} {
		file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+body+"\nRET\n")
		if err != nil {
			continue
		}
		if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
			t.Errorf("inference accepted %q", body)
		}
		sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
		if out, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil || out != "" {
			t.Errorf("translation accepted %q", body)
		}
	}
}

const wasmV128SpecializedMemoryOracle = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const prefix = [0xfd];
const seed = [...prefix, 0x0c, ...Array.from({length:16}, (_, i) => 0x20+i)];
const names = rows.map(({Name}, i) => [...vector([...Buffer.from(Name)]), 0, ...uleb(i)]);
names.push([...vector([...Buffer.from('memory')]), 2, 0]);
const pages = translated.memory.buffer.byteLength / 65536;
const native = instantiate(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, [2, 0x60, 1, 0x7e, 0, 0x60, 2, 0x7e, 0x7e, 0]),
  ...section(3, vector(rows.map(({Store}) => Store ? 0 : 1))),
  ...section(5, [1, 0, ...uleb(pages)]),
  ...section(7, vector(names)),
  ...section(10, vector(rows.map(({Code,Lane,Store}) => vector([
    0, ...(Store ? [] : [0x20,1,0xa7]), 0x20,0,0xa7, ...(Lane >= 0 ? seed : []),
    ...prefix, ...uleb(Code), 0, 13, ...(Lane >= 0 ? [Lane] : []),
    ...(Store ? [] : [...prefix,0x0b,0,0]), 0x0b,
  ])))),
]));
const input = new Uint8Array(native.memory.buffer);
const output = new Uint8Array(translated.memory.buffer);
const boundary = input.length;
const destination = 8192;
function trapped(fn, address) {
  try { fn(BigInt(address), BigInt(destination)); return false; }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return true;
  }
}
for (const {Name, Opcode, Width, Lane} of rows) {
  const last = boundary - Width - 13;
  for (const address of [0, 3584, 3585, last, last+1, boundary, 0xffffffff]) {
    const start = Math.min(address, boundary-32);
    const ranges = [[0,32], [destination-1,18], [start,32]];
    for (const [begin, width] of ranges) {
      for (let i = 0; i < width; i++) input[begin+i] = output[begin+i] = (0x70 + 19*i) & 255;
    }
    const where = Opcode + '/' + Lane + '/' + address;
    if (trapped(native[Name], address) !== trapped(translated[Name], address)) {
      throw Error(where + ' memory trap differs');
    }
    for (const [begin, width] of ranges) {
      for (let i = begin; i < begin + width; i++) {
        if (input[i] !== output[i]) throw Error(where + ' memory byte ' + i + ' differs');
      }
    }
  }
}
`
