package plan9asm

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type wasmV128RoutingCase struct {
	Name   string
	Opcode string
	Code   int
	Mask   []int
	Lane   int
}

func wasmV128RoutingCases() []wasmV128RoutingCase {
	return []wasmV128RoutingCase{
		{Name: "swizzle", Opcode: "I8x16Swizzle", Code: 0x0e},
		{Name: "relaxedSwizzle", Opcode: "I8x16RelaxedSwizzle", Code: 0x100},
		{Name: "shuffleHigh", Opcode: "I8x16Shuffle16", Code: 0x0d,
			Mask: []int{31, 0, 30, 1, 29, 2, 28, 3, 27, 4, 26, 5, 25, 6, 24, 7}},
		{Name: "shuffleLow", Opcode: "I8x16Shuffle16", Code: 0x0d,
			Mask: []int{23, 8, 22, 9, 21, 10, 20, 11, 19, 12, 18, 13, 17, 14, 16, 15}},
		{Name: "select8", Opcode: "I8x16RelaxedLaneselect", Code: 0x109, Lane: 1},
		{Name: "select16", Opcode: "I16x8RelaxedLaneselect", Code: 0x10a, Lane: 2},
		{Name: "select32", Opcode: "I32x4RelaxedLaneselect", Code: 0x10b, Lane: 4},
		{Name: "select64", Opcode: "I64x2RelaxedLaneselect", Code: 0x10c, Lane: 8},
	}
}

func wasmV128RoutingSource(rows []wasmV128RoutingCase) string {
	var source strings.Builder
	for _, row := range rows {
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", row.Name)
		source.WriteString("I32Const $128\nI32Const $32\nV128Load $0\nI32Const $64\nV128Load $0\n")
		if row.Lane != 0 {
			source.WriteString("I32Const $96\nV128Load $0\n")
		}
		source.WriteString(row.Opcode)
		if row.Mask != nil {
			var mask [16]byte
			for i, index := range row.Mask {
				mask[i] = byte(index)
			}
			fmt.Fprintf(&source, " $0x%x,$0x%x", binary.LittleEndian.Uint64(mask[:8]), binary.LittleEndian.Uint64(mask[8:]))
		}
		source.WriteString("\nV128Store\nReturn\n")
	}
	return source.String()
}

func TestWASMV128RoutingDifferential(t *testing.T) {
	rows := wasmV128RoutingCases()
	checkWASMV128MemoryRuntime(t, wasmV128RoutingSource(rows), rows, wasmV128RoutingOracle)
}

func checkWASMV128MemoryRuntime(t *testing.T, source string, rows any, oracle string, nodeFlags ...string) {
	t.Helper()
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := make(map[string]FuncSig)
	for _, fn := range file.Funcs {
		sig, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || sig.Ret != Void || len(sig.Args) != 0 {
			t.Fatalf("%s inference = %+v / %v, want no arguments and void", fn.Sym, sig, err)
		}
		sigs[fn.Sym] = sig
	}
	data, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	matrix := filepath.Join(t.TempDir(), "matrix.json")
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
					t.Fatal("SIMD memory-kernel translation failed", err)
				}
				for _, level := range []string{"0", "2"} {
					t.Run("O"+level, func(t *testing.T) {
						runLLVMWASMObjectWithNodeFlags(t, ir, level, oracle, nodeFlags, matrix)
					})
				}
			})
		}
	}
}

func TestWASMV128RoutingRejectsMalformedSource(t *testing.T) {
	for _, body := range []string{
		"RET\nI8x16Shuffle16",
		"RET\nI8x16Shuffle16 $0,$0,$0",
		"RET\nI8x16Shuffle16 $1.5,$0",
		"RET\nI8x16Shuffle16 $0x20,$0",
		"RET\nI8x16Shuffle16 $0,$0x2000000000000000",
		"RET\nI8x16Shuffle16 $-1,$0",
		"RET\nI8x16Swizzle $0",
		"RET\nI64x2RelaxedLaneselect.invalid",
		"V128Const $0,$0\nI8x16RelaxedSwizzle",
		"V128Const $0,$0\nV128Const $0,$0\nI32Const $0\nI16x8RelaxedLaneselect",
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

const wasmV128MemoryKernelJS = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
function nativeMemory(arity, kernels = rows) {
  const names = kernels.map(({Name}, i) => [...vector([...Buffer.from(Name)]), 0, ...uleb(i)]);
  names.push([...vector([...Buffer.from('memory')]), 2, 0]);
  const load = addr => [0x41, addr | 0x80, 0, 0xfd, 0x00, 0, 0];
  return instantiate(Uint8Array.from([
    0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
    ...section(1, [1, 0x60, 0, 0]),
    ...section(3, vector(kernels.map(() => 0))),
    ...section(5, [1, 0, 1]),
    ...section(7, vector(names)),
    ...section(10, vector(kernels.map(row => vector([
      // i32.const arguments use signed LEB128.
      0, 0x41, 0x80, 0x01, ...[32,64,96].slice(0, arity(row)).flatMap(load),
      0xfd, ...uleb(row.Code), ...(row.Mask || []), 0xfd, 0x0b, 0, 0, 0x0b,
    ])))),
  ]));
}
`

const wasmV128RoutingOracle = wasmV128MemoryKernelJS + `
const native = nativeMemory(row => row.Lane ? 3 : 2);
const bitselect = nativeMemory(() => 3, rows.filter(row => row.Lane).map(row => ({...row, Code: 0x52})));
const input = new Uint8Array(native.memory.buffer);
const bitselectMemory = new Uint8Array(bitselect.memory.buffer);
const output = new Uint8Array(translated.memory.buffer);
const indices = Array.from({length:16}, (_, i) => i);
function prepare(mem, a, b, mask) {
  mem.set(a, 32);
  mem.set(b, 64);
  mem.set(mask, 96);
  mem.fill(0x6b, 127, 145);
}
function matches(mem, expected) {
  return mem[127] === 0x6b && mem[144] === 0x6b &&
    expected.every((byte, i) => byte === mem[128+i]);
}
for (const {Name, Mask, Lane} of rows) {
  for (let seed = 0; seed < 16; seed++) {
    const a = indices.map(i => (97 + 19*i + seed) & 255);
    const b = indices.map(i => Lane || Mask ? (192 - 17*i + seed) & 255 : seed*16+i);
    const c = indices.map(i => {
      if (Lane && seed < 2) return i % (2*Lane) < Lane ? 255 : 0;
      return (seed*16 + 41*i) & 255;
    });
    const strict = indices.map(i => {
      if (Mask) return [...a,...b][Mask[i]];
      if (Lane) return (a[i] & c[i]) | (b[i] & (~c[i] & 255));
      return b[i] < 16 ? a[b[i]] : 0;
    });
    if (Lane) {
      // Whole-lane masks have the same value in either relaxed mode.
      // V8 can blend by byte on mixed i16x8 masks (relaxed-simd #125).
      // With mixed masks, compare the translator's deterministic result
      // against native v128.bitselect as well as the scalar calculation.
      const mask = indices.map(i => c[Math.floor(i/Lane)*Lane+Lane-1] & 128 ? 255 : 0);
      const selected = indices.map(i => mask[i] ? a[i] : b[i]);
      prepare(input, a, b, mask);
      native[Name]();
      if (!matches(input, selected)) {
        throw Error(Name + '/' + seed + ': wrong native whole-lane result: ' + input.subarray(127,145));
      }
      prepare(bitselectMemory, a, b, c);
      bitselect[Name]();
      if (!matches(bitselectMemory, strict)) {
        throw Error(Name + '/' + seed + ': wrong native bitselect result: ' + bitselectMemory.subarray(127,145));
      }
    } else {
      const alternative = Name === 'relaxedSwizzle' ?
        indices.map(i => b[i] < 128 ? a[b[i] & 15] : 0) : strict;
      prepare(input, a, b, c);
      native[Name]();
      if (!matches(input, strict) && !matches(input, alternative)) {
        throw Error(Name + '/' + seed + ': native result is outside the allowed alternatives: ' + input.subarray(127,145));
      }
    }
    prepare(output, a, b, c);
    translated[Name]();
    if (!matches(output, strict)) {
      throw Error(Name + '/' + seed + ': wrong deterministic result or out-of-range store: ' + output.subarray(127,145));
    }
  }
}
`
