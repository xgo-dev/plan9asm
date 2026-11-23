package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type wasmIntegerComparisonCase struct {
	Name     string
	Bits     int
	Arity    int
	Encoding int
}

func wasmIntegerComparisonCases(t *testing.T) []wasmIntegerComparisonCase {
	t.Helper()
	names, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"(I(32|64)(?:Eqz|Eq|Ne|(?:Lt|Gt|Le|Ge)[SU]))"`)
	var cases []wasmIntegerComparisonCase
	for _, match := range pattern.FindAllStringSubmatch(string(names), -1) {
		row := wasmIntegerComparisonCase{Name: match[1], Bits: 32, Arity: 2, Encoding: 0x45 + len(cases)}
		if match[2] == "64" {
			row.Bits = 64
		}
		if strings.HasSuffix(row.Name, "Eqz") {
			row.Arity = 1
		}
		cases = append(cases, row)
	}
	if len(cases) != 22 || !strings.Contains(string(names), `"Not"`) {
		t.Fatalf("Go integer comparison namespace changed: %v", cases)
	}
	return append(cases, wasmIntegerComparisonCase{Name: "Not", Bits: 32, Arity: 1, Encoding: 0x45})
}

func TestWASMIntegerComparisonsRequireTypedOperands(t *testing.T) {
	for _, row := range wasmIntegerComparisonCases(t) {
		t.Run(row.Name, func(t *testing.T) {
			want := fmt.Sprintf("I%dConst $1\n", row.Bits)
			other := "I64Const $4294967296\n"
			if row.Bits == 64 {
				other = "I32Const $1\n"
			}
			bodies := []string{other}
			if row.Arity == 2 {
				bodies = []string{other + want, want + other}
			}
			for _, body := range bodies {
				file, err := Parse(ArchWASM, "TEXT comparison(SB),4,$0-0\n"+body+row.Name+"\nReturn\n")
				if err != nil {
					t.Fatal(err)
				}
				if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "comparison"); err == nil {
					t.Error("inference accepted an integer comparison of the wrong width")
				}
				sigs := map[string]FuncSig{"comparison": {Name: "comparison", Ret: I32}}
				for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
					ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
					if err == nil || ir != "" || !strings.Contains(err.Error(), "stack value") {
						t.Errorf("%s silently accepted an integer comparison of the wrong width: %v", route, err)
					}
				}
			}
		})
	}
}

func TestWASMIntegerComparisonSourceFormat(t *testing.T) {
	for _, row := range wasmIntegerComparisonCases(t) {
		for _, suffix := range []string{".INVALID", " R0,R1,R2"} {
			file, err := Parse(ArchWASM, "TEXT comparison(SB),4,$0-0\nRET\n"+row.Name+suffix+"\n")
			if err != nil {
				continue // The parser may reject the spelling before format checking.
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "comparison"); err == nil {
				t.Errorf("inference accepted an invalid dead instruction: %s%s", row.Name, suffix)
			}
			sigs := map[string]FuncSig{"comparison": {Name: "comparison", Ret: Void}}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Errorf("translation accepted an invalid dead instruction: %s%s", row.Name, suffix)
			}
		}
	}
}

func TestWASMIntegerComparisonOfficialMatrix(t *testing.T) {
	var source strings.Builder
	var cases []wasmIntegerComparisonCase
	sigs := make(map[string]FuncSig)
	for _, row := range wasmIntegerComparisonCases(t) {
		for _, suffix := range []string{"", " $7", " R0,R1"} {
			name := fmt.Sprintf("comparison%d", len(cases))
			fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n", name)
			sig := FuncSig{Name: name, Ret: I32}
			for i := 0; i < row.Arity; i++ {
				reg := Reg(fmt.Sprintf("R%d", i))
				fmt.Fprintf(&source, "Get %s\n", reg)
				if row.Bits == 32 {
					source.WriteString("I32WrapI64\n")
				}
				sig.Args = append(sig.Args, I64)
				sig.ArgRegs = append(sig.ArgRegs, reg)
			}
			fmt.Fprintf(&source, "%s%s\nReturn\n", row.Name, suffix)
			cases = append(cases, row)
			sigs[name] = sig
		}
	}
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source.String(), goos)
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for _, fn := range file.Funcs {
		want := sigs[fn.Sym]
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || got.Ret != want.Ret || !reflect.DeepEqual(got.Args, want.Args) || !reflect.DeepEqual(got.ArgRegs, want.ArgRegs) {
			t.Errorf("%s: inferred %+v, want %+v: %v", fn.Sym, got, want, err)
		}
	}
	matrix := filepath.Join(t.TempDir(), "cases.json")
	data, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(matrix, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		ir, err := wasmPackedTranslate(t, file, wasmPackedOptions(sigs, WASMABIDirect), route)
		if err != nil {
			t.Errorf("%s: %v", route, err)
			continue
		}
		for _, level := range []string{"0", "2"} {
			t.Run(route+"/O"+level, func(t *testing.T) {
				runLLVMWASMObject(t, ir, level, wasmIntegerComparisonDifferential, matrix)
			})
		}
	}
}

const wasmIntegerComparisonDifferential = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const exportsOf = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = exportsOf(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const types = [1, 2].map(arity => [0x60, ...vector(Array(arity).fill(0x7e)), 1, 0x7f]);
const body = ({Bits, Encoding, Arity}) => {
  const operands = [];
  for (let i = 0; i < Arity; i++) {
    operands.push(0x20, i);
    if (Bits === 32) operands.push(0xa7);
  }
  return vector([0, ...operands, Encoding, 0x0b]);
};
const native = exportsOf(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, vector(types)),
  ...section(3, vector(rows.map(({Arity}) => Arity - 1))),
  ...section(7, vector(rows.map((_, i) => [...vector([...Buffer.from('comparison' + i)]), 0, ...uleb(i)]))),
  ...section(10, vector(rows.map(body))),
]));
const inputs = [0n, 1n, -1n, 0x7fffffffn, 0x80000000n, 0x100000000n, 1n << 63n]
  .map(value => BigInt.asIntN(64, value));
for (const [i, {Name, Arity}] of rows.entries()) {
  const symbol = 'comparison' + i;
  for (const left of inputs) {
    for (const right of Arity === 2 ? inputs : [0n]) {
      const args = Arity === 2 ? [left, right] : [left];
      const got = translated[symbol](...args);
      const want = native[symbol](...args);
      if (got !== want) throw Error(Name + ' row ' + i + ' input ' + args + ': got ' + got + ', want ' + want);
    }
  }
}
`
