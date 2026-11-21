package plan9asm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

type wasmIntegerBinaryCase struct {
	Name     string
	Bits     int
	Encoding int
	Drop     bool
}

func wasmIntegerBinaryCases(t *testing.T) []wasmIntegerBinaryCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src/cmd/internal/obj/wasm/anames.go"))
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`"(I(32|64)(?:Add|Sub|Mul|Div[SU]|Rem[SU]|And|Or|Xor|Shl|Shr[SU]|Rot[lr]))"`)
	var cases []wasmIntegerBinaryCase
	for _, match := range pattern.FindAllStringSubmatch(string(data), -1) {
		bits, encoding := 32, 0x6a+len(cases)
		if match[2] == "64" {
			bits, encoding = 64, 0x7c+len(cases)-15
		}
		cases = append(cases, wasmIntegerBinaryCase{Name: match[1], Bits: bits, Encoding: encoding})
	}
	if len(cases) != 30 {
		t.Fatalf("Go scalar binary integer namespace has %d forms, want 30", len(cases))
	}
	return cases
}

func TestWASMIntegerBinaryNativeMatrix(t *testing.T) {
	var source strings.Builder
	sigs := make(map[string]FuncSig)
	cases := wasmIntegerBinaryCases(t)
	for _, row := range cases {
		if strings.Contains(row.Name, "Div") || strings.Contains(row.Name, "Rem") {
			row.Drop = true
			cases = append(cases, row)
		}
	}
	for index, row := range cases {
		typ := I32
		if row.Bits == 64 {
			typ = I64
		}
		name := fmt.Sprintf("binary%d", index)
		fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\nGet R0\nGet R1\n%s\n", name, row.Name)
		if row.Drop {
			fmt.Fprintf(&source, "Drop\nI%dConst $42\n", row.Bits)
		}
		source.WriteString("Return\n")
		sigs[name] = FuncSig{Name: name, Args: []LLVMType{typ, typ}, ArgRegs: []Reg{"R0", "R1"}, Ret: typ}
	}
	for _, goos := range wasmPackedGoPlatforms {
		wasmDataGoObject(t, source.String(), goos)
	}
	file, err := Parse(ArchWASM, source.String())
	if err != nil {
		t.Fatal(err)
	}
	for index, fn := range file.Funcs {
		want := sigs[fn.Sym]
		got, err := InferWASMAssemblyFuncSig(fn, fn.Sym)
		if err != nil || got.Ret != want.Ret || len(got.Args) != 2 || got.Args[0] != want.Args[0] || got.Args[1] != want.Args[1] {
			t.Errorf("%s: inferred %v -> %s, want %v -> %s: %v", cases[index].Name, got.Args, got.Ret, want.Args, want.Ret, err)
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
				runLLVMWASMObject(t, ir, level, wasmIntegerBinaryDifferential, matrix)
			})
		}
	}
}

const wasmIntegerBinaryDifferential = `
const fs = require('fs');
const rows = JSON.parse(fs.readFileSync(process.argv[2]));
const instantiate = bytes => new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const translated = instantiate(fs.readFileSync(process.argv[1]));
` + wasmTestSectionJS + `
const type = code => [0x60, 2, code, code, 1, code];
const native = instantiate(Uint8Array.from([
  0, 0x61, 0x73, 0x6d, 1, 0, 0, 0,
  ...section(1, vector([type(0x7f), type(0x7e)])),
  ...section(3, vector(rows.map(({Bits}) => Bits === 32 ? 0 : 1))),
  ...section(7, vector(rows.map((_, i) => [...vector([...Buffer.from('binary' + i)]), 0, i]))),
  ...section(10, vector(rows.map(({Bits, Encoding, Drop}) => vector([
    0, 0x20, 0, 0x20, 1, Encoding, ...(Drop ? [0x1a, Bits === 32 ? 0x41 : 0x42, 42] : []), 0x0b,
  ])))),
]));
function outcome(fn, left, right) {
  try { return fn(left, right); }
  catch (error) {
    if (!(error instanceof WebAssembly.RuntimeError)) throw error;
    return 'trap';
  }
}
for (const [i, {Name, Bits, Drop}] of rows.entries()) {
  const symbol = 'binary' + i;
  const sign = 1n << BigInt(Bits - 1);
  const inputs = [0n, 1n, 3n, -1n, -3n, sign, sign + 1n, sign - 1n, 2n * sign - 1n, 0x9e3779b97f4a7c15n];
  const counts = /(?:Sh[lr]|Rot)/.test(Name) ? Array.from({length: 2 * Bits + 3}, (_, i) => BigInt(i - 1)) : [];
  const arg = value => Bits === 32 ? Number(BigInt.asIntN(32, value)) : BigInt.asIntN(64, value);
  for (const left of inputs.map(arg)) {
    for (const right of [...inputs, ...counts].map(arg)) {
      const want = outcome(native[symbol], left, right);
      const got = outcome(translated[symbol], left, right);
      if (got !== want) throw Error(Name + ' (drop=' + Drop + ') ' + left + '/' + right + ': got ' + got + ', want ' + want);
    }
  }
}
`

func TestWASMIntegerBinaryOptimizationSemantics(t *testing.T) {
	const source = `TEXT shiftFullWidth(SB),4,$0-0
	I32Const $3
	I32Const $32
	I32Shl
	Return
TEXT discardDivision(SB),4,$0-0
	I64Const $17
	Get R0
	I64DivU
	Drop
	I64Const $42
	Return
`
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	sigs := map[string]FuncSig{
		"shiftFullWidth":  {Name: "shiftFullWidth", Ret: I32},
		"discardDivision": {Name: "discardDivision", Args: []LLVMType{I64}, ArgRegs: []Reg{"R0"}, Ret: I64},
	}
	ir, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect))
	if err != nil {
		t.Fatal(err)
	}
	runLLVMWASMObject(t, ir, "2", `
const bytes = require('fs').readFileSync(process.argv[1]);
const {shiftFullWidth, discardDivision} = new WebAssembly.Instance(new WebAssembly.Module(bytes)).exports;
const failures = [];
if (shiftFullWidth() !== 3) failures.push('shifting by the carrier width must retain the input');
if (discardDivision(1n) !== 42n) failures.push('valid division expected');
try {
  discardDivision(0n);
  failures.push('discarding a quotient erased the divide-by-zero trap');
} catch (error) {
  if (!(error instanceof WebAssembly.RuntimeError)) throw error;
}
if (failures.length !== 0) throw Error(failures.join('\n'));
`)
}

func TestWASMIntegerBinaryRejectsInvalidStackAndFormat(t *testing.T) {
	sigs := map[string]FuncSig{"invalid": {Name: "invalid", Ret: Void}}
	for _, row := range wasmIntegerBinaryCases(t) {
		constant, wrong := "I32Const $1\n", "I64Const $1\n"
		if row.Bits == 64 {
			constant, wrong = wrong, constant
		}
		for _, body := range []string{
			constant + row.Name,
			constant + wrong + row.Name,
			wrong + constant + row.Name,
			"Get F0\n" + constant + row.Name,
			"RET\n" + row.Name + " $1",
			"RET\n" + row.Name + ".invalid",
		} {
			file, err := Parse(ArchWASM, "TEXT invalid(SB),4,$0-0\n"+body+"\nRET\n")
			if err != nil {
				continue
			}
			if _, err := InferWASMAssemblyFuncSig(file.Funcs[0], "invalid"); err == nil {
				t.Errorf("inference accepted %q", body)
			}
			if _, err := Translate(file, wasmPackedOptions(sigs, WASMABIDirect)); err == nil {
				t.Errorf("translation accepted %q", body)
			}
		}
	}
}
