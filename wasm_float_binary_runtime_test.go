package plan9asm

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type wasmFloatBinaryReference struct {
	A, B, Want string
	NaN        int // 0: exact bits, 1: canonical NaN, 2: arithmetic NaN.
}

func wasmFloatBinarySamples(bits int) []uint64 {
	if bits == 32 {
		return []uint64{0, 0x80000000, 1, 0x80000001, 0x007fffff, 0x807fffff,
			0x00800000, 0x80800000, 0x3f800000, 0xbf800000, 0x7f7fffff, 0xff7fffff,
			0x7f800000, 0xff800000, 0x7fc00000, 0xffc00000, 0x7fc12345, 0xffc12345,
			0x7f800001, 0xff800001}
	}
	return []uint64{0, 0x8000000000000000, 1, 0x8000000000000001,
		0x000fffffffffffff, 0x800fffffffffffff, 0x0010000000000000, 0x8010000000000000,
		0x3ff0000000000000, 0xbff0000000000000, 0x7fefffffffffffff, 0xffefffffffffffff,
		0x7ff0000000000000, 0xfff0000000000000, 0x7ff8000000000000, 0xfff8000000000000,
		0x7ff8123456789abc, 0xfff8123456789abc, 0x7ff0000000000001, 0xfff0000000000001}
}

// Reference the core Wasm relation, not the lowering's predicates/intrinsics.
// NaN results are a permitted set: exact payload matching to one engine would
// incorrectly reject other conforming canonical/arithmetic NaN choices.
func wasmFloatBinaryReferenceValue(name string, a, b uint64) (uint64, int) {
	sign, exponent, quiet := uint64(1)<<63, uint64(0x7ff0000000000000), uint64(1)<<51
	x, y := math.Float64frombits(a), math.Float64frombits(b)
	if strings.HasPrefix(name, "F32") {
		sign, exponent, quiet = 1<<31, 0x7f800000, 1<<22
		x, y = float64(math.Float32frombits(uint32(a))), float64(math.Float32frombits(uint32(b)))
	}
	isNaN := func(v uint64) bool { return v&exponent == exponent && v&(quiet*2-1) != 0 }
	nanA, nanB := isNaN(a), isNaN(b)
	operation := name[3:]
	if operation == "Min" || operation == "Max" {
		if nanA || nanB {
			kind := 1
			if nanA && a&(quiet*2-1) != quiet || nanB && b&(quiet*2-1) != quiet {
				kind = 2
			}
			return exponent | quiet, kind
		}
		if a & ^sign == 0 && b & ^sign == 0 {
			if operation == "Min" {
				return a | b, 0
			}
			return a & b, 0
		}
		if operation == "Min" && x < y || operation == "Max" && x > y {
			return a, 0
		}
		return b, 0
	}
	result := false
	switch operation {
	case "Eq":
		result = !nanA && !nanB && x == y
	case "Ne":
		result = nanA || nanB || x != y
	case "Lt":
		result = !nanA && !nanB && x < y
	case "Gt":
		result = !nanA && !nanB && x > y
	case "Le":
		result = !nanA && !nanB && x <= y
	case "Ge":
		result = !nanA && !nanB && x >= y
	default:
		panic("unknown independent Wasm reference operation " + name)
	}
	if result {
		return 1, 0
	}
	return 0, 0
}

type wasmFloatBinaryRuntimeRow struct {
	Name  string
	Bits  int
	Cases []wasmFloatBinaryReference
}

func wasmFloatBinaryRuntimeFixture(t *testing.T) (string, string, map[string]FuncSig, string, string, []byte) {
	t.Helper()
	return wasmFloatRuntimeFixture(t, wasmFloatBinaryGoNames(t), wasmFloatBinaryTestTypes,
		wasmFloatBinarySamples, wasmFloatBinaryReferenceValue)
}

// Share the actual ABI adapter, bounded execution and NaN-set checkers across
// floating families. Each caller supplies its independent full opcode/input
// inventory and reference; the existing comparison/minmax denominator is fixed.
func wasmFloatRuntimeFixture(t *testing.T, names []string,
	types func(string) (LLVMType, LLVMType, Reg, Reg), samples func(int) []uint64,
	reference func(string, uint64, uint64) (uint64, int)) (string, string, map[string]FuncSig, string, string, []byte) {
	t.Helper()
	var source, original, wrapper, goSource strings.Builder
	goSource.WriteString("package main\nimport (\"encoding/json\";\"fmt\";\"strconv\")\n")
	sigs := make(map[string]FuncSig)
	var rows []wasmFloatBinaryRuntimeRow
	for _, opcode := range names {
		typ, result, _, _ := types(opcode)
		bits, base := 32, 0
		if typ == "double" {
			bits, base = 64, 16
		}
		for _, alias := range []bool{false, true} {
			for _, dead := range []bool{false, true} {
				name := fmt.Sprintf("kernel%d", len(rows))
				first, second := Reg(fmt.Sprintf("F%d", base+15)), Reg(fmt.Sprintf("F%d", base))
				if alias {
					second = first
				}
				body := fmt.Sprintf("Get %s\nGet %s\n%s\n", first, second, opcode)
				ret := result
				if dead {
					body += "Drop\nI64Const $0\n"
					ret = I64
				}
				fmt.Fprintf(&source, "TEXT %s(SB),4,$0-0\n%sReturn\n", name, body)
				args, regs := []LLVMType{typ}, []Reg{first}
				if !alias {
					args, regs = append(args, typ), append(regs, second)
				}
				sigs[name] = FuncSig{Name: name, Args: args, ArgRegs: regs, Ret: ret}
				// This is the original Go ABI adapter, not translated test-only
				// transport: the exact Get/Get/op/Drop region is shared above.
				fmt.Fprintf(&original, "TEXT ·%s(SB),4,$0-24\nMOVD $0,ret+16(FP)\nF%dLoad a+0(FP)\nSet %s\n", name, bits, first)
				if !alias {
					fmt.Fprintf(&original, "F%dLoad b+8(FP)\nSet %s\n", bits, second)
				}
				store := "I32Store"
				if dead {
					store = "I64Store"
				} else if result == typ {
					store = fmt.Sprintf("F%dStore", bits)
				}
				fmt.Fprintf(&original, "Get SP\n%s%s ret+16(FP)\nRET\n", body, store)
				fmt.Fprintf(&goSource, "func %s(a,b uint64) uint64\n", name)
				fmt.Fprintf(&wrapper, "define i64 @probe_%s(i64 %%a,i64 %%b){\n", name)
				integer := "i64"
				for _, arg := range []string{"a", "b"} {
					value := "%" + arg
					if bits == 32 {
						integer = "i32"
						fmt.Fprintf(&wrapper, "%%%s32 = trunc i64 %%%s to i32\n", arg, arg)
						value += "32"
					}
					fmt.Fprintf(&wrapper, "%%%sf = bitcast %s %s to %s\n", arg, integer, value, typ)
				}
				fmt.Fprintf(&wrapper, "%%value = call %s @%s(%s %%af", ret, name, typ)
				if !alias {
					fmt.Fprintf(&wrapper, ",%s %%bf", typ)
				}
				wrapper.WriteString(")\n")
				if dead {
					wrapper.WriteString("ret i64 %value\n}\n")
				} else {
					value := "%value"
					if result == typ {
						fmt.Fprintf(&wrapper, "%%raw = bitcast %s %%value to %s\n", typ, integer)
						value = "%raw"
					} else {
						integer = "i32"
					}
					if integer == "i32" {
						fmt.Fprintf(&wrapper, "%%wide = zext i32 %s to i64\n", value)
						value = "%wide"
					}
					fmt.Fprintf(&wrapper, "ret i64 %s\n}\n", value)
				}
				row := wasmFloatBinaryRuntimeRow{Name: name, Bits: bits}
				for _, a := range samples(bits) {
					for _, b := range samples(bits) {
						rhs := b
						if alias {
							rhs = a
						}
						want, nan := reference(opcode, a, rhs)
						if dead {
							want, nan = 0, 0
						}
						row.Cases = append(row.Cases, wasmFloatBinaryReference{fmt.Sprint(a), fmt.Sprint(b), fmt.Sprint(want), nan})
					}
				}
				rows = append(rows, row)
			}
		}
	}
	encoded, err := json.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	fns := make([]string, len(rows))
	for i, row := range rows {
		fns[i] = row.Name
	}
	fmt.Fprintf(&goSource, "var inputs=%q\nvar functions=[]func(uint64,uint64)uint64{%s}\n", encoded, strings.Join(fns, ","))
	goSource.WriteString(wasmFloatBinaryGoCheck)
	return source.String(), original.String(), sigs, wrapper.String(), goSource.String(), encoded
}

const wasmFloatBinaryGoCheck = `
type reference struct {
 A, B, Want string
 NaN int
}
type row struct {
 Name string
 Bits int
 Cases []reference
}

func number(s string) uint64 {
 value, err := strconv.ParseUint(s, 10, 64)
 if err != nil {
  panic(err)
 }
 return value
}

func main() {
 var rows []row
 if err := json.Unmarshal([]byte(inputs), &rows); err != nil {
  panic(err)
 }
 count := 0
 for i, r := range rows {
  for _, c := range r.Cases {
   got := functions[i](number(c.A), number(c.B))
   want := number(c.Want)
   good := got == want
   if c.NaN != 0 {
    exponent, quiet, sign := uint64(0x7ff0000000000000), uint64(1)<<51, uint64(1)<<63
    if r.Bits == 32 {
     exponent, quiet, sign = 0x7f800000, 1<<22, 1<<31
    }
    good = got&exponent == exponent && got&quiet != 0 && got & ^(sign|exponent|(quiet*2-1)) == 0
    if c.NaN == 1 {
     good = good && got & ^sign == want
    }
   }
   if !good {
    panic(fmt.Sprintf("%s/%s/%s: %x want %x nan=%d", r.Name, c.A, c.B, got, want, c.NaN))
   }
   count++
  }
 }
 fmt.Printf("actual Go Wasm float binary PASS %d\n", count)
}
`

func TestWASMFloatBinaryOriginalGoRuntime(t *testing.T) {
	_, source, _, _, goSource, _ := wasmFloatBinaryRuntimeFixture(t)
	wasmFloatRunOriginal(t, source, goSource, 25600)
}

func wasmFloatRunOriginal(t *testing.T, source, goSource string, count int) {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{"go.mod": "module float_binary_oracle\ngo 1.20\n", "main.go": goSource, "oracle_wasm.s": source} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", "oracle.wasm", ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOOS=js", "GOARCH=wasm", "GOTOOLCHAIN=local")
	if output, err := runtimeOracleCombinedOutput(ctx, cmd); err != nil {
		t.Fatalf("original Go build: %v\n%s", err, output)
	}
	cmd, err := wasmPackedGoRuntimeCommand(ctx, runtime.GOROOT(), wasmPackedNode(t), filepath.Join(dir, "oracle.wasm"))
	if err != nil {
		t.Fatal(err)
	}
	output, err := runtimeOracleCombinedOutput(ctx, cmd)
	if err != nil || strings.TrimSpace(string(output)) != fmt.Sprintf("actual Go Wasm float binary PASS %d", count) {
		t.Fatalf("original Go runtime: %v\n%s", err, output)
	}
	t.Log(strings.TrimSpace(string(output)))
}

func wasmFloatBinaryCommand(t *testing.T, command string, arguments ...string) string {
	t.Helper()
	ctx, cancel := runtimeOracleStageContext(t)
	defer cancel()
	output, err := runtimeOracleCombinedOutput(ctx, exec.CommandContext(ctx, command, arguments...))
	if err != nil {
		t.Fatalf("%s %q: %v\n%s", filepath.Base(command), arguments, err, output)
	}
	return string(output)
}

func TestWASMFloatBinaryThreeAPIsFourOptimizationAxesRuntime(t *testing.T) {
	source, _, sigs, wrappers, _, inputs := wasmFloatBinaryRuntimeFixture(t)
	wasmFloatRunLLVM(t, source, sigs, wrappers, inputs, 25600)
}

func wasmFloatRunLLVM(t *testing.T, source string, sigs map[string]FuncSig, wrappers string, inputs []byte, count int) {
	t.Helper()
	file, err := Parse(ArchWASM, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, route := range []string{"Translate", "TranslateModule", "TranslateModuleInContext"} {
		for _, triple := range []string{"wasm32-unknown-unknown", "wasm32-wasi"} {
			options := wasmPackedOptions(sigs, WASMABIDirect)
			options.TargetTriple = triple
			ir, err := wasmPackedTranslate(t, file, options, route)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(ir, "blockaddress") || strings.Contains(ir, " fcmp fast ") {
				t.Fatal("Wasm float lowering introduced invalid control flow or relaxed float semantics")
			}
			for _, optimize := range []bool{false, true} {
				for _, backend := range []string{"0", "2"} {
					t.Run(fmt.Sprintf("%s/%s/IR-O2=%t/llc-O%s", route, triple, optimize, backend), func(t *testing.T) {
						dir := t.TempDir()
						input, object, binary := filepath.Join(dir, "input.ll"), filepath.Join(dir, "output.o"), filepath.Join(dir, "output.wasm")
						if err := os.WriteFile(input, []byte(ir+wrappers), 0600); err != nil {
							t.Fatal(err)
						}
						if optimize {
							optimized := filepath.Join(dir, "optimized.ll")
							wasmFloatBinaryCommand(t, wasmDataTool(t, "opt"), "-passes=default<O2>", "-verify-each", "-S", input, "-o", optimized)
							input = optimized
						}
						wasmFloatBinaryCommand(t, wasmDataTool(t, "llc"), "-O"+backend, "-filetype=obj", input, "-o", object)
						if header := wasmFloatBinaryCommand(t, wasmDataTool(t, "llvm-readobj"), "--file-headers", object); !strings.Contains(header, "Format: WASM") {
							t.Fatalf("not a real Wasm object:\n%s", header)
						}
						wasmFloatBinaryCommand(t, wasmDataTool(t, "wasm-ld"), "--no-entry", "--export-all", object, "-o", binary)
						inputJSON := filepath.Join(dir, "inputs.json")
						if err := os.WriteFile(inputJSON, inputs, 0600); err != nil {
							t.Fatal(err)
						}
						output := wasmFloatBinaryCommand(t, wasmPackedNode(t), "-e", wasmFloatBinaryNodeCheck, binary, inputJSON)
						if strings.TrimSpace(output) != fmt.Sprintf("LLVM Wasm float binary PASS %d", count) {
							t.Fatalf("runtime failed to consume complete matrix: %s", output)
						}
						t.Log(strings.TrimSpace(output))
					})
				}
			}
		}
	}
}

const wasmFloatBinaryNodeCheck = `
const fs = require('fs');
WebAssembly.instantiate(fs.readFileSync(process.argv[1]), {}).then(({instance:{exports:e}}) => {
  const rows = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
  let count = 0;
  for (const row of rows) {
    const fn = e['probe_' + row.Name];
    for (const c of row.Cases) {
      const got = BigInt.asUintN(64, fn(BigInt(c.A), BigInt(c.B)));
      const want = BigInt(c.Want);
      let good = got === want;
      if (c.NaN !== 0) {
        const exponent = row.Bits === 32 ? 0x7f800000n : 0x7ff0000000000000n;
        const quiet = 1n << BigInt(row.Bits === 32 ? 22 : 51);
        const sign = 1n << BigInt(row.Bits - 1);
        good = (got & exponent) === exponent && (got & quiet) !== 0n &&
          (got & ~(sign | exponent | (quiet * 2n - 1n))) === 0n;
        if (c.NaN === 1) good = good && (got & ~sign) === want;
      }
      if (!good) throw Error(row.Name + '/' + c.A + '/' + c.B + ': ' + got.toString(16) + ' want ' + want.toString(16) + ' nan=' + c.NaN);
      count++;
    }
  }
  console.log('LLVM Wasm float binary PASS ' + count);
}).catch(error => { console.error(error); process.exit(1); });
`
